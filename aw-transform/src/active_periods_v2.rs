use std::collections::{HashMap, HashSet};

use aw_models::Event;
use fancy_regex::Regex;
use serde_json::Value;

use crate::{
    classify_v2::{MAX_EXPRESSION_DEPTH, MAX_EXPRESSION_NODES, MAX_REGEX_LENGTH, MAX_RULE_SOURCES},
    filter_period_intersect, period_union,
};

#[derive(Clone, Copy)]
enum ValueMode {
    String,
    Scalar,
}

enum ActiveExpression {
    None,
    Regex {
        source: String,
        host: Option<String>,
        regex: Regex,
        fields: Option<Vec<String>>,
        negate: bool,
        value_mode: ValueMode,
    },
    All(Vec<ActiveExpression>),
    Any(Vec<ActiveExpression>),
}

pub fn active_periods_v2(
    named_sources: Vec<(String, Vec<Event>)>,
    expression: &Value,
) -> Result<Vec<Event>, String> {
    active_periods_v2_for_host(named_sources, expression, None)
}

pub fn active_periods_v2_for_host(
    named_sources: Vec<(String, Vec<Event>)>,
    expression: &Value,
    host: Option<&str>,
) -> Result<Vec<Event>, String> {
    if named_sources.len() > MAX_RULE_SOURCES {
        return Err(format!(
            "active-time sources exceed maximum count of {MAX_RULE_SOURCES}"
        ));
    }
    if host.is_some_and(str::is_empty) {
        return Err("active-time host must be a non-empty string".to_string());
    }
    let mut sources = HashMap::with_capacity(named_sources.len());
    let mut source_ids = HashSet::with_capacity(named_sources.len());
    for (source_id, events) in named_sources {
        validate_source_id(&source_id)?;
        if !source_ids.insert(source_id.clone()) {
            return Err(format!("duplicate active-time source id: {source_id:?}"));
        }
        sources.insert(source_id, events);
    }

    compile_expression(expression, 1, &mut ExpressionCompileState::default())?
        .evaluate(&sources, host)
}

impl ActiveExpression {
    fn evaluate(
        &self,
        sources: &HashMap<String, Vec<Event>>,
        host: Option<&str>,
    ) -> Result<Vec<Event>, String> {
        match self {
            Self::None => Ok(Vec::new()),
            Self::Regex {
                source,
                host: required_host,
                regex,
                fields,
                negate,
                value_mode,
            } => {
                if required_host
                    .as_deref()
                    .is_some_and(|required| Some(required) != host)
                {
                    return Ok(Vec::new());
                }
                let Some(events) = sources.get(source) else {
                    return Err(format!(
                        "active-time expression references unknown source: {source:?}"
                    ));
                };
                Ok(events
                    .iter()
                    .filter(|event| {
                        let values = selected_values(event, fields.as_deref())
                            .into_iter()
                            .filter_map(|value| normalize_value(value, *value_mode))
                            .collect::<Vec<_>>();
                        if values.is_empty() {
                            return false;
                        }
                        let any_match = values
                            .iter()
                            .any(|value| regex.is_match(value).unwrap_or(false));
                        if *negate {
                            !any_match
                        } else {
                            any_match
                        }
                    })
                    .cloned()
                    .collect())
            }
            Self::All(children) => {
                let mut children = children.iter();
                let mut periods = children.next().unwrap().evaluate(sources, host)?;
                for child in children {
                    periods = filter_period_intersect(periods, child.evaluate(sources, host)?);
                }
                Ok(periods)
            }
            Self::Any(children) => {
                let mut periods = Vec::new();
                for child in children {
                    periods = period_union(&periods, &child.evaluate(sources, host)?);
                }
                Ok(periods)
            }
        }
    }
}

#[derive(Default)]
struct ExpressionCompileState {
    nodes: usize,
    sources: HashSet<String>,
}

fn compile_expression(
    spec: &Value,
    depth: usize,
    state: &mut ExpressionCompileState,
) -> Result<ActiveExpression, String> {
    if depth > MAX_EXPRESSION_DEPTH {
        return Err(format!(
            "active-time expression exceeds maximum depth of {MAX_EXPRESSION_DEPTH}"
        ));
    }
    state.nodes += 1;
    if state.nodes > MAX_EXPRESSION_NODES {
        return Err(format!(
            "active-time expression exceeds maximum node count of {MAX_EXPRESSION_NODES}"
        ));
    }
    let spec = spec
        .as_object()
        .ok_or_else(|| "active-time expression must be an object".to_string())?;
    let expression_type = match spec.get("type") {
        Some(Value::String(expression_type)) => Some(expression_type.as_str()),
        Some(Value::Null) | None if spec.contains_key("regex") => Some("regex"),
        Some(Value::Null) | None => None,
        Some(value) => return Err(format!("unknown active-time expression type: {value}")),
    };

    match expression_type {
        Some("none") => Ok(ActiveExpression::None),
        Some("regex") => {
            let expression = compile_regex_expression(spec)?;
            if let ActiveExpression::Regex { source, .. } = &expression {
                state.sources.insert(source.clone());
                if state.sources.len() > MAX_RULE_SOURCES {
                    return Err(format!(
                        "active-time expressions exceed maximum source count of {MAX_RULE_SOURCES}"
                    ));
                }
            }
            Ok(expression)
        }
        Some(expression_type @ ("all" | "any")) => {
            let children = spec
                .get("rules")
                .or_else(|| spec.get("children"))
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    format!("{expression_type} expression requires a list of child 'rules'")
                })?;
            if children.is_empty() {
                return Err(
                    "active-time expression group must contain at least one child".to_string(),
                );
            }
            let children = children
                .iter()
                .map(|child| compile_expression(child, depth + 1, state))
                .collect::<Result<Vec<_>, _>>()?;
            if expression_type == "all" {
                Ok(ActiveExpression::All(children))
            } else {
                Ok(ActiveExpression::Any(children))
            }
        }
        _ => Err(format!(
            "unknown active-time expression type: {expression_type:?}"
        )),
    }
}

fn compile_regex_expression(
    spec: &serde_json::Map<String, Value>,
) -> Result<ActiveExpression, String> {
    let source = match spec.get("source") {
        Some(Value::String(source)) => {
            validate_source_id(source)?;
            source.clone()
        }
        _ => return Err("active-time regex expression requires a string 'source'".to_string()),
    };
    let host = match spec.get("host") {
        None | Some(Value::Null) => None,
        Some(Value::String(host)) if !host.is_empty() => Some(host.clone()),
        _ => {
            return Err(
                "active-time regex expression 'host' must be a non-empty string".to_string(),
            )
        }
    };
    let pattern = match spec.get("regex") {
        Some(Value::String(pattern)) if !pattern.is_empty() => pattern,
        _ => {
            return Err(
                "active-time regex expression requires a non-empty string 'regex'".to_string(),
            )
        }
    };
    if pattern.len() > MAX_REGEX_LENGTH {
        return Err(format!(
            "active-time regex exceeds maximum length of {MAX_REGEX_LENGTH}"
        ));
    }
    let ignore_case = parse_bool(spec.get("ignore_case"), false, "ignore_case")?;
    let regex_source = if ignore_case {
        format!("(?i){pattern}")
    } else {
        pattern.clone()
    };
    let regex =
        Regex::new(&regex_source).map_err(|error| format!("invalid regex {pattern:?}: {error}"))?;
    let negate = parse_bool(spec.get("negate"), false, "negate")?;
    parse_integer(spec.get("weight"), 0)
        .map_err(|_| "active-time regex expression 'weight' must be an integer".to_string())?;
    let value_mode = match spec.get("value_mode") {
        None => ValueMode::String,
        Some(Value::String(value)) if value == "string" => ValueMode::String,
        Some(Value::String(value)) if value == "scalar" => ValueMode::Scalar,
        _ => {
            return Err(
                "active-time regex expression 'value_mode' must be 'string' or 'scalar'"
                    .to_string(),
            )
        }
    };
    let fields_value = if spec.contains_key("fields") {
        spec.get("fields")
    } else if spec.contains_key("field") {
        spec.get("field")
    } else {
        spec.get("select_keys")
    };
    let fields =
        match fields_value {
            None | Some(Value::Null) => None,
            Some(Value::String(field)) if !field.is_empty() => Some(vec![field.clone()]),
            Some(Value::Array(fields))
                if !fields.is_empty()
                    && fields.iter().all(
                        |field| matches!(field, Value::String(field) if !field.is_empty()),
                    ) =>
            {
                Some(
                    fields
                        .iter()
                        .map(|field| field.as_str().unwrap().to_string())
                        .collect(),
                )
            }
            _ => return Err(
                "active-time regex field selector must be a non-empty string or list of strings"
                    .to_string(),
            ),
        };

    Ok(ActiveExpression::Regex {
        source,
        host,
        regex,
        fields,
        negate,
        value_mode,
    })
}

fn validate_source_id(source_id: &str) -> Result<(), String> {
    if source_id.is_empty()
        || !source_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
    {
        return Err(
            "active-time source id may only contain letters, numbers, '_' and '-'".to_string(),
        );
    }
    Ok(())
}

fn parse_bool(value: Option<&Value>, default: bool, field: &str) -> Result<bool, String> {
    match value {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(format!(
            "active-time regex expression '{field}' must be a boolean"
        )),
    }
}

fn parse_integer(value: Option<&Value>, default: i64) -> Result<i64, ()> {
    match value {
        None => Ok(default),
        Some(Value::Number(value)) => value
            .as_i64()
            .or_else(|| {
                value.as_f64().and_then(|value| {
                    (value.is_finite()
                        && value.fract() == 0.0
                        && value >= i64::MIN as f64
                        && value <= i64::MAX as f64)
                        .then_some(value as i64)
                })
            })
            .ok_or(()),
        _ => Err(()),
    }
}

fn selected_values<'a>(event: &'a Event, fields: Option<&[String]>) -> Vec<&'a Value> {
    if let Some(fields) = fields {
        return fields
            .iter()
            .filter_map(|field| event.data.get(field))
            .collect();
    }
    event
        .data
        .iter()
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "$category" | "$category_score" | "$category_rule" | "$category_explain" | "$host"
            ) && !key.starts_with("$source.")
        })
        .map(|(_, value)| value)
        .collect()
}

fn normalize_value(value: &Value, value_mode: ValueMode) -> Option<String> {
    match (value_mode, value) {
        (_, Value::String(value)) => Some(value.clone()),
        (ValueMode::Scalar, Value::Bool(value)) => Some(value.to_string()),
        (ValueMode::Scalar, Value::Number(value)) => Some(value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use serde_json::json;
    use std::str::FromStr;

    use super::{active_periods_v2, active_periods_v2_for_host};
    use aw_models::Event;

    fn event(start: &str, duration: i64, data: serde_json::Value) -> Event {
        Event {
            id: None,
            timestamp: DateTime::from_str(start).unwrap(),
            duration: Duration::seconds(duration),
            data: data.as_object().unwrap().clone(),
        }
    }

    #[test]
    fn all_intersects_only_overlapping_matching_periods() {
        let left = event("2025-01-01T00:00:00Z", 10, json!({"state": "active"}));
        let right = event("2025-01-01T00:00:05Z", 10, json!({"app": "editor"}));
        let expression = json!({
            "type": "all",
            "rules": [
                {"type": "regex", "source": "afk", "field": "state", "regex": "^active$"},
                {"type": "regex", "source": "window", "field": "app", "regex": "^editor$"}
            ]
        });

        let result = active_periods_v2(
            vec![
                ("afk".to_string(), vec![left]),
                ("window".to_string(), vec![right]),
            ],
            &expression,
        )
        .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].timestamp,
            DateTime::<Utc>::from_str("2025-01-01T00:00:05Z").unwrap()
        );
        assert_eq!(result[0].duration, Duration::seconds(5));
    }

    #[test]
    fn any_unions_matching_periods_and_strips_data() {
        let first = event("2025-01-01T00:00:00Z", 4, json!({"active": true}));
        let second = event("2025-01-01T00:00:03Z", 4, json!({"audible": true}));
        let expression = json!({
            "type": "any",
            "rules": [
                {"type": "regex", "source": "afk", "field": "active", "regex": "^true$", "value_mode": "scalar"},
                {"type": "regex", "source": "audio", "field": "audible", "regex": "^true$", "value_mode": "scalar"}
            ]
        });

        let result = active_periods_v2(
            vec![
                ("afk".to_string(), vec![first]),
                ("audio".to_string(), vec![second]),
            ],
            &expression,
        )
        .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].duration, Duration::seconds(7));
        assert!(result[0].data.is_empty());
    }

    #[test]
    fn single_child_any_strips_data() {
        let source_event = event("2025-01-01T00:00:00Z", 4, json!({"state": "active"}));
        let expression = json!({
            "type": "any",
            "rules": [
                {"regex": "^active$", "source": "afk", "field": "state", "weight": 1.0}
            ]
        });

        let result =
            active_periods_v2(vec![("afk".to_string(), vec![source_event])], &expression).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].data.is_empty());
    }

    #[test]
    fn negate_does_not_match_missing_field_and_unknown_source_errors() {
        let event = event("2025-01-01T00:00:00Z", 4, json!({"state": "active"}));
        let missing_field = json!({
            "type": "regex", "source": "afk", "field": "missing", "regex": "idle", "negate": true
        });
        let missing_source = json!({
            "type": "regex", "source": "unknown", "field": "state", "regex": "idle", "negate": true
        });

        assert!(active_periods_v2(
            vec![("afk".to_string(), vec![event.clone()])],
            &missing_field
        )
        .unwrap()
        .is_empty());
        assert!(
            active_periods_v2(vec![("afk".to_string(), vec![event])], &missing_source)
                .unwrap_err()
                .contains("unknown source")
        );
    }

    #[test]
    fn rejects_nonintegral_weight() {
        let expression =
            json!({"regex": "active", "source": "afk", "field": "state", "weight": 1.5});
        assert!(
            active_periods_v2(vec![("afk".to_string(), vec![])], &expression)
                .unwrap_err()
                .contains("weight")
        );
    }

    #[test]
    fn rejects_invalid_and_duplicate_source_ids() {
        let expression = json!({"type": "none"});
        assert!(
            active_periods_v2(vec![("bad.source".to_string(), vec![])], &expression)
                .unwrap_err()
                .contains("source id")
        );
        assert!(active_periods_v2(
            vec![("same".to_string(), vec![]), ("same".to_string(), vec![])],
            &expression
        )
        .unwrap_err()
        .contains("duplicate"));
    }

    #[test]
    fn optional_host_gates_active_predicates() {
        let expression = json!({
            "type": "regex",
            "source": "window",
            "host": "workstation",
            "field": "app",
            "regex": "editor"
        });
        let source = event("2025-01-01T00:00:00Z", 4, json!({"app": "editor"}));

        assert!(!active_periods_v2_for_host(
            vec![("window".to_string(), vec![source.clone()])],
            &expression,
            Some("workstation")
        )
        .unwrap()
        .is_empty());
        assert!(active_periods_v2_for_host(
            vec![("window".to_string(), vec![source])],
            &expression,
            Some("laptop")
        )
        .unwrap()
        .is_empty());
    }
}
