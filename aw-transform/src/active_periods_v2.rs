use std::collections::{HashMap, HashSet};

use aw_models::Event;
use serde_json::Value;

use crate::{
    classify_v2::{
        MAX_EXPRESSION_DEPTH, MAX_EXPRESSION_NODES, MAX_REGEX_LENGTH, MAX_RULE_INTEGER,
        MAX_RULE_SOURCES, MIN_RULE_INTEGER,
    },
    fact_resolver::resolve_fact_slices,
    filter_period_intersect, period_union,
    predicate::{selected_values, RegexPredicate, ValueMode},
};

enum ActiveExpression {
    None,
    Regex {
        source: String,
        host: Option<String>,
        predicate: RegexPredicate,
        fields: Option<Vec<String>>,
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
        sources.insert(source_id, resolve_fact_slices(&events));
    }

    let periods = compile_expression(expression, 1, &mut ExpressionCompileState::default())?
        .evaluate(&sources, host)?;
    Ok(period_union(&[], &periods))
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
                predicate,
                fields,
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
                let mut matching = Vec::new();
                for event in events {
                    if predicate
                        .evaluate(selected_values(event, None, fields.as_deref()))?
                        .matched
                    {
                        matching.push(event.clone());
                    }
                }
                Ok(matching)
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
    let negate = parse_bool(spec.get("negate"), false, "negate")?;
    parse_rule_integer(spec.get("weight"), 0).map_err(|_| {
        format!(
            "active-time regex expression 'weight' must be an integer between {MIN_RULE_INTEGER} and {MAX_RULE_INTEGER}"
        )
    })?;
    let value_mode = ValueMode::parse(spec.get("value_mode"), "active-time regex expression")?;
    let predicate = RegexPredicate::compile(pattern, ignore_case, negate, value_mode)?;
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
        predicate,
        fields,
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

fn parse_rule_integer(value: Option<&Value>, default: i64) -> Result<i64, ()> {
    match value {
        None => Ok(default),
        Some(Value::Number(value)) => value
            .as_i64()
            .or_else(|| {
                value.as_f64().and_then(|value| {
                    (value.is_finite() && value.fract() == 0.0).then_some(value as i64)
                })
            })
            .filter(|value| (MIN_RULE_INTEGER..=MAX_RULE_INTEGER).contains(value))
            .ok_or(()),
        _ => Err(()),
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
    fn adjacent_matching_fact_slices_are_one_period() {
        let first = event("2025-01-01T00:00:00Z", 4, json!({"state": "active"}));
        let second = event("2025-01-01T00:00:04Z", 3, json!({"state": "active"}));
        let expression = json!({
            "type": "regex", "source": "afk", "field": "state", "regex": "^active$"
        });

        let result =
            active_periods_v2(vec![("afk".to_string(), vec![first, second])], &expression).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].duration, Duration::seconds(7));
        assert!(result[0].data.is_empty());
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
    fn predicates_evaluate_the_winning_fact_slices() {
        let source = vec![
            event("2025-01-01T00:00:00Z", 30, json!({"state": "on"})),
            event("2025-01-01T00:00:10Z", 10, json!({"state": "off"})),
        ];
        let on = json!({
            "type": "regex", "source": "switch", "field": "state", "regex": "^on$"
        });
        let contradiction = json!({
            "type": "all",
            "rules": [
                {"type": "regex", "source": "switch", "field": "state", "regex": "^on$"},
                {"type": "regex", "source": "switch", "field": "state", "regex": "^off$"}
            ]
        });

        let periods = active_periods_v2(vec![("switch".to_string(), source.clone())], &on).unwrap();
        assert_eq!(
            periods
                .iter()
                .map(|event| (event.timestamp.to_rfc3339(), event.duration.num_seconds()))
                .collect::<Vec<_>>(),
            vec![
                ("2025-01-01T00:00:00+00:00".to_string(), 10),
                ("2025-01-01T00:00:20+00:00".to_string(), 10),
            ]
        );
        assert!(
            active_periods_v2(vec![("switch".to_string(), source.clone())], &contradiction,)
                .unwrap()
                .is_empty()
        );

        let coverage = vec![event("2025-01-01T00:00:00Z", 30, json!({"coverage": true}))];
        let enriched = crate::merge_subwatcher_fields(
            coverage,
            source,
            &["state".to_string()],
            "base_wins",
            Some("switch"),
        )
        .unwrap();
        let categorized = crate::categorize_v2(
            enriched,
            &json!([{
                "name": ["On"],
                "rule": {
                    "type": "regex", "source": "switch", "field": "state", "regex": "^on$"
                }
            }]),
        )
        .unwrap();
        assert_eq!(
            categorized
                .iter()
                .map(|event| (
                    event.duration.num_seconds(),
                    event.data["$category"].clone()
                ))
                .collect::<Vec<_>>(),
            vec![
                (10, json!(["On"])),
                (10, json!(["Uncategorized"])),
                (10, json!(["On"])),
            ]
        );
    }

    #[test]
    fn scalar_predicates_use_ecmascript_spelling() {
        let cases = [
            (json!(1e-7), "^1e-7$"),
            (json!(1e-6), "^0\\.000001$"),
            (json!(1.5), "^1\\.5$"),
            (json!(1.0), "^1$"),
            (json!(-0.0), "^0$"),
            (json!(0.1), "^0\\.1$"),
            (json!(1e20), "^100000000000000000000$"),
            (json!(1e21), "^1e\\+21$"),
            (json!(123.456e5), "^12345600$"),
            (json!(1_000_000_000_000_000.2), "^1000000000000000\\.2$"),
            (json!(1_551_040_077_889.2812), "^1551040077889\\.2812$"),
            (json!(true), "^true$"),
            (json!(9_007_199_254_740_993_i64), "^9007199254740993$"),
        ];
        for (value, regex) in cases {
            let expression = json!({
                "type": "regex", "source": "values", "field": "value",
                "regex": regex, "value_mode": "scalar"
            });
            assert_eq!(
                active_periods_v2(
                    vec![(
                        "values".to_string(),
                        vec![event("2025-01-01T00:00:00Z", 1, json!({"value": value}),)]
                    )],
                    &expression,
                )
                .unwrap()
                .len(),
                1,
                "value {value}"
            );
        }
    }

    #[test]
    fn regex_runtime_failures_are_errors_even_when_negated() {
        let expression = json!({
            "type": "regex", "source": "values", "field": "value",
            "regex": "^(a+)+(?=b)$|^a+!$", "negate": true
        });
        let error = active_periods_v2(
            vec![(
                "values".to_string(),
                vec![event(
                    "2025-01-01T00:00:00Z",
                    1,
                    json!({"value": format!("{}!", "a".repeat(30))}),
                )],
            )],
            &expression,
        )
        .unwrap_err();
        assert!(error.contains("regex execution failed"), "{error}");
    }

    #[test]
    fn rejects_nonintegral_and_out_of_range_weight() {
        for weight in [json!(1.5), json!(1_000_001), json!(-1_000_001), json!(true)] {
            let expression = json!({
                "regex": "active", "source": "afk", "field": "state", "weight": weight
            });
            assert!(
                active_periods_v2(vec![("afk".to_string(), vec![])], &expression)
                    .unwrap_err()
                    .contains("weight")
            );
        }
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
