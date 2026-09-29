use std::collections::{HashMap, HashSet};

use aw_models::Event;
use serde_json::{json, Value};

use crate::predicate::{selected_values, RegexPredicate, ValueMode};

pub(crate) const MAX_EXPRESSION_DEPTH: usize = 32;
pub(crate) const MAX_EXPRESSION_NODES: usize = 4096;
pub(crate) const MAX_REGEX_LENGTH: usize = 4096;
pub(crate) const MAX_CATEGORY_RULES: usize = 1000;
pub(crate) const MAX_RULE_SOURCES: usize = 128;
pub(crate) const MIN_RULE_INTEGER: i64 = -1_000_000;
pub(crate) const MAX_RULE_INTEGER: i64 = 1_000_000;

#[derive(Clone, Copy, Debug)]
struct MatchResult {
    matched: bool,
    score: i64,
}

enum RuleExpression {
    None,
    Regex {
        predicate: RegexPredicate,
        weight: i64,
        source: Option<String>,
        host: Option<String>,
        fields: Option<Vec<String>>,
    },
    All(Vec<RuleExpression>),
    Any(Vec<RuleExpression>),
}

impl RuleExpression {
    fn matches(&self, event: &Event) -> Result<MatchResult, String> {
        Ok(match self {
            Self::None => MatchResult {
                matched: false,
                score: 0,
            },
            Self::Regex {
                predicate,
                weight,
                source,
                host,
                fields,
            } => {
                if host.as_ref().is_some_and(|host| {
                    event.data.get("$host").and_then(Value::as_str) != Some(host.as_str())
                }) {
                    MatchResult {
                        matched: false,
                        score: 0,
                    }
                } else {
                    match_regex(event, predicate, *weight, source, fields)?.0
                }
            }
            Self::All(expressions) => {
                let mut score = 0_i64;
                for expression in expressions {
                    let result = expression.matches(event)?;
                    if !result.matched {
                        return Ok(MatchResult {
                            matched: false,
                            score: 0,
                        });
                    }
                    score = score.checked_add(result.score).ok_or_else(|| {
                        "category rule score overflowed the supported i64 range".to_string()
                    })?;
                }
                MatchResult {
                    matched: true,
                    score,
                }
            }
            Self::Any(expressions) => {
                let best_score = expressions
                    .iter()
                    .map(|expression| expression.matches(event))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|result| result.matched)
                    .map(|result| result.score)
                    .max();
                MatchResult {
                    matched: best_score.is_some(),
                    score: best_score.unwrap_or(0),
                }
            }
        })
    }

    fn explain(&self, event: &Event) -> Result<Value, String> {
        Ok(match self {
            Self::None => json!({"type": "none", "matched": false, "score": 0}),
            Self::Regex {
                predicate,
                weight,
                source,
                host,
                fields,
            } => {
                let host_matched = host.as_ref().map_or(true, |host| {
                    event.data.get("$host").and_then(Value::as_str) == Some(host.as_str())
                });
                let (result, value_count) = if host_matched {
                    match_regex(event, predicate, *weight, source, fields)?
                } else {
                    (
                        MatchResult {
                            matched: false,
                            score: 0,
                        },
                        0,
                    )
                };
                json!({
                    "type": "regex",
                    "matched": result.matched,
                    "score": result.score,
                    "value_count": value_count,
                    "host": host,
                    "host_matched": host_matched,
                })
            }
            Self::All(expressions) => {
                let children = expressions
                    .iter()
                    .map(|expression| expression.explain(event))
                    .collect::<Result<Vec<_>, _>>()?;
                let matched = children.iter().all(explanation_matched);
                let score = if matched {
                    children.iter().try_fold(0_i64, |score, child| {
                        score.checked_add(explanation_score(child)).ok_or_else(|| {
                            "category rule score overflowed the supported i64 range".to_string()
                        })
                    })?
                } else {
                    0
                };
                json!({"type": "all", "matched": matched, "score": score, "children": children})
            }
            Self::Any(expressions) => {
                let children = expressions
                    .iter()
                    .map(|expression| expression.explain(event))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut selected: Option<(usize, i64)> = None;
                for (index, child) in children.iter().enumerate() {
                    if explanation_matched(child) {
                        let score = explanation_score(child);
                        if selected
                            .map(|(_, best_score)| score > best_score)
                            .unwrap_or(true)
                        {
                            selected = Some((index, score));
                        }
                    }
                }
                json!({
                    "type": "any",
                    "matched": selected.is_some(),
                    "score": selected.map(|(_, score)| score).unwrap_or(0),
                    "selected": selected.map(|(index, _)| index),
                    "children": children,
                })
            }
        })
    }
}

fn match_regex(
    event: &Event,
    predicate: &RegexPredicate,
    weight: i64,
    source: &Option<String>,
    fields: &Option<Vec<String>>,
) -> Result<(MatchResult, usize), String> {
    let result =
        predicate.evaluate(selected_values(event, source.as_deref(), fields.as_deref()))?;
    Ok((
        MatchResult {
            matched: result.matched,
            score: if result.matched { weight } else { 0 },
        },
        result.value_count,
    ))
}

fn explanation_matched(value: &Value) -> bool {
    value
        .get("matched")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn explanation_score(value: &Value) -> i64 {
    value.get("score").and_then(Value::as_i64).unwrap_or(0)
}

pub struct CategoryRule {
    id: String,
    name: Vec<String>,
    expression: RuleExpression,
    priority: i64,
    set_priority: i64,
    requires: Vec<String>,
    index: usize,
}

pub(crate) fn categorize_legacy(
    events: Vec<Event>,
    legacy_rules: &[(Vec<String>, crate::classify::Rule)],
) -> Result<Vec<Event>, String> {
    let mut legacy_fields = events
        .iter()
        .flat_map(|event| event.data.keys().cloned())
        .collect::<Vec<_>>();
    legacy_fields.sort();
    legacy_fields.dedup();
    if legacy_fields.is_empty() {
        legacy_fields.push("__legacy_missing__".to_string());
    }

    let rules = legacy_rules
        .iter()
        .enumerate()
        .filter(|(_, (category, _))| !category.is_empty())
        .map(|(index, (category, rule))| CategoryRule {
            id: format!("legacy-{index}"),
            name: category.clone(),
            expression: match rule {
                crate::classify::Rule::None => RuleExpression::None,
                crate::classify::Rule::Regex(regex) => RuleExpression::Regex {
                    predicate: RegexPredicate::from_compiled(regex.regex.clone()),
                    weight: 0,
                    source: None,
                    host: None,
                    fields: Some(
                        regex
                            .select_keys
                            .clone()
                            .unwrap_or_else(|| legacy_fields.clone()),
                    ),
                },
            },
            priority: 0,
            set_priority: 0,
            requires: Vec::new(),
            index,
        })
        .collect::<Vec<_>>();
    categorize_with_rules(events, &rules, None)
}

pub fn compile_category_rules(specs: &Value) -> Result<Vec<CategoryRule>, String> {
    let specs = specs
        .as_array()
        .ok_or_else(|| "category rules must be a list".to_string())?;
    if specs.len() > MAX_CATEGORY_RULES {
        return Err(format!(
            "category rules exceed maximum count of {MAX_CATEGORY_RULES}"
        ));
    }
    let mut rules = Vec::with_capacity(specs.len());
    let mut ids = HashSet::new();
    let mut expression_state = ExpressionCompileState::default();

    for (index, spec) in specs.iter().enumerate() {
        let spec = spec
            .as_object()
            .ok_or_else(|| format!("category rule at index {index} must be an object"))?;
        let name = parse_nonempty_string_list(spec.get("name")).map_err(|_| {
            format!("category rule at index {index} requires a non-empty string list 'name'")
        })?;
        let default_id = name.join("\u{1f}");
        let id = match spec.get("id") {
            Some(Value::String(id)) if !id.is_empty() => id.clone(),
            None => default_id,
            _ => {
                return Err(format!(
                    "category rule at index {index} has an invalid 'id'"
                ))
            }
        };
        if !ids.insert(id.clone()) {
            return Err(format!("duplicate category rule id: {id:?}"));
        }

        let priority = parse_rule_integer(spec.get("priority"), 0)
            .map_err(|_| rule_integer_error(&format!("category rule {id:?} 'priority'")))?;
        let set_priority = parse_rule_integer(spec.get("set_priority"), 0)
            .map_err(|_| rule_integer_error(&format!("category rule {id:?} 'set_priority'")))?;
        let requires = match spec.get("requires") {
            None => Vec::new(),
            Some(value) => parse_string_list(value).map_err(|_| {
                format!("category rule {id:?} 'requires' must be a list of rule ids")
            })?,
        };
        let default_rule = json!({"type": "none"});
        let expression = compile_expression(
            spec.get("rule").unwrap_or(&default_rule),
            1,
            &mut expression_state,
        )?;

        rules.push(CategoryRule {
            id,
            name,
            expression,
            priority,
            set_priority,
            requires,
            index,
        });
    }

    validate_requirements(&rules)?;
    Ok(rules)
}

pub fn categorize_v2(events: Vec<Event>, category_specs: &Value) -> Result<Vec<Event>, String> {
    categorize_v2_for_host(events, category_specs, None)
}

pub fn categorize_v2_for_host(
    events: Vec<Event>,
    category_specs: &Value,
    host: Option<&str>,
) -> Result<Vec<Event>, String> {
    if host.is_some_and(str::is_empty) {
        return Err("categorization host must be a non-empty string".to_string());
    }
    let rules = compile_category_rules(category_specs)?;
    categorize_with_rules(events, &rules, host)
}

fn categorize_with_rules(
    mut events: Vec<Event>,
    rules: &[CategoryRule],
    host: Option<&str>,
) -> Result<Vec<Event>, String> {
    for event in &mut events {
        let previous_host = host.map(|host| event.data.insert("$host".to_string(), json!(host)));
        let raw_matches: HashMap<&str, MatchResult> = rules
            .iter()
            .map(|rule| (rule.id.as_str(), rule.expression.matches(event)))
            .map(|(id, result)| result.map(|result| (id, result)))
            .collect::<Result<_, _>>()?;
        let eligible_ids = eligible_rule_ids(&rules, &raw_matches);
        let winner = rules
            .iter()
            .filter(|rule| eligible_ids.contains(rule.id.as_str()))
            .max_by_key(|rule| {
                (
                    raw_matches[rule.id.as_str()].score,
                    rule.priority,
                    rule.name.len(),
                    rule.set_priority,
                    rule.index,
                )
            });

        if let Some(winner) = winner {
            event
                .data
                .insert("$category".to_string(), json!(winner.name));
            event.data.insert(
                "$category_score".to_string(),
                json!(raw_matches[winner.id.as_str()].score),
            );
            event
                .data
                .insert("$category_rule".to_string(), json!(winner.id));
        } else {
            event
                .data
                .insert("$category".to_string(), json!(["Uncategorized"]));
            event.data.insert("$category_score".to_string(), json!(0));
            event.data.insert("$category_rule".to_string(), Value::Null);
        }
        if let Some(previous_host) = previous_host {
            if let Some(previous_host) = previous_host {
                event.data.insert("$host".to_string(), previous_host);
            } else {
                event.data.remove("$host");
            }
        }
    }

    Ok(events)
}

pub fn categorize_v2_explain(
    events: Vec<Event>,
    category_specs: &Value,
) -> Result<Vec<Event>, String> {
    categorize_v2_explain_for_host(events, category_specs, None)
}

pub fn categorize_v2_explain_for_host(
    mut events: Vec<Event>,
    category_specs: &Value,
    host: Option<&str>,
) -> Result<Vec<Event>, String> {
    if host.is_some_and(str::is_empty) {
        return Err("categorization host must be a non-empty string".to_string());
    }
    let rules = compile_category_rules(category_specs)?;

    for event in &mut events {
        let previous_host = host.map(|host| event.data.insert("$host".to_string(), json!(host)));
        let raw_matches: HashMap<&str, MatchResult> = rules
            .iter()
            .map(|rule| (rule.id.as_str(), rule.expression.matches(event)))
            .map(|(id, result)| result.map(|result| (id, result)))
            .collect::<Result<_, _>>()?;
        let raw_explanations: HashMap<&str, Value> = rules
            .iter()
            .map(|rule| (rule.id.as_str(), rule.expression.explain(event)))
            .map(|(id, result)| result.map(|result| (id, result)))
            .collect::<Result<_, _>>()?;
        let eligible_ids = eligible_rule_ids(&rules, &raw_matches);
        let winner = rules
            .iter()
            .filter(|rule| eligible_ids.contains(rule.id.as_str()))
            .max_by_key(|rule| {
                (
                    raw_matches[rule.id.as_str()].score,
                    rule.priority,
                    rule.name.len(),
                    rule.set_priority,
                    rule.index,
                )
            });

        if let Some(winner) = winner {
            event
                .data
                .insert("$category".to_string(), json!(winner.name));
            event.data.insert(
                "$category_score".to_string(),
                json!(raw_matches[winner.id.as_str()].score),
            );
            event
                .data
                .insert("$category_rule".to_string(), json!(winner.id));
        } else {
            event
                .data
                .insert("$category".to_string(), json!(["Uncategorized"]));
            event.data.insert("$category_score".to_string(), json!(0));
            event.data.insert("$category_rule".to_string(), Value::Null);
        }

        let candidates = rules
            .iter()
            .map(|rule| {
                let requirements = rule
                    .requires
                    .iter()
                    .map(|required| {
                        (
                            required.clone(),
                            json!(
                                raw_matches[required.as_str()].matched
                                    && eligible_ids.contains(required.as_str())
                            ),
                        )
                    })
                    .collect::<serde_json::Map<String, Value>>();
                json!({
                    "id": rule.id,
                    "name": rule.name,
                    "matched": raw_matches[rule.id.as_str()].matched,
                    "eligible": eligible_ids.contains(rule.id.as_str()),
                    "score": raw_matches[rule.id.as_str()].score,
                    "priority": rule.priority,
                    "depth": rule.name.len(),
                    "set_priority": rule.set_priority,
                    "requires": rule.requires,
                    "requirements": requirements,
                    "expression": raw_explanations[rule.id.as_str()],
                })
            })
            .collect::<Vec<_>>();
        event.data.insert(
            "$category_explain".to_string(),
            json!({
                "winner": winner.map(|rule| rule.id.clone()),
                "candidates": candidates,
            }),
        );
        if let Some(previous_host) = previous_host {
            if let Some(previous_host) = previous_host {
                event.data.insert("$host".to_string(), previous_host);
            } else {
                event.data.remove("$host");
            }
        }
    }
    Ok(events)
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
) -> Result<RuleExpression, String> {
    if depth > MAX_EXPRESSION_DEPTH {
        return Err(format!(
            "rule expression exceeds maximum depth of {MAX_EXPRESSION_DEPTH}"
        ));
    }
    state.nodes += 1;
    if state.nodes > MAX_EXPRESSION_NODES {
        return Err(format!(
            "rule expression exceeds maximum node count of {MAX_EXPRESSION_NODES}"
        ));
    }
    let spec = spec
        .as_object()
        .ok_or_else(|| "rule expression must be an object".to_string())?;
    let rule_type = match spec.get("type") {
        Some(Value::String(rule_type)) => Some(rule_type.as_str()),
        Some(Value::Null) | None if spec.contains_key("regex") => Some("regex"),
        Some(Value::Null) | None => None,
        Some(value) => return Err(format!("unknown rule expression type: {value}")),
    };

    match rule_type {
        Some("none") => Ok(RuleExpression::None),
        Some("regex") => {
            let expression = compile_regex_expression(spec)?;
            if let RuleExpression::Regex {
                source: Some(source),
                ..
            } = &expression
            {
                state.sources.insert(source.clone());
                if state.sources.len() > MAX_RULE_SOURCES {
                    return Err(format!(
                        "rule expressions exceed maximum source count of {MAX_RULE_SOURCES}"
                    ));
                }
            }
            Ok(expression)
        }
        Some(rule_type @ ("all" | "any")) => {
            let children = spec
                .get("rules")
                .or_else(|| spec.get("children"))
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{rule_type} rule requires a list of child 'rules'"))?;
            if children.is_empty() {
                return Err("rule group must contain at least one child rule".to_string());
            }
            let expressions = children
                .iter()
                .map(|child| compile_expression(child, depth + 1, state))
                .collect::<Result<Vec<_>, _>>()?;
            if rule_type == "all" {
                Ok(RuleExpression::All(expressions))
            } else {
                Ok(RuleExpression::Any(expressions))
            }
        }
        _ => Err(format!(
            "unknown rule expression type: {}",
            rule_type
                .map(|value| format!("{value:?}"))
                .unwrap_or_else(|| "None".to_string())
        )),
    }
}

fn compile_regex_expression(
    spec: &serde_json::Map<String, Value>,
) -> Result<RuleExpression, String> {
    let regex_pattern = match spec.get("regex") {
        Some(Value::String(regex)) if !regex.is_empty() => regex,
        _ => return Err("regex rule requires a non-empty string 'regex'".to_string()),
    };
    if regex_pattern.len() > MAX_REGEX_LENGTH {
        return Err(format!(
            "regex rule exceeds maximum length of {MAX_REGEX_LENGTH}"
        ));
    }
    let ignore_case = parse_bool(spec.get("ignore_case"), false)
        .map_err(|_| "regex rule 'ignore_case' must be a boolean".to_string())?;
    let negate = parse_bool(spec.get("negate"), false)
        .map_err(|_| "regex rule 'negate' must be a boolean".to_string())?;
    let weight = parse_rule_integer(spec.get("weight"), 0)
        .map_err(|_| rule_integer_error("regex rule 'weight'"))?;
    let value_mode = ValueMode::parse(spec.get("value_mode"), "regex rule")?;
    let predicate = RegexPredicate::compile(regex_pattern, ignore_case, negate, value_mode)?;
    let source = match spec.get("source") {
        None | Some(Value::Null) => None,
        Some(Value::String(source)) => {
            if !source.is_empty()
                && !source
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
            {
                return Err(
                    "regex rule 'source' may only contain letters, numbers, '_' and '-'"
                        .to_string(),
                );
            }
            Some(source.clone())
        }
        _ => return Err("regex rule 'source' must be a string".to_string()),
    };
    let host = match spec.get("host") {
        None | Some(Value::Null) => None,
        Some(Value::String(host)) if !host.is_empty() => Some(host.clone()),
        _ => return Err("regex rule 'host' must be a non-empty string".to_string()),
    };
    let fields_value = if spec.contains_key("fields") {
        spec.get("fields")
    } else if spec.contains_key("field") {
        spec.get("field")
    } else {
        spec.get("select_keys")
    };
    let fields = match fields_value {
        None | Some(Value::Null) => None,
        Some(Value::String(field)) if !field.is_empty() => Some(vec![field.clone()]),
        Some(Value::Array(fields))
            if !fields.is_empty()
                && fields
                    .iter()
                    .all(|field| matches!(field, Value::String(value) if !value.is_empty())) =>
        {
            Some(
                fields
                    .iter()
                    .map(|field| field.as_str().unwrap().to_string())
                    .collect(),
            )
        }
        _ => {
            return Err(
                "regex rule field selector must be a non-empty string or list of strings"
                    .to_string(),
            )
        }
    };

    Ok(RuleExpression::Regex {
        predicate,
        weight,
        source,
        host,
        fields,
    })
}

fn validate_requirements(rules: &[CategoryRule]) -> Result<(), String> {
    let rules_by_id: HashMap<&str, &CategoryRule> =
        rules.iter().map(|rule| (rule.id.as_str(), rule)).collect();
    for rule in rules {
        let missing: Vec<&str> = rule
            .requires
            .iter()
            .map(String::as_str)
            .filter(|required| !rules_by_id.contains_key(required))
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "category rule {:?} requires unknown rule ids: {missing:?}",
                rule.id
            ));
        }
    }

    fn visit<'a>(
        rule_id: &'a str,
        rules_by_id: &HashMap<&'a str, &'a CategoryRule>,
        visiting: &mut HashSet<&'a str>,
        visited: &mut HashSet<&'a str>,
    ) -> Result<(), String> {
        if visiting.contains(rule_id) {
            return Err(format!(
                "category rule dependency cycle includes {rule_id:?}"
            ));
        }
        if visited.contains(rule_id) {
            return Ok(());
        }
        visiting.insert(rule_id);
        for required in &rules_by_id[rule_id].requires {
            visit(required, rules_by_id, visiting, visited)?;
        }
        visiting.remove(rule_id);
        visited.insert(rule_id);
        Ok(())
    }

    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for rule in rules {
        visit(&rule.id, &rules_by_id, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn eligible_rule_ids<'a>(
    rules: &'a [CategoryRule],
    raw_matches: &HashMap<&'a str, MatchResult>,
) -> HashSet<&'a str> {
    fn is_eligible<'a>(
        rule_id: &'a str,
        rules_by_id: &HashMap<&'a str, &'a CategoryRule>,
        raw_matches: &HashMap<&'a str, MatchResult>,
        eligibility: &mut HashMap<&'a str, bool>,
    ) -> bool {
        if let Some(eligible) = eligibility.get(rule_id) {
            return *eligible;
        }
        let rule = rules_by_id[rule_id];
        let eligible = raw_matches[rule_id].matched
            && rule
                .requires
                .iter()
                .all(|required| is_eligible(required, rules_by_id, raw_matches, eligibility));
        eligibility.insert(rule_id, eligible);
        eligible
    }

    let rules_by_id: HashMap<&str, &CategoryRule> =
        rules.iter().map(|rule| (rule.id.as_str(), rule)).collect();
    let mut eligibility = HashMap::new();
    rules
        .iter()
        .filter_map(|rule| {
            is_eligible(&rule.id, &rules_by_id, raw_matches, &mut eligibility)
                .then_some(rule.id.as_str())
        })
        .collect()
}

fn parse_bool(value: Option<&Value>, default: bool) -> Result<bool, ()> {
    match value {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(()),
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

fn rule_integer_error(field: &str) -> String {
    format!("{field} must be an integer between {MIN_RULE_INTEGER} and {MAX_RULE_INTEGER}")
}

fn parse_nonempty_string_list(value: Option<&Value>) -> Result<Vec<String>, ()> {
    let value = value.ok_or(())?;
    let values = parse_string_list(value)?;
    if values.is_empty() {
        Err(())
    } else {
        Ok(values)
    }
}

fn parse_string_list(value: &Value) -> Result<Vec<String>, ()> {
    let values = value.as_array().ok_or(())?;
    values
        .iter()
        .map(|value| match value {
            Value::String(value) if !value.is_empty() => Ok(value.clone()),
            _ => Err(()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use aw_models::Event;
    use serde_json::{json, Value};

    use super::{categorize_v2, categorize_v2_explain, categorize_v2_for_host};

    fn event(data: Value) -> Event {
        let mut event = Event::default();
        event.data = data.as_object().unwrap().clone();
        event
    }

    #[test]
    fn nested_rules_scores_sources_and_requirements() {
        let categories = json!([
            {
                "id": "work",
                "name": ["Work"],
                "rule": {"type": "regex", "field": "app", "regex": "devenv"}
            },
            {
                "id": "personal",
                "name": ["Personal"],
                "requires": ["work"],
                "rule": {
                    "type": "all",
                    "rules": [
                        {"type": "regex", "field": "app", "regex": "devenv"},
                        {
                            "type": "regex",
                            "source": "vdesktop",
                            "field": "vdesktop",
                            "regex": "^Personal$",
                            "weight": 10
                        }
                    ]
                }
            }
        ]);
        let result = categorize_v2(
            vec![event(json!({
                "app": "devenv.exe",
                "$source.vdesktop.vdesktop": "Personal"
            }))],
            &categories,
        )
        .unwrap();

        assert_eq!(result[0].data["$category"], json!(["Personal"]));
        assert_eq!(result[0].data["$category_score"], json!(10));
        assert_eq!(result[0].data["$category_rule"], json!("personal"));
    }

    #[test]
    fn any_uses_best_branch_and_ties_use_priority_depth_then_last() {
        let categories = json!([
            {
                "id": "first",
                "name": ["First"],
                "priority": 10,
                "rule": {"type": "regex", "regex": "matching"}
            },
            {
                "id": "deep",
                "name": ["First", "Deep"],
                "priority": 10,
                "rule": {
                    "type": "any",
                    "rules": [
                        {"type": "regex", "field": "title", "regex": "matching", "weight": 2},
                        {"type": "regex", "field": "app", "regex": "devenv", "weight": 5}
                    ]
                }
            },
            {
                "id": "last",
                "name": ["Last", "Deep"],
                "priority": 10,
                "rule": {"type": "regex", "regex": "matching", "weight": 5}
            }
        ]);
        let result = categorize_v2(
            vec![event(json!({"title": "matching", "app": "devenv.exe"}))],
            &categories,
        )
        .unwrap();

        assert_eq!(result[0].data["$category"], json!(["Last", "Deep"]));
        assert_eq!(result[0].data["$category_score"], json!(5));
    }

    #[test]
    fn explain_includes_selected_branch_and_parent_gate() {
        let categories = json!([
            {
                "id": "parent",
                "name": ["Work"],
                "rule": {"type": "regex", "field": "app", "regex": "Code"}
            },
            {
                "id": "child",
                "name": ["Work", "Project"],
                "requires": ["parent"],
                "rule": {
                    "type": "any",
                    "rules": [
                        {"type": "regex", "field": "title", "regex": "Other", "weight": 1},
                        {"type": "regex", "field": "title", "regex": "Project", "weight": 5}
                    ]
                }
            }
        ]);
        let result = categorize_v2_explain(
            vec![event(json!({"app": "Code", "title": "Project"}))],
            &categories,
        )
        .unwrap();
        let explain = &result[0].data["$category_explain"];
        let child = explain["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["id"] == json!("child"))
            .unwrap();

        assert_eq!(explain["winner"], json!("child"));
        assert_eq!(child["eligible"], json!(true));
        assert_eq!(child["requirements"]["parent"], json!(true));
        assert_eq!(child["expression"]["selected"], json!(1));
    }

    #[test]
    fn negate_requires_a_value_and_scalar_matching_is_opt_in() {
        let categories = json!([
            {
                "id": "negative",
                "name": ["Not Personal"],
                "rule": {
                    "type": "regex",
                    "field": "vdesktop",
                    "regex": "^Personal$",
                    "negate": true
                }
            },
            {
                "id": "scalar",
                "name": ["Scalar"],
                "rule": {
                    "type": "regex",
                    "field": "audible",
                    "regex": "^true$",
                    "value_mode": "scalar",
                    "weight": 1
                }
            }
        ]);
        let results = categorize_v2(
            vec![
                event(json!({"app": "test"})),
                event(json!({"vdesktop": "Work"})),
                event(json!({"audible": true})),
            ],
            &categories,
        )
        .unwrap();

        assert_eq!(results[0].data["$category"], json!(["Uncategorized"]));
        assert_eq!(results[1].data["$category"], json!(["Not Personal"]));
        assert_eq!(results[2].data["$category"], json!(["Scalar"]));
    }

    #[test]
    fn default_source_and_metadata_are_excluded() {
        let categories = json!([
            {
                "id": "metadata",
                "name": ["Metadata"],
                "rule": {"type": "regex", "regex": "first-rule"}
            },
            {
                "id": "default-source",
                "name": ["Default source"],
                "rule": {"type": "regex", "regex": "Personal"}
            }
        ]);
        let first = categorize_v2(
            vec![event(json!({
                "title": "other",
                "$source.vdesktop.name": "Personal",
                "$category_rule": "first-rule"
            }))],
            &categories,
        )
        .unwrap();

        assert_eq!(first[0].data["$category"], json!(["Uncategorized"]));
        assert_eq!(first[0].data["$category_score"], json!(0));
        assert_eq!(first[0].data["$category_rule"], Value::Null);
    }

    #[test]
    fn optional_host_gates_predicates() {
        let categories = json!([{
            "name": ["Workstation"],
            "rule": {
                "type": "regex",
                "host": "workstation",
                "field": "app",
                "regex": "editor"
            }
        }]);
        let matching = categorize_v2_for_host(
            vec![event(json!({"app": "editor"}))],
            &categories,
            Some("workstation"),
        )
        .unwrap();
        let other = categorize_v2_for_host(
            vec![event(json!({"app": "editor"}))],
            &categories,
            Some("laptop"),
        )
        .unwrap();

        assert_eq!(matching[0].data["$category"], json!(["Workstation"]));
        assert_eq!(other[0].data["$category"], json!(["Uncategorized"]));
        assert!(!matching[0].data.contains_key("$host"));
    }

    #[test]
    fn set_priority_ranks_after_category_depth_and_is_explained() {
        let categories = json!([
            {
                "id": "high-set-shallow",
                "name": ["Shallow"],
                "set_priority": 100,
                "rule": {"type": "regex", "regex": "match"}
            },
            {
                "id": "low-set-deep",
                "name": ["Deep", "Child"],
                "set_priority": 1,
                "rule": {"type": "regex", "regex": "match"}
            },
            {
                "id": "high-set-deep",
                "name": ["Winning", "Child"],
                "set_priority": 2,
                "rule": {"type": "regex", "regex": "match"}
            }
        ]);
        let result =
            categorize_v2_explain(vec![event(json!({"title": "match"}))], &categories).unwrap();
        assert_eq!(result[0].data["$category"], json!(["Winning", "Child"]));
        let priorities = result[0].data["$category_explain"]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|candidate| candidate["set_priority"].as_i64().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(priorities, vec![100, 1, 2]);

        let invalid = json!([{
            "name": ["Bad"],
            "set_priority": 1.5,
            "rule": {"type": "none"}
        }]);
        assert!(categorize_v2(Vec::new(), &invalid)
            .unwrap_err()
            .contains("'set_priority' must be an integer"));
    }

    #[test]
    fn field_aliases_priority_and_requirements_are_applied() {
        let aliases = json!([
            {
                "id": "all-fields",
                "name": ["All fields"],
                "rule": {"type": "regex", "regex": "match"}
            },
            {
                "id": "fields",
                "name": ["Fields"],
                "rule": {
                    "type": "regex",
                    "fields": ["app", "title"],
                    "regex": "match",
                    "weight": 2
                }
            },
            {
                "id": "select-keys",
                "name": ["Select keys"],
                "rule": {
                    "type": "regex",
                    "select_keys": ["project"],
                    "regex": "match",
                    "weight": 1
                }
            }
        ]);
        let results = categorize_v2(
            vec![
                event(json!({"project": "match", "app": "other"})),
                event(json!({"project": "other", "title": "match"})),
            ],
            &aliases,
        )
        .unwrap();
        assert_eq!(results[0].data["$category"], json!(["Select keys"]));
        assert_eq!(results[1].data["$category"], json!(["Fields"]));

        let requirements = json!([
            {
                "id": "parent",
                "name": ["Parent"],
                "rule": {"type": "regex", "field": "title", "regex": "parent"}
            },
            {
                "id": "gated",
                "name": ["Gated"],
                "priority": 100,
                "requires": ["parent"],
                "rule": {"type": "regex", "field": "app", "regex": "devenv"}
            },
            {
                "id": "fallback",
                "name": ["Fallback"],
                "priority": 1,
                "rule": {"type": "regex", "field": "app", "regex": "devenv"}
            }
        ]);
        let result = categorize_v2(
            vec![event(json!({"app": "devenv.exe", "title": "other"}))],
            &requirements,
        )
        .unwrap();
        assert_eq!(result[0].data["$category"], json!(["Fallback"]));

        let priority = json!([
            {"id": "low", "name": ["Low", "Deep"], "priority": 1, "rule": {"regex": "match"}},
            {"id": "high", "name": ["High"], "priority": 2, "rule": {"regex": "match"}}
        ]);
        let result = categorize_v2(vec![event(json!({"title": "match"}))], &priority).unwrap();
        assert_eq!(result[0].data["$category"], json!(["High"]));
    }

    #[test]
    fn rejects_invalid_specs() {
        let cycle = json!([
            {"id": "a", "name": ["A"], "requires": ["b"], "rule": {"regex": "test"}},
            {"id": "b", "name": ["B"], "requires": ["a"], "rule": {"regex": "test"}}
        ]);
        assert!(categorize_v2(Vec::new(), &cycle)
            .unwrap_err()
            .contains("dependency cycle"));

        let invalid_regex = json!([{"name": ["Invalid"], "rule": {"type": "regex", "regex": "["}}]);
        assert!(categorize_v2(Vec::new(), &invalid_regex)
            .unwrap_err()
            .contains("invalid regex"));

        let non_integer = json!([{"name": ["Invalid"], "priority": 1.5, "rule": {"type": "none"}}]);
        assert!(categorize_v2(Vec::new(), &non_integer)
            .unwrap_err()
            .contains("'priority' must be an integer"));

        let empty_group = json!([{"name": ["Invalid"], "rule": {"type": "all", "rules": []}}]);
        assert!(categorize_v2(Vec::new(), &empty_group)
            .unwrap_err()
            .contains("at least one child"));

        let mut nested = json!({"type": "regex", "regex": "test"});
        for _ in 0..32 {
            nested = json!({"type": "all", "rules": [nested]});
        }
        let too_deep = json!([{"name": ["Too deep"], "rule": nested}]);
        assert!(categorize_v2(Vec::new(), &too_deep)
            .unwrap_err()
            .contains("maximum depth"));

        let too_long = json!([{
            "name": ["Too long"],
            "rule": {"type": "regex", "regex": "x".repeat(4097)}
        }]);
        assert!(categorize_v2(Vec::new(), &too_long)
            .unwrap_err()
            .contains("maximum length"));
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
            let categories = json!([{
                "name": ["Matched"],
                "rule": {
                    "type": "regex", "field": "value", "regex": regex,
                    "value_mode": "scalar"
                }
            }]);
            let result =
                categorize_v2(vec![event(json!({"value": value.clone()}))], &categories).unwrap();
            assert_eq!(result[0].data["$category"], json!(["Matched"]), "{value}");
        }
    }

    #[test]
    fn regex_runtime_failures_propagate_from_matches_and_explanations() {
        let categories = json!([{
            "name": ["Negated"],
            "rule": {
                "type": "regex", "field": "value",
                "regex": "^(a+)+(?=b)$|^a+!$", "negate": true
            }
        }]);
        let events = vec![event(json!({"value": format!("{}!", "a".repeat(30))}))];

        let error = categorize_v2(events.clone(), &categories).unwrap_err();
        assert!(error.contains("regex execution failed"), "{error}");
        let error = categorize_v2_explain(events, &categories).unwrap_err();
        assert!(error.contains("regex execution failed"), "{error}");
    }

    #[test]
    fn ranking_integers_are_bounded() {
        let boundaries = json!([
            {
                "name": ["Minimum"], "priority": -1_000_000, "set_priority": -1_000_000,
                "rule": {"type": "regex", "regex": "match", "weight": -1_000_000}
            },
            {
                "name": ["Maximum"], "priority": 1_000_000, "set_priority": 1_000_000,
                "rule": {"type": "regex", "regex": "match", "weight": 1_000_000}
            }
        ]);
        let result = categorize_v2(vec![event(json!({"value": "match"}))], &boundaries).unwrap();
        assert_eq!(result[0].data["$category"], json!(["Maximum"]));

        for categories in [
            json!([{"name": ["Bad"], "priority": 1_000_001, "rule": {"type": "none"}}]),
            json!([{"name": ["Bad"], "set_priority": -1_000_001, "rule": {"type": "none"}}]),
            json!([{"name": ["Bad"], "rule": {"type": "regex", "regex": ".", "weight": true}}]),
        ] {
            let error = categorize_v2(Vec::new(), &categories).unwrap_err();
            assert!(error.contains("between -1000000 and 1000000"), "{error}");
        }
    }
}
