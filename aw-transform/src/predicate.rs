use aw_models::Event;
use fancy_regex::Regex;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValueMode {
    String,
    Scalar,
}

impl ValueMode {
    pub(crate) fn parse(value: Option<&Value>, context: &str) -> Result<Self, String> {
        match value {
            None => Ok(Self::String),
            Some(Value::String(value)) if value == "string" => Ok(Self::String),
            Some(Value::String(value)) if value == "scalar" => Ok(Self::Scalar),
            _ => Err(format!(
                "{context} 'value_mode' must be 'string' or 'scalar'"
            )),
        }
    }
}

pub(crate) struct RegexPredicate {
    regex: Regex,
    negate: bool,
    value_mode: ValueMode,
}

pub(crate) struct PredicateMatch {
    pub(crate) matched: bool,
    pub(crate) value_count: usize,
}

impl RegexPredicate {
    pub(crate) fn compile(
        pattern: &str,
        ignore_case: bool,
        negate: bool,
        value_mode: ValueMode,
    ) -> Result<Self, String> {
        let source = if ignore_case {
            format!("(?i){pattern}")
        } else {
            pattern.to_string()
        };
        let regex =
            Regex::new(&source).map_err(|error| format!("invalid regex {pattern:?}: {error}"))?;
        Ok(Self {
            regex,
            negate,
            value_mode,
        })
    }

    pub(crate) fn from_compiled(regex: Regex) -> Self {
        Self {
            regex,
            negate: false,
            value_mode: ValueMode::String,
        }
    }

    pub(crate) fn evaluate<'a>(
        &self,
        values: impl IntoIterator<Item = &'a Value>,
    ) -> Result<PredicateMatch, String> {
        let values = values
            .into_iter()
            .filter_map(|value| normalize_value(value, self.value_mode))
            .collect::<Vec<_>>();
        if values.is_empty() {
            return Ok(PredicateMatch {
                matched: false,
                value_count: 0,
            });
        }

        let mut any_match = false;
        for value in &values {
            if self
                .regex
                .is_match(value)
                .map_err(|error| format!("regex execution failed: {error}"))?
            {
                any_match = true;
                break;
            }
        }
        Ok(PredicateMatch {
            matched: if self.negate { !any_match } else { any_match },
            value_count: values.len(),
        })
    }
}

pub(crate) fn selected_values<'a>(
    event: &'a Event,
    source: Option<&str>,
    fields: Option<&[String]>,
) -> Vec<&'a Value> {
    let source_prefix = source
        .filter(|source| !source.is_empty())
        .map(|source| format!("$source.{source}."));
    if let Some(fields) = fields {
        return fields
            .iter()
            .filter_map(|field| {
                let key = source_prefix
                    .as_ref()
                    .map(|prefix| format!("{prefix}{field}"))
                    .unwrap_or_else(|| field.clone());
                event.data.get(&key)
            })
            .collect();
    }
    if let Some(source_prefix) = source_prefix {
        return event
            .data
            .iter()
            .filter(|(key, _)| key.starts_with(&source_prefix))
            .map(|(_, value)| value)
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
        (ValueMode::Scalar, Value::Number(value)) => Some(format_json_number(value)),
        _ => None,
    }
}

fn format_json_number(number: &serde_json::Number) -> String {
    if number.is_i64() || number.is_u64() {
        return number.to_string();
    }
    number
        .as_f64()
        .map(format_ecmascript_number)
        .unwrap_or_else(|| number.to_string())
}

fn format_ecmascript_number(value: f64) -> String {
    ryu_js::Buffer::new().format(value).to_string()
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::{normalize_value, ValueMode};

    #[test]
    fn scalar_values_use_ecmascript_number_spelling() {
        let cases = [
            (json!(1e-7), "1e-7"),
            (json!(1e-6), "0.000001"),
            (json!(1.5), "1.5"),
            (json!(1.0), "1"),
            (json!(-0.0), "0"),
            (json!(0.1), "0.1"),
            (json!(1e20), "100000000000000000000"),
            (json!(1e21), "1e+21"),
            (json!(123.456e5), "12345600"),
            (json!(1_000_000_000_000_000.2), "1000000000000000.2"),
            (json!(1_551_040_077_889.2812), "1551040077889.2812"),
            (json!(true), "true"),
            (json!(9_007_199_254_740_993_i64), "9007199254740993"),
        ];
        for (value, expected) in cases {
            assert_eq!(
                normalize_value(&value, ValueMode::Scalar).as_deref(),
                Some(expected),
                "value: {value}"
            );
        }
        for value in [Value::Null, json!([]), json!({})] {
            assert_eq!(normalize_value(&value, ValueMode::Scalar), None);
        }
    }
}
