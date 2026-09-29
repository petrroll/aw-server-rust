use fancy_regex::Regex;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::fmt;

pub const RULES_KEY: &str = "rules_v2";
pub const PROFILE_KEY: &str = "activity_profiles_v2";
pub const SET_KEY: &str = "category_sets_v2";
pub const LEGACY_KEYS: [&str; 6] = [
    PROFILE_KEY,
    SET_KEY,
    "classes",
    "always_active_pattern",
    "category_sets",
    "active_set_ids",
];
const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 4096;
const MAX_REGEX: usize = 4096;
const MAX_CATEGORIES: usize = 1000;
const MAX_SOURCES: usize = 128;
const MIN_RULE_INTEGER: i64 = -1_000_000;
const MAX_RULE_INTEGER: i64 = 1_000_000;
pub const MAX_SAFE_REVISION: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum BuiltinSource {
    Window,
    Browser,
    Stopwatch,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum IntervalPolicy {
    Exact,
    Heartbeat,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum SourceScope {
    Host,
    Global,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FieldType {
    String,
    Scalar,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RulesSettingsError {
    Validation(String),
    Conflict(String),
}

impl fmt::Display for RulesSettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(message) | Self::Conflict(message) => formatter.write_str(message),
        }
    }
}

impl From<String> for RulesSettingsError {
    fn from(message: String) -> Self {
        Self::Validation(message)
    }
}

fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))
}

fn array<'a>(value: &'a Value, path: &str) -> Result<&'a Vec<Value>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{path} must be an array"))
}

fn string<'a>(value: &'a Value, path: &str, allow_empty: bool) -> Result<&'a str, String> {
    value
        .as_str()
        .filter(|value| allow_empty || !value.is_empty())
        .ok_or_else(|| {
            format!(
                "{path} must be a {}string",
                if allow_empty { "" } else { "non-empty " }
            )
        })
}

fn integer(value: &Value, path: &str) -> Result<i64, String> {
    value
        .as_i64()
        .ok_or_else(|| format!("{path} must be an integer JSON token"))
}

fn rule_integer(value: &Value, path: &str) -> Result<i64, String> {
    let value = integer(value, path)?;
    if !(MIN_RULE_INTEGER..=MAX_RULE_INTEGER).contains(&value) {
        return Err(format!(
            "{path} must be between {MIN_RULE_INTEGER} and {MAX_RULE_INTEGER}"
        ));
    }
    Ok(value)
}

fn string_array<'a>(value: &'a Value, path: &str, nonempty: bool) -> Result<Vec<&'a str>, String> {
    let values = array(value, path)?;
    if nonempty && values.is_empty() {
        return Err(format!("{path} must not be empty"));
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| string(value, &format!("{path}[{index}]"), false))
        .collect()
}

fn typed_present<T: DeserializeOwned>(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<T>, String> {
    object
        .get(key)
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|error| format!("{path}.{key} is invalid: {error}"))
        })
        .transpose()
}

fn optional_bool(object: &Map<String, Value>, key: &str, path: &str) -> Result<(), String> {
    if object.get(key).is_some_and(|value| !value.is_boolean()) {
        return Err(format!("{path}.{key} must be boolean"));
    }
    Ok(())
}

struct ExpressionState {
    nodes: usize,
    sources: HashSet<String>,
}

fn validate_expression(
    value: &Value,
    path: &str,
    state: &mut ExpressionState,
    depth: usize,
    allow_none_children: bool,
    require_source: bool,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{path} exceeds maximum depth of {MAX_DEPTH}"));
    }
    let expression = object(value, path)?;
    state.nodes += 1;
    if state.nodes > MAX_NODES {
        return Err(format!("{path} exceeds maximum node count of {MAX_NODES}"));
    }
    match expression.get("type").and_then(Value::as_str) {
        Some("none") => Ok(()),
        Some("regex") => {
            let pattern = string(
                expression.get("regex").unwrap_or(&Value::Null),
                &format!("{path}.regex"),
                false,
            )?;
            if pattern.len() > MAX_REGEX {
                return Err(format!(
                    "{path}.regex exceeds maximum length of {MAX_REGEX}"
                ));
            }
            Regex::new(pattern).map_err(|error| format!("{path}.regex is invalid: {error}"))?;
            if let Some(weight) = expression.get("weight") {
                rule_integer(weight, &format!("{path}.weight"))?;
            }
            if expression.contains_key("field") && expression.contains_key("fields") {
                return Err(format!("{path} cannot contain both field and fields"));
            }
            if let Some(field) = expression.get("field") {
                string(field, &format!("{path}.field"), false)?;
            }
            if let Some(fields) = expression.get("fields") {
                string_array(fields, &format!("{path}.fields"), true)?;
            }
            for key in ["source", "host"] {
                if let Some(value) = expression.get(key) {
                    string(value, &format!("{path}.{key}"), false)?;
                }
            }
            let source = expression.get("source").and_then(Value::as_str);
            if require_source && source.is_none() {
                return Err(format!("{path}.source must be non-empty"));
            }
            if let Some(source) = source {
                state.sources.insert(source.to_string());
                if state.sources.len() > MAX_SOURCES {
                    return Err(format!(
                        "{path} exceeds maximum source count of {MAX_SOURCES}"
                    ));
                }
            }
            match expression.get("value_mode") {
                None => {}
                Some(Value::String(value)) if matches!(value.as_str(), "string" | "scalar") => {}
                _ => return Err(format!("{path}.value_mode must be string or scalar")),
            }
            optional_bool(expression, "ignore_case", path)?;
            optional_bool(expression, "negate", path)
        }
        Some(kind @ ("all" | "any")) => {
            let rules = array(
                expression.get("rules").unwrap_or(&Value::Null),
                &format!("{path}.rules"),
            )?;
            if rules.is_empty() {
                return Err(format!("{path}.rules must contain at least one rule"));
            }
            for (index, rule) in rules.iter().enumerate() {
                let child_path = format!("{path}.rules[{index}]");
                if !allow_none_children && rule.get("type").and_then(Value::as_str) == Some("none")
                {
                    return Err(format!("{child_path} must be configured"));
                }
                validate_expression(
                    rule,
                    &child_path,
                    state,
                    depth + 1,
                    allow_none_children,
                    require_source,
                )?;
            }
            let _ = kind;
            Ok(())
        }
        _ => Err(format!("{path}.type is unsupported")),
    }
}

fn legacy_compatible_category(category: &Value) -> bool {
    let Some(category) = category.as_object() else {
        return false;
    };
    if ["priority", "set_priority"].iter().any(|key| {
        category
            .get(*key)
            .is_some_and(|value| integer(value, key).ok() != Some(0))
    }) || category
        .get("requires")
        .and_then(Value::as_array)
        .is_some_and(|requires| !requires.is_empty())
    {
        return false;
    }
    let Some(rule) = category.get("rule").and_then(Value::as_object) else {
        return false;
    };
    if rule.get("type").and_then(Value::as_str) == Some("none") {
        return true;
    }
    rule.get("type").and_then(Value::as_str) == Some("regex")
        && rule.get("source").map_or(true, Value::is_null)
        && rule.get("host").map_or(true, Value::is_null)
        && !rule.get("negate").and_then(Value::as_bool).unwrap_or(false)
        && rule
            .get("weight")
            .map_or(true, |weight| integer(weight, "weight").ok() == Some(0))
        && matches!(
            rule.get("value_mode").and_then(Value::as_str),
            None | Some("string")
        )
}

fn validate_category_set(value: &Value, path: &str) -> Result<(), String> {
    let category_set = object(value, path)?;
    if category_set.get("schema_version").and_then(Value::as_i64) != Some(2) {
        return Err(format!("{path}.schema_version must be 2"));
    }
    string(
        category_set.get("id").unwrap_or(&Value::Null),
        &format!("{path}.id"),
        false,
    )?;
    if let Some(priority) = category_set.get("priority") {
        rule_integer(priority, &format!("{path}.priority"))?;
    }
    let categories = array(
        category_set.get("categories").unwrap_or(&Value::Null),
        &format!("{path}.categories"),
    )?;
    if categories.len() > MAX_CATEGORIES {
        return Err(format!(
            "{path}.categories exceeds maximum count of {MAX_CATEGORIES}"
        ));
    }
    let mut ids = HashSet::new();
    let mut by_id: HashMap<String, &Value> = HashMap::new();
    let mut state = ExpressionState {
        nodes: 0,
        sources: HashSet::new(),
    };
    for (index, category_value) in categories.iter().enumerate() {
        let category_path = format!("{path}.categories[{index}]");
        let category = object(category_value, &category_path)?;
        let id = string(
            category.get("id").unwrap_or(&Value::Null),
            &format!("{category_path}.id"),
            false,
        )?;
        if !ids.insert(id.to_string()) {
            return Err(format!("{category_path}.id is duplicated"));
        }
        by_id.insert(id.to_string(), category_value);
        string_array(
            category.get("name").unwrap_or(&Value::Null),
            &format!("{category_path}.name"),
            true,
        )?;
        for key in ["priority", "set_priority"] {
            if let Some(priority) = category.get(key) {
                rule_integer(priority, &format!("{category_path}.{key}"))?;
            }
        }
        if let Some(requires) = category.get("requires") {
            string_array(requires, &format!("{category_path}.requires"), false)?;
        }
        if category.get("data").is_some_and(|data| !data.is_object()) {
            return Err(format!("{category_path}.data must be an object"));
        }
        optional_bool(category, "simple_ui", &category_path)?;
        validate_expression(
            category.get("rule").unwrap_or(&Value::Null),
            &format!("{category_path}.rule"),
            &mut state,
            1,
            false,
            false,
        )?;
        if category.get("simple_ui").and_then(Value::as_bool) == Some(true)
            && !legacy_compatible_category(category_value)
        {
            return Err(format!(
                "{category_path} has simple_ui=true but is not simple-compatible"
            ));
        }
    }
    for (id, category) in &by_id {
        for required in category
            .get("requires")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let required = required.as_str().unwrap();
            let Some(required_category) = by_id.get(required) else {
                return Err(format!(
                    "{path}.categories[{id}].requires references unknown id {required}"
                ));
            };
            if required_category
                .pointer("/rule/type")
                .and_then(Value::as_str)
                == Some("none")
            {
                return Err(format!(
                    "{path}.categories[{id}].requires references category without a matching rule {required}"
                ));
            }
        }
    }
    fn visit(
        id: &str,
        by_id: &HashMap<String, &Value>,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
        path: &str,
    ) -> Result<(), String> {
        if visiting.contains(id) {
            return Err(format!(
                "{path} contains a category requirement cycle at {id}"
            ));
        }
        if visited.contains(id) {
            return Ok(());
        }
        visiting.insert(id.to_string());
        for required in by_id[id]
            .get("requires")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            visit(required.as_str().unwrap(), by_id, visiting, visited, path)?;
        }
        visiting.remove(id);
        visited.insert(id.to_string());
        Ok(())
    }
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for id in by_id.keys() {
        visit(id, &by_id, &mut visiting, &mut visited, path)?;
    }
    Ok(())
}

fn validate_source(value: &Value, path: &str) -> Result<(), String> {
    let source = object(value, path)?;
    let id = string(
        source.get("id").unwrap_or(&Value::Null),
        &format!("{path}.id"),
        false,
    )?;
    if !id
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '-')
    {
        return Err(format!("{path}.id contains unsupported characters"));
    }
    string(
        source.get("label").unwrap_or(&Value::Null),
        &format!("{path}.label"),
        false,
    )?;
    let bucket_ids = string_array(
        source.get("bucket_ids").unwrap_or(&Value::Null),
        &format!("{path}.bucket_ids"),
        false,
    )?;
    let fields = string_array(
        source.get("fields").unwrap_or(&Value::Null),
        &format!("{path}.fields"),
        true,
    )?;
    if bucket_ids.iter().collect::<HashSet<_>>().len() != bucket_ids.len() {
        return Err(format!("{path}.bucket_ids must be unique"));
    }
    if fields.iter().collect::<HashSet<_>>().len() != fields.len() {
        return Err(format!("{path}.fields must be unique"));
    }
    let builtin = typed_present::<BuiltinSource>(source, "builtin", path)?;
    let expected_id = match builtin {
        Some(BuiltinSource::Window) => Some("builtin_window"),
        Some(BuiltinSource::Browser) => Some("browser"),
        Some(BuiltinSource::Stopwatch) => Some("stopwatch"),
        None => None,
    };
    if expected_id.is_some_and(|expected| expected != id) {
        return Err(format!("{path}.builtin is unsupported for this source id"));
    }
    if builtin.is_none() && bucket_ids.is_empty() {
        return Err(format!(
            "{path}.bucket_ids must be non-empty for a custom source"
        ));
    }

    typed_present::<IntervalPolicy>(source, "interval_policy", path)?;
    let explicit_scope = typed_present::<SourceScope>(source, "scope", path)?;
    let field_types = typed_present::<HashMap<String, FieldType>>(source, "field_types", path)?;
    if let Some(field_types) = &field_types {
        if let Some(field) = field_types
            .keys()
            .find(|field| !fields.contains(&field.as_str()))
        {
            return Err(format!(
                "{path}.field_types may not describe unconfigured field {field:?}"
            ));
        }
    }
    for key in ["creates_activity", "keeps_active", "auto_generated"] {
        optional_bool(source, key, path)?;
    }
    if source
        .get("keeps_active")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && !source
            .get("creates_activity")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err(format!("{path}.keeps_active requires creates_activity"));
    }

    let host = typed_present::<String>(source, "host", path)?;
    if host.as_ref().is_some_and(String::is_empty) {
        return Err(format!("{path}.host must be a non-empty string"));
    }
    let bucket_hosts = typed_present::<HashMap<String, String>>(source, "bucket_hosts", path)?;
    if let Some((bucket, _)) = bucket_hosts
        .as_ref()
        .and_then(|hosts| hosts.iter().find(|(_, host)| host.is_empty()))
    {
        return Err(format!(
            "{path}.bucket_hosts[{bucket}] must be a non-empty string"
        ));
    }

    let has_host = host.is_some();
    let has_bucket_hosts = bucket_hosts.is_some();
    if explicit_scope == Some(SourceScope::Global) && (has_host || has_bucket_hosts) {
        return Err(format!("{path} global scope cannot define host ownership"));
    }
    if has_host && has_bucket_hosts {
        return Err(format!(
            "{path} host scope must use either host or bucket_hosts"
        ));
    }

    // Builtin buckets are discovered by the client. Known fields are fully
    // typed above; ownership completeness is checked after discovery.
    if builtin.is_some() && bucket_ids.is_empty() {
        return Ok(());
    }

    if let Some(bucket_hosts) = &bucket_hosts {
        if bucket_hosts.len() != bucket_ids.len()
            || bucket_ids
                .iter()
                .any(|bucket| !bucket_hosts.contains_key(*bucket))
        {
            return Err(format!(
                "{path}.bucket_hosts must map every and only configured bucket id"
            ));
        }
    }
    let scope =
        explicit_scope.or_else(|| (has_host || has_bucket_hosts).then_some(SourceScope::Host));
    let Some(scope) = scope else {
        return Err(format!("{path}.scope must be host or global"));
    };
    if scope == SourceScope::Host && !has_host && !has_bucket_hosts {
        return Err(format!("{path} host scope requires host ownership"));
    }
    Ok(())
}

fn expression_sources(value: &Value, output: &mut HashSet<String>) {
    match value.get("type").and_then(Value::as_str) {
        Some("regex") => {
            if let Some(source) = value.get("source").and_then(Value::as_str) {
                output.insert(source.to_string());
            }
        }
        Some("all" | "any") => {
            for child in value
                .get("rules")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                expression_sources(child, output);
            }
        }
        _ => {}
    }
}

fn expression_has_unsourced_regex(value: &Value) -> bool {
    match value.get("type").and_then(Value::as_str) {
        Some("regex") => value.get("source").is_none(),
        Some("all" | "any") => value
            .get("rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(expression_has_unsourced_regex),
        _ => false,
    }
}

fn validate_profile(
    value: &Value,
    path: &str,
    sets: &HashMap<String, &Value>,
) -> Result<(), String> {
    let profile = object(value, path)?;
    if profile.get("schema_version").and_then(Value::as_i64) != Some(2) {
        return Err(format!("{path}.schema_version must be 2"));
    }
    string(
        profile.get("id").unwrap_or(&Value::Null),
        &format!("{path}.id"),
        false,
    )?;
    if let Some(version) = profile.get("source_defaults_version") {
        if integer(version, &format!("{path}.source_defaults_version"))? < 0 {
            return Err(format!(
                "{path}.source_defaults_version must be non-negative"
            ));
        }
    }
    let selected = string_array(
        profile.get("category_set_ids").unwrap_or(&Value::Null),
        &format!("{path}.category_set_ids"),
        true,
    )?;
    if selected.iter().collect::<HashSet<_>>().len() != selected.len() {
        return Err(format!("{path}.category_set_ids must be unique"));
    }
    for set_id in &selected {
        if !sets.contains_key(*set_id) {
            return Err(format!(
                "{path}.category_set_ids references unknown category set {set_id}"
            ));
        }
    }
    let sources = array(
        profile.get("sources").unwrap_or(&Value::Null),
        &format!("{path}.sources"),
    )?;
    if sources.len() > MAX_SOURCES {
        return Err(format!(
            "{path}.sources exceeds maximum count of {MAX_SOURCES}"
        ));
    }
    let mut source_ids = HashSet::new();
    for (index, source) in sources.iter().enumerate() {
        validate_source(source, &format!("{path}.sources[{index}]"))?;
        let id = source.get("id").and_then(Value::as_str).unwrap();
        if !source_ids.insert(id.to_string()) {
            return Err(format!("{path}.sources[{index}].id is duplicated"));
        }
    }
    for key in ["app_title_source_id", "browser_focus_source_id"] {
        if let Some(value) = profile.get(key) {
            let source = string(value, &format!("{path}.{key}"), false)?;
            if !source_ids.contains(source) {
                return Err(format!("{path}.{key} references unknown source {source}"));
            }
        }
    }
    let active_time = object(
        profile.get("active_time").unwrap_or(&Value::Null),
        &format!("{path}.active_time"),
    )?;
    match active_time.get("type").and_then(Value::as_str) {
        Some("legacy") => {
            for key in ["use_afk", "include_audible"] {
                if !active_time.get(key).is_some_and(Value::is_boolean) {
                    return Err(format!("{path}.active_time.{key} must be boolean"));
                }
            }
            let pattern = string(
                active_time
                    .get("always_active_pattern")
                    .unwrap_or(&Value::Null),
                &format!("{path}.active_time.always_active_pattern"),
                true,
            )?;
            if !pattern.is_empty() {
                Regex::new(pattern).map_err(|error| {
                    format!("{path}.active_time.always_active_pattern is invalid: {error}")
                })?;
                let window = sources
                    .iter()
                    .find(|source| source.get("builtin").and_then(Value::as_str) == Some("window"))
                    .ok_or_else(|| {
                        format!(
                            "{path}.active_time.always_active_pattern requires a configured App & window source"
                        )
                    })?;
                if !window["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|field| matches!(field.as_str(), Some("app") | Some("title")))
                {
                    return Err(format!(
                        "{path}.active_time.always_active_pattern requires an App & window source exposing app or title"
                    ));
                }
            }
        }
        Some("expression") => {
            let rule = active_time.get("rule").unwrap_or(&Value::Null);
            let mut state = ExpressionState {
                nodes: 0,
                sources: HashSet::new(),
            };
            validate_expression(
                rule,
                &format!("{path}.active_time.rule"),
                &mut state,
                1,
                true,
                true,
            )?;
            if let Some(missing) = state
                .sources
                .iter()
                .find(|source| !source_ids.contains(source.as_str()))
            {
                return Err(format!(
                    "{path}.active_time.rule references unknown source {missing}"
                ));
            }
        }
        _ => {
            return Err(format!(
                "{path}.active_time.type must be legacy or expression"
            ))
        }
    }
    let selected_category_count = selected
        .iter()
        .map(|set_id| sets[*set_id]["categories"].as_array().unwrap().len())
        .sum::<usize>();
    if selected_category_count > MAX_CATEGORIES {
        return Err(format!(
            "{path}.category_set_ids select {selected_category_count} category rules; maximum is {MAX_CATEGORIES}"
        ));
    }
    let mut aggregate_state = ExpressionState {
        nodes: 0,
        sources: HashSet::new(),
    };
    for set_id in selected {
        for (category_index, category) in sets[set_id]
            .get("categories")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .enumerate()
        {
            validate_expression(
                &category["rule"],
                &format!("{path}.category_set_ids[{set_id}].categories[{category_index}].rule"),
                &mut aggregate_state,
                1,
                false,
                false,
            )?;
            if let Some(missing) = aggregate_state
                .sources
                .iter()
                .find(|source| !source_ids.contains(source.as_str()))
            {
                return Err(format!(
                    "{path}.category_set_ids[{set_id}] references unknown source {missing}"
                ));
            }
            if expression_has_unsourced_regex(&category["rule"])
                && !sources
                    .iter()
                    .any(|source| source.get("builtin").and_then(Value::as_str) == Some("window"))
            {
                return Err(format!(
                    "{path}.category_set_ids[{set_id}] category {} has an unsourced rule but no App & window source",
                    category["id"].as_str().unwrap()
                ));
            }
            let mut used_sources = HashSet::new();
            expression_sources(&category["rule"], &mut used_sources);
            if let Some(missing) = used_sources
                .iter()
                .find(|source| !source_ids.contains(source.as_str()))
            {
                return Err(format!(
                    "{path}.category_set_ids[{set_id}] category {} references unknown source {missing}",
                    category["id"].as_str().unwrap()
                ));
            }
        }
    }
    Ok(())
}

pub fn validate_envelope(value: &Value) -> Result<(), String> {
    let envelope = object(value, RULES_KEY)?;
    let expected: HashSet<&str> = ["revision", PROFILE_KEY, SET_KEY].into_iter().collect();
    let actual: HashSet<&str> = envelope.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(format!(
            "{RULES_KEY} must contain exactly revision, {PROFILE_KEY}, and {SET_KEY}"
        ));
    }
    let revision = envelope["revision"].as_u64().ok_or_else(|| {
        format!("rules_v2.revision must be an integer between 0 and {MAX_SAFE_REVISION}")
    })?;
    if revision > MAX_SAFE_REVISION {
        return Err(format!(
            "rules_v2.revision must be between 0 and {MAX_SAFE_REVISION}"
        ));
    }
    let category_sets = array(&envelope[SET_KEY], "rules_v2.category_sets_v2")?;
    let profiles = array(&envelope[PROFILE_KEY], "rules_v2.activity_profiles_v2")?;
    if category_sets.is_empty() || profiles.is_empty() {
        return Err("rules_v2 must contain at least one profile and category set".to_string());
    }
    let mut sets = HashMap::new();
    for (index, category_set) in category_sets.iter().enumerate() {
        validate_category_set(category_set, &format!("rules_v2.category_sets_v2[{index}]"))?;
        let id = category_set["id"].as_str().unwrap();
        if sets.insert(id.to_string(), category_set).is_some() {
            return Err(format!(
                "rules_v2.category_sets_v2[{index}].id is duplicated"
            ));
        }
    }
    let mut profile_ids = HashSet::new();
    for (index, profile) in profiles.iter().enumerate() {
        validate_profile(
            profile,
            &format!("rules_v2.activity_profiles_v2[{index}]"),
            &sets,
        )?;
        let id = profile["id"].as_str().unwrap();
        if !profile_ids.insert(id) {
            return Err(format!(
                "rules_v2.activity_profiles_v2[{index}].id is duplicated"
            ));
        }
    }
    Ok(())
}

fn v2_rule_to_legacy(rule: &Value) -> Value {
    if rule.get("type").and_then(Value::as_str) != Some("regex") {
        return json!({"type": "none"});
    }
    let mut legacy = Map::new();
    legacy.insert("type".to_string(), json!("regex"));
    legacy.insert("regex".to_string(), rule["regex"].clone());
    if let Some(value) = rule.get("ignore_case") {
        legacy.insert("ignore_case".to_string(), value.clone());
    }
    if let Some(value) = rule.get("fields") {
        legacy.insert("select_keys".to_string(), value.clone());
    } else if let Some(value) = rule.get("field") {
        legacy.insert("select_keys".to_string(), json!([value]));
    } else if let Some(value) = rule.get("select_keys") {
        legacy.insert("select_keys".to_string(), value.clone());
    }
    Value::Object(legacy)
}

fn set_to_legacy(category_set: &Value) -> Value {
    Value::Array(
        category_set["categories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|category| {
                let mut projected = Map::new();
                projected.insert("name".to_string(), category["name"].clone());
                projected.insert(
                    "rule".to_string(),
                    if legacy_compatible_category(category) {
                        v2_rule_to_legacy(&category["rule"])
                    } else {
                        json!({"type": "none"})
                    },
                );
                if let Some(data) = category.get("data") {
                    projected.insert("data".to_string(), data.clone());
                }
                Value::Object(projected)
            })
            .collect(),
    )
}

pub fn projection(envelope: &Value) -> Result<Map<String, Value>, String> {
    validate_envelope(envelope)?;
    let profile = &envelope[PROFILE_KEY][0];
    let sets: HashMap<&str, &Value> = envelope[SET_KEY]
        .as_array()
        .unwrap()
        .iter()
        .map(|set| (set["id"].as_str().unwrap(), set))
        .collect();
    let active_ids = profile["category_set_ids"].as_array().unwrap();
    let mut seen = HashSet::new();
    let mut classes = Vec::new();
    for set_id in active_ids {
        for category in set_to_legacy(sets[set_id.as_str().unwrap()])
            .as_array()
            .unwrap()
        {
            let name = serde_json::to_string(&category["name"]).unwrap();
            if seen.insert(name) {
                classes.push(category.clone());
            }
        }
    }
    let category_sets = envelope[SET_KEY]
        .as_array()
        .unwrap()
        .iter()
        .map(|set| json!({"id": set["id"], "categories": set_to_legacy(set)}))
        .collect();
    let active_time = &profile["active_time"];
    let mut result = Map::new();
    result.insert(PROFILE_KEY.to_string(), envelope[PROFILE_KEY].clone());
    result.insert(SET_KEY.to_string(), envelope[SET_KEY].clone());
    result.insert("classes".to_string(), Value::Array(classes));
    result.insert(
        "always_active_pattern".to_string(),
        if active_time["type"] == "legacy" {
            active_time["always_active_pattern"].clone()
        } else {
            json!("")
        },
    );
    result.insert("category_sets".to_string(), Value::Array(category_sets));
    result.insert(
        "active_set_ids".to_string(),
        Value::Array(active_ids.clone()),
    );
    Ok(result)
}

fn legacy_rule_to_v2(rule: &Value, path: &str) -> Result<Value, String> {
    if rule.is_null() {
        return Ok(json!({"type": "none"}));
    }
    let rule = object(rule, path)?;
    match rule.get("type") {
        None | Some(Value::Null) => return Ok(json!({"type": "none"})),
        Some(Value::String(value)) if value == "none" => {
            return Ok(json!({"type": "none"}));
        }
        Some(Value::String(value)) if value == "regex" => {}
        _ => return Err(format!("{path}.type must be regex or none")),
    }
    let pattern = string(
        rule.get("regex").unwrap_or(&Value::Null),
        &format!("{path}.regex"),
        false,
    )?;
    Regex::new(pattern).map_err(|error| format!("{path}.regex is invalid: {error}"))?;
    let mut result = json!({"type": "regex", "regex": pattern, "weight": 0});
    if let Some(ignore_case) = rule.get("ignore_case") {
        if !ignore_case.is_boolean() {
            return Err(format!("{path}.ignore_case must be boolean"));
        }
        if ignore_case == &Value::Bool(true) {
            result["ignore_case"] = Value::Bool(true);
        }
    }
    if let Some(select_keys) = rule.get("select_keys") {
        let keys = string_array(select_keys, &format!("{path}.select_keys"), true)?;
        if keys.len() == 1 {
            result["field"] = json!(keys[0]);
        } else {
            result["fields"] = select_keys.clone();
        }
    }
    Ok(result)
}

fn stable_category_id(set_id: &str, name: &[&str]) -> String {
    // Category names are escaped byte-for-byte to match encodeURIComponent for
    // the ASCII names emitted by predecessor clients. Non-ASCII remains stable
    // and unambiguous through percent encoding.
    fn encode(segment: &str) -> String {
        segment
            .bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
                    (byte as char).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect()
    }
    format!(
        "{set_id}:{}",
        name.iter()
            .map(|segment| encode(segment))
            .collect::<Vec<_>>()
            .join("/")
    )
}

fn legacy_categories_to_v2(value: &Value, set_id: &str, path: &str) -> Result<Value, String> {
    let categories = array(value, path)?;
    if categories.len() > MAX_CATEGORIES {
        return Err(format!("{path} exceeds maximum count of {MAX_CATEGORIES}"));
    }
    let mut result = Vec::new();
    let mut names = HashSet::new();
    for (index, category_value) in categories.iter().enumerate() {
        let category_path = format!("{path}[{index}]");
        let category = object(category_value, &category_path)?;
        let name = string_array(
            category.get("name").unwrap_or(&Value::Null),
            &format!("{category_path}.name"),
            true,
        )?;
        let name_key = serde_json::to_string(&category["name"]).unwrap();
        if !names.insert(name_key) {
            return Err(format!("{category_path}.name is duplicated"));
        }
        let mut converted = json!({
            "id": stable_category_id(set_id, &name),
            "name": category["name"].clone(),
            "rule": legacy_rule_to_v2(category.get("rule").unwrap_or(&Value::Null), &format!("{category_path}.rule"))?,
            "simple_ui": true
        });
        if let Some(data) = category.get("data") {
            if !data.is_object() {
                return Err(format!("{category_path}.data must be an object"));
            }
            converted["data"] = data.clone();
        }
        result.push(converted);
    }
    Ok(Value::Array(result))
}

fn set_is_legacy_writable(category_set: &Value) -> bool {
    category_set["categories"]
        .as_array()
        .unwrap()
        .iter()
        .all(legacy_compatible_category)
}

pub fn translate_legacy_write(
    envelope: &Value,
    key: &str,
    value: &Value,
) -> Result<Value, RulesSettingsError> {
    if matches!(key, PROFILE_KEY | SET_KEY) {
        return Err(RulesSettingsError::Conflict(format!(
            "{key} is part of the atomic rules_v2 document; write /settings/rules_v2 instead"
        )));
    }
    let mut updated = envelope.clone();
    let profile = &mut updated[PROFILE_KEY][0];
    match key {
        "always_active_pattern" => {
            string(value, key, true)?;
            if profile["active_time"]["type"] != "legacy" {
                return Err(RulesSettingsError::Conflict(
                    "always_active_pattern cannot represent the canonical active-time expression"
                        .to_string(),
                ));
            }
            profile["active_time"]["always_active_pattern"] = value.clone();
        }
        "active_set_ids" => {
            let active_ids = string_array(value, key, true)?;
            if active_ids.iter().collect::<HashSet<_>>().len() != active_ids.len() {
                return Err(RulesSettingsError::Validation(
                    "active_set_ids must be unique".to_string(),
                ));
            }
            let known: HashSet<&str> = updated[SET_KEY]
                .as_array()
                .unwrap()
                .iter()
                .map(|set| set["id"].as_str().unwrap())
                .collect();
            if let Some(missing) = active_ids.iter().find(|id| !known.contains(**id)) {
                return Err(RulesSettingsError::Validation(format!(
                    "active_set_ids references unknown set {missing}"
                )));
            }
            updated[PROFILE_KEY][0]["category_set_ids"] = value.clone();
        }
        "classes" => {
            let active_ids = profile["category_set_ids"].as_array().unwrap();
            if active_ids.len() != 1 {
                return Err(RulesSettingsError::Conflict(
                    "classes write is ambiguous while multiple canonical category sets are active"
                        .to_string(),
                ));
            }
            let set_id = active_ids[0].as_str().unwrap().to_string();
            let category_sets = updated[SET_KEY].as_array_mut().unwrap();
            let category_set = category_sets
                .iter_mut()
                .find(|set| set["id"] == set_id)
                .unwrap();
            if !set_is_legacy_writable(category_set) {
                return Err(RulesSettingsError::Conflict(
                    "classes write would discard advanced canonical category rules".to_string(),
                ));
            }
            category_set["categories"] = legacy_categories_to_v2(value, &set_id, "classes")?;
        }
        "category_sets" => {
            let incoming = array(value, key)?;
            let mut seen = HashSet::new();
            for (index, legacy_set_value) in incoming.iter().enumerate() {
                let path = format!("category_sets[{index}]");
                let legacy_set = object(legacy_set_value, &path)?;
                let id = string(
                    legacy_set.get("id").unwrap_or(&Value::Null),
                    &format!("{path}.id"),
                    false,
                )?;
                if !seen.insert(id.to_string()) {
                    return Err(RulesSettingsError::Validation(format!(
                        "{path}.id is duplicated"
                    )));
                }
                let categories = legacy_categories_to_v2(
                    legacy_set.get("categories").unwrap_or(&Value::Null),
                    id,
                    &format!("{path}.categories"),
                )?;
                let category_sets = updated[SET_KEY].as_array_mut().unwrap();
                if let Some(position) = category_sets.iter().position(|set| set["id"] == id) {
                    if !set_is_legacy_writable(&category_sets[position]) {
                        return Err(RulesSettingsError::Conflict(format!(
                            "category_sets write would discard advanced canonical rules in set {id}"
                        )));
                    }
                    // Preserve set-level priority and forward-compatible metadata
                    // that the predecessor format cannot express.
                    category_sets[position]["categories"] = categories;
                } else {
                    category_sets.push(json!({
                        "schema_version": 2,
                        "id": id,
                        "categories": categories
                    }));
                }
            }
        }
        _ => {
            return Err(RulesSettingsError::Validation(format!(
                "{key} is not a legacy rules key"
            )))
        }
    }
    validate_envelope(&updated)?;
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_projection_preserves_select_keys_alias() {
        let document = json!({
            "revision": 0,
            "activity_profiles_v2": [{
                "schema_version": 2,
                "id": "default",
                "category_set_ids": ["work"],
                "sources": [{
                    "id":"builtin_window", "label":"Window", "bucket_ids":[],
                    "builtin":"window", "fields":["app", "title"],
                    "creates_activity":true, "interval_policy":"heartbeat"
                }],
                "active_time": {
                    "type":"legacy", "use_afk":true, "include_audible":true,
                    "always_active_pattern":""
                }
            }],
            "category_sets_v2": [{
                "schema_version":2, "id":"work", "categories":[{
                    "id":"work", "name":["Work"], "simple_ui":true,
                    "rule":{"type":"regex", "regex":"Editor", "select_keys":["title"]}
                }]
            }]
        });
        let projected = projection(&document).unwrap();
        assert_eq!(
            projected["classes"][0]["rule"]["select_keys"],
            json!(["title"])
        );
    }

    #[test]
    fn selected_sets_share_the_executable_category_budget() {
        let categories = |set_id: &str| {
            (0..501)
                .map(|index| {
                    json!({
                        "id": format!("{set_id}-{index}"),
                        "name": [set_id, index.to_string()],
                        "rule": {"type": "none"}
                    })
                })
                .collect::<Vec<_>>()
        };
        let document = json!({
            "revision": 0,
            "activity_profiles_v2": [{
                "schema_version": 2,
                "id": "default",
                "category_set_ids": ["one", "two"],
                "sources": [],
                "active_time": {"type": "expression", "rule": {"type": "none"}}
            }],
            "category_sets_v2": [
                {"schema_version": 2, "id": "one", "categories": categories("one")},
                {"schema_version": 2, "id": "two", "categories": categories("two")}
            ]
        });
        let error = validate_envelope(&document).unwrap_err();
        assert!(error.contains("select 1002 category rules"), "{error}");
    }

    #[test]
    fn selected_sets_share_the_executable_expression_budget() {
        let category = |set_id: &str| {
            json!({
                "id": format!("{set_id}-root"),
                "name": [set_id],
                "rule": {
                    "type": "any",
                    "rules": (0..2048).map(|_| json!({"type":"regex", "regex":"."})).collect::<Vec<_>>()
                }
            })
        };
        let document = json!({
            "revision": 0,
            "activity_profiles_v2": [{
                "schema_version": 2,
                "id": "default",
                "category_set_ids": ["one", "two"],
                "sources": [{"schema_version":2, "id":"builtin_window", "label":"Window", "bucket_ids":[], "builtin":"window", "fields":["app"], "creates_activity":true, "interval_policy":"heartbeat"}],
                "active_time": {"type": "expression", "rule": {"type": "none"}}
            }],
            "category_sets_v2": [
                {"schema_version": 2, "id": "one", "categories": [category("one")]},
                {"schema_version": 2, "id": "two", "categories": [category("two")]}
            ]
        });
        let error = validate_envelope(&document).unwrap_err();
        assert!(error.contains("maximum node count of 4096"), "{error}");
    }
}
