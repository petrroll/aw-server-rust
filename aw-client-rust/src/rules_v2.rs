//! Native settings/profile compiler for the source-only v2 query pipeline.

use crate::queries::{
    try_build_canonical_events_v2, ActiveTimeSource, ActivityCoverageSource,
    CanonicalQueryV2Options, ContextSource, IntervalPolicy, SourceScope,
};
use aw_models::Bucket;
use fancy_regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const BUILTIN_WINDOW_SOURCE_ID: &str = "builtin_window";
pub const BUILTIN_BROWSER_SOURCE_ID: &str = "browser";
pub const BUILTIN_STOPWATCH_SOURCE_ID: &str = "stopwatch";
pub const AFK_SOURCE_ID: &str = "afk";

#[derive(Debug, thiserror::Error)]
pub enum ProfileQueryError {
    #[error("ActivityWatch request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid activity profile: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileQueryRequest {
    #[serde(default)]
    pub profile_id: Option<String>,
    pub hostname: String,
    #[serde(default = "default_true")]
    pub filter_afk: bool,
    #[serde(default)]
    pub filter_categories: Option<Vec<Vec<String>>>,
    #[serde(default)]
    pub explain_categories: bool,
}

fn default_true() -> bool {
    true
}

impl ProfileQueryRequest {
    pub fn for_hostname(hostname: impl Into<String>) -> Self {
        Self {
            profile_id: None,
            hostname: hostname.into(),
            filter_afk: true,
            filter_categories: None,
            explain_categories: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MaterializedProfileV2 {
    pub profile_id: String,
    pub options: CanonicalQueryV2Options,
    pub app_title_source_id: Option<String>,
    pub browser_focus_source_id: Option<String>,
}

impl MaterializedProfileV2 {
    pub fn query(&self) -> Result<String, String> {
        try_build_canonical_events_v2(&self.options)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesEnvelope {
    revision: i64,
    activity_profiles_v2: Vec<ActivityProfile>,
    category_sets_v2: Vec<CategorySet>,
}

#[derive(Debug, Clone, Deserialize)]
struct ActivityProfile {
    schema_version: i64,
    id: String,
    category_set_ids: Vec<String>,
    sources: Vec<SourceDefinition>,
    #[serde(default)]
    app_title_source_id: Option<String>,
    #[serde(default)]
    browser_focus_source_id: Option<String>,
    active_time: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct CategorySet {
    schema_version: i64,
    id: String,
    #[serde(default)]
    priority: Option<i64>,
    categories: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct SourceDefinition {
    id: String,
    label: String,
    bucket_ids: Vec<String>,
    #[serde(default)]
    builtin: Option<String>,
    #[serde(default)]
    scope: Option<SourceScope>,
    #[serde(default)]
    bucket_hosts: BTreeMap<String, String>,
    fields: Vec<String>,
    #[serde(default)]
    creates_activity: bool,
    #[serde(default)]
    keeps_active: bool,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    interval_policy: Option<IntervalPolicy>,
}

fn policy(source: &SourceDefinition) -> IntervalPolicy {
    source
        .interval_policy
        .unwrap_or(match source.builtin.as_deref() {
            Some("window" | "browser") => IntervalPolicy::Heartbeat,
            _ => IntervalPolicy::Exact,
        })
}

pub fn flattened_rule_id(set_id: &str, rule_id: &str) -> String {
    format!("set:{}:{set_id}:rule:{rule_id}", set_id.len())
}

fn flatten_category_sets(
    profile: &ActivityProfile,
    category_sets: &[CategorySet],
) -> Result<Vec<Value>, String> {
    if profile.category_set_ids.is_empty() {
        return Err("activity profile must select at least one category set".to_string());
    }
    let by_id = category_sets
        .iter()
        .map(|set| (set.id.as_str(), set))
        .collect::<BTreeMap<_, _>>();
    let mut result = Vec::new();
    for (set_index, set_id) in profile.category_set_ids.iter().enumerate() {
        let set = by_id.get(set_id.as_str()).ok_or_else(|| {
            format!("activity profile references unavailable category set {set_id:?}")
        })?;
        let local_ids = set
            .categories
            .iter()
            .filter_map(|category| category.get("id").and_then(Value::as_str))
            .collect::<BTreeSet<_>>();
        for category in &set.categories {
            let mut category = category
                .as_object()
                .cloned()
                .ok_or_else(|| format!("category set {set_id:?} contains a non-object rule"))?;
            let rule_id = category
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| format!("category set {set_id:?} contains a rule without an id"))?
                .to_string();
            category.insert("id".to_string(), json!(flattened_rule_id(set_id, &rule_id)));
            if let Some(requirements) = category.get_mut("requires") {
                let requirements = requirements.as_array_mut().ok_or_else(|| {
                    format!("category rule {rule_id:?} has invalid prerequisites")
                })?;
                for requirement in requirements {
                    let id = requirement
                        .as_str()
                        .filter(|id| local_ids.contains(id))
                        .ok_or_else(|| {
                            format!("category rule {rule_id:?} has an invalid prerequisite")
                        })?;
                    *requirement = json!(flattened_rule_id(set_id, id));
                }
            }
            category.insert(
                "set_priority".to_string(),
                json!(set
                    .priority
                    .unwrap_or((profile.category_set_ids.len() - set_index) as i64)),
            );
            result.push(Value::Object(category));
        }
    }
    Ok(result)
}

fn qualify_legacy_expression(value: &Value, source_id: &str) -> Value {
    let Some(mut expression) = value.as_object().cloned() else {
        return json!({"type": "none"});
    };
    if expression.get("type") == Some(&Value::Null) {
        return json!({"type": "none"});
    }
    let kind = match expression.get("type") {
        Some(value) => value.as_str(),
        None if expression.contains_key("regex") => Some("regex"),
        None => None,
    };
    if kind.is_none() {
        return json!({"type": "none"});
    }
    match kind {
        Some("regex") => {
            expression.entry("type").or_insert(json!("regex"));
            expression.entry("source").or_insert(json!(source_id));
            if !expression.contains_key("field") && !expression.contains_key("fields") {
                if let Some(keys) = expression
                    .remove("select_keys")
                    .and_then(|value| value.as_array().cloned())
                {
                    if keys.len() == 1 {
                        expression.insert("field".to_string(), keys[0].clone());
                    } else if !keys.is_empty() {
                        expression.insert("fields".to_string(), Value::Array(keys));
                    }
                }
            }
        }
        Some("all" | "any") => {
            let children = expression
                .remove("rules")
                .or_else(|| expression.remove("children"))
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default();
            expression.insert(
                "rules".to_string(),
                Value::Array(
                    children
                        .iter()
                        .map(|child| qualify_legacy_expression(child, source_id))
                        .collect(),
                ),
            );
        }
        _ => {}
    }
    Value::Object(expression)
}

fn encode_uri_component(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| match *byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => (*byte as char).to_string(),
            byte => format!("%{byte:02X}"),
        })
        .collect()
}

fn stable_category_id(set_id: &str, name: &[Value]) -> String {
    let encoded = name
        .iter()
        .filter_map(Value::as_str)
        .map(encode_uri_component)
        .collect::<Vec<_>>()
        .join("/");
    format!("{set_id}:{encoded}")
}

fn migrate_category_set(categories: &[Value], set_id: &str) -> Value {
    let categories = categories
        .iter()
        .filter_map(|category| {
            let category = category.as_object()?;
            let name = category.get("name")?.as_array()?.clone();
            let mut rule = qualify_legacy_expression(
                category.get("rule").unwrap_or(&Value::Null),
                BUILTIN_WINDOW_SOURCE_ID,
            );
            if rule.get("type").and_then(Value::as_str) == Some("regex") {
                rule.as_object_mut()
                    .expect("qualified rules are objects")
                    .entry("weight")
                    .or_insert(json!(0));
            }
            let mut output = serde_json::Map::from_iter([
                ("id".to_string(), json!(stable_category_id(set_id, &name))),
                ("name".to_string(), Value::Array(name)),
                ("rule".to_string(), rule),
                ("simple_ui".to_string(), json!(true)),
            ]);
            if let Some(data) = category.get("data").filter(|data| !data.is_null()) {
                output.insert("data".to_string(), data.clone());
            }
            Some(Value::Object(output))
        })
        .collect::<Vec<_>>();
    json!({"schema_version": 2, "id": set_id, "categories": categories})
}

fn default_sources() -> Value {
    json!([
        {"id": BUILTIN_WINDOW_SOURCE_ID, "label": "App & window", "bucket_ids": [], "builtin": "window", "fields": ["app", "title"], "creates_activity": true, "interval_policy": "heartbeat"},
        {"id": BUILTIN_BROWSER_SOURCE_ID, "label": "Browser tabs", "bucket_ids": [], "builtin": "browser", "fields": ["title", "url", "audible", "incognito", "tabCount"], "interval_policy": "heartbeat"},
        {"id": BUILTIN_STOPWATCH_SOURCE_ID, "label": "Stopwatch", "bucket_ids": [], "builtin": "stopwatch", "fields": ["label"], "creates_activity": true, "keeps_active": true, "interval_policy": "exact"}
    ])
}

fn default_profile(settings: &Value, selected_set_ids: &[String]) -> Value {
    json!({
        "schema_version": 2,
        "source_defaults_version": 4,
        "id": "default",
        "category_set_ids": selected_set_ids,
        "sources": default_sources(),
        "app_title_source_id": BUILTIN_WINDOW_SOURCE_ID,
        "browser_focus_source_id": BUILTIN_WINDOW_SOURCE_ID,
        "active_time": {
            "type": "legacy", "use_afk": true, "include_audible": true,
            "always_active_pattern": settings.get("always_active_pattern").cloned().unwrap_or(json!(""))
        }
    })
}

fn migrate_legacy_category_sets(settings: &Value) -> Option<(Vec<Value>, Vec<String>)> {
    let legacy_sets = settings.get("category_sets")?.as_array()?;
    let valid = legacy_sets
        .iter()
        .filter_map(|set| {
            let set = set.as_object()?;
            Some((
                set.get("id")?.as_str()?.to_string(),
                set.get("categories")?.as_array()?.clone(),
            ))
        })
        .filter(|(id, _)| !id.is_empty())
        .collect::<Vec<_>>();
    if valid.is_empty() {
        return None;
    }
    let known = valid
        .iter()
        .map(|(id, _)| id.as_str())
        .collect::<BTreeSet<_>>();
    let mut active_ids = Vec::new();
    if let Some(requested) = settings.get("active_set_ids").and_then(Value::as_array) {
        for id in requested.iter().filter_map(Value::as_str) {
            if known.contains(id) && !active_ids.iter().any(|selected| selected == id) {
                active_ids.push(id.to_string());
            }
        }
    }
    if active_ids.is_empty() {
        active_ids.push(valid[0].0.clone());
    }
    let originals = valid
        .iter()
        .map(|(id, categories)| migrate_category_set(categories, id))
        .collect::<Vec<_>>();
    Some((originals, active_ids))
}

fn initialize_predecessor_profiles(profiles: &[Value]) -> Vec<Value> {
    let mut profiles = profiles.to_vec();
    for profile in &mut profiles {
        let Some(profile) = profile.as_object_mut() else {
            continue;
        };
        let version = profile
            .get("source_defaults_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if version >= 4 {
            continue;
        }
        let Some(sources) = profile.get_mut("sources").and_then(Value::as_array_mut) else {
            continue;
        };
        if version < 2 {
            let defaults = default_sources().as_array().unwrap().clone();
            if !sources
                .iter()
                .any(|source| source.get("builtin") == Some(&json!("window")))
            {
                sources.insert(0, defaults[0].clone());
            }
            if !sources
                .iter()
                .any(|source| source.get("id") == Some(&json!(BUILTIN_BROWSER_SOURCE_ID)))
            {
                sources.push(defaults[1].clone());
            }
            if !sources
                .iter()
                .any(|source| source.get("id") == Some(&json!(BUILTIN_STOPWATCH_SOURCE_ID)))
            {
                sources.push(defaults[2].clone());
            }
        }
        if version < 3 {
            if let Some(stopwatch) = sources.iter_mut().find(|source| {
                source.get("builtin") == Some(&json!("stopwatch"))
                    || source.get("id") == Some(&json!(BUILTIN_STOPWATCH_SOURCE_ID))
            }) {
                if stopwatch.get("creates_activity").and_then(Value::as_bool) == Some(true)
                    && stopwatch.get("keeps_active").is_none()
                {
                    stopwatch["keeps_active"] = json!(true);
                }
            }
        }
        if version < 4 {
            for source in sources {
                if source.get("interval_policy").is_none() {
                    source["interval_policy"] = if matches!(
                        source.get("builtin").and_then(Value::as_str),
                        Some("window" | "browser")
                    ) {
                        json!("heartbeat")
                    } else {
                        json!("exact")
                    };
                }
            }
        }
        profile.insert("source_defaults_version".to_string(), json!(4));
        profile
            .entry("app_title_source_id")
            .or_insert(json!(BUILTIN_WINDOW_SOURCE_ID));
        profile
            .entry("browser_focus_source_id")
            .or_insert(json!(BUILTIN_WINDOW_SOURCE_ID));
    }
    profiles
}

pub fn migrate_legacy_settings(settings: &Value) -> Value {
    if let (Some(profiles), Some(sets)) = (
        settings
            .get("activity_profiles_v2")
            .and_then(Value::as_array),
        settings.get("category_sets_v2").and_then(Value::as_array),
    ) {
        return json!({
            "revision": 0,
            "activity_profiles_v2": initialize_predecessor_profiles(profiles),
            "category_sets_v2": sets,
        });
    }

    let (category_sets, selected_set_ids) =
        migrate_legacy_category_sets(settings).unwrap_or_else(|| {
            let defaults = crate::classes::default_class_settings();
            let classes = match settings.get("classes") {
                Some(Value::Array(classes)) => classes.clone(),
                _ => serde_json::to_value(defaults)
                    .expect("built-in categories serialize")
                    .as_array()
                    .expect("built-in categories are an array")
                    .clone(),
            };
            (
                vec![migrate_category_set(&classes, "default")],
                vec!["default".to_string()],
            )
        });
    json!({
        "revision": 0,
        "activity_profiles_v2": [default_profile(settings, &selected_set_ids)],
        "category_sets_v2": category_sets,
    })
}

fn discover_builtin(
    kind: &str,
    buckets: &HashMap<String, Bucket>,
    hostname: &str,
) -> (Vec<String>, SourceScope) {
    let event_type = match kind {
        "window" => "currentwindow",
        "browser" => "web.tab.current",
        "stopwatch" => "general.stopwatch",
        _ => return (Vec::new(), SourceScope::Global),
    };
    let candidates = buckets
        .iter()
        .filter(|(id, bucket)| {
            bucket._type == event_type
                && !(kind == "window" && id.starts_with("aw-watcher-android"))
        })
        .collect::<Vec<_>>();
    let mut owned = candidates
        .iter()
        .filter(|(_, bucket)| bucket.hostname == hostname)
        .map(|(id, _)| (*id).clone())
        .collect::<Vec<_>>();
    owned.sort();
    if !owned.is_empty() {
        return (owned, SourceScope::Host);
    }
    if matches!(kind, "browser" | "stopwatch") {
        let mut unknown = candidates
            .iter()
            .filter(|(_, bucket)| bucket.hostname == "unknown")
            .map(|(id, _)| (*id).clone())
            .collect::<Vec<_>>();
        unknown.sort();
        return (unknown, SourceScope::Global);
    }
    (Vec::new(), SourceScope::Host)
}

fn materialize_source(
    source: &SourceDefinition,
    buckets: &HashMap<String, Bucket>,
    hostname: &str,
) -> Option<SourceDefinition> {
    let mut source = source.clone();
    if source.bucket_ids.is_empty() {
        if let Some(builtin) = source.builtin.as_deref() {
            let (bucket_ids, scope) = discover_builtin(builtin, buckets, hostname);
            source.bucket_ids = bucket_ids;
            source.scope = Some(scope);
            source.host = (scope == SourceScope::Host).then(|| hostname.to_string());
            source.bucket_hosts.clear();
        }
    }
    (!source.bucket_ids.is_empty()).then_some(source)
}

fn allocate_generated_source_id(used_ids: &mut BTreeSet<String>, base: &str) -> String {
    let mut candidate = base.to_string();
    let mut suffix = 2;
    while used_ids.contains(&candidate) {
        candidate = format!("{base}_{suffix}");
        suffix += 1;
    }
    used_ids.insert(candidate.clone());
    candidate
}

fn append_active_source(
    active_sources: &mut Vec<ActiveTimeSource>,
    source: ActiveTimeSource,
) -> Result<(), String> {
    match active_sources
        .iter()
        .find(|candidate| candidate.source_id == source.source_id)
    {
        None => active_sources.push(source),
        Some(existing) if existing == &source => {}
        Some(_) => {
            return Err(format!(
                "distinct active sources use id {:?}",
                source.source_id
            ))
        }
    }
    Ok(())
}

fn active_source(source: &SourceDefinition) -> ActiveTimeSource {
    ActiveTimeSource {
        source_id: source.id.clone(),
        bucket_ids: source.bucket_ids.clone(),
        scope: source.scope,
        bucket_hosts: source.bucket_hosts.clone(),
        host: source.host.clone(),
        interval_policy: policy(source),
    }
}

fn collect_source_ids(expression: &Value, output: &mut BTreeSet<String>) {
    let Some(expression) = expression.as_object() else {
        return;
    };
    let kind = expression.get("type").and_then(Value::as_str);
    match kind {
        Some("regex") => {
            if let Some(source) = expression.get("source").and_then(Value::as_str) {
                output.insert(source.to_string());
            }
        }
        Some("all" | "any") => {
            if let Some(children) = expression
                .get("rules")
                .or_else(|| expression.get("children"))
                .and_then(Value::as_array)
            {
                for child in children {
                    collect_source_ids(child, output);
                }
            }
        }
        _ => {}
    }
}

const RULES_SCHEMA_VERSION: i64 = 2;
const MAX_CATEGORY_RULES: usize = 1000;
const MAX_EXPRESSION_NODES: usize = 4096;
const MAX_EXPRESSION_DEPTH: usize = 32;
const MAX_RULE_SOURCES: usize = 128;
const MAX_REGEX_LENGTH: usize = 4096;
const MAX_RANKING_INTEGER: i64 = 1_000_000;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Default)]
struct BoundaryExpressionState {
    nodes: usize,
    sources: BTreeSet<String>,
}

fn validate_ranking_integer(value: &Value, path: &str) -> Result<(), String> {
    let value = value.as_i64().ok_or_else(|| {
        format!(
            "{path} must be an integer between {} and {MAX_RANKING_INTEGER}",
            -MAX_RANKING_INTEGER
        )
    })?;
    if !(-MAX_RANKING_INTEGER..=MAX_RANKING_INTEGER).contains(&value) {
        return Err(format!(
            "{path} must be an integer between {} and {MAX_RANKING_INTEGER}",
            -MAX_RANKING_INTEGER
        ));
    }
    Ok(())
}

fn validate_expression_boundary(
    expression: &Value,
    path: &str,
    depth: usize,
    state: &mut BoundaryExpressionState,
) -> Result<(), String> {
    let expression = expression
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))?;
    if let Some(weight) = expression.get("weight") {
        validate_ranking_integer(weight, &format!("{path}.weight"))?;
    }
    if depth > MAX_EXPRESSION_DEPTH {
        return Err(format!(
            "{path} exceeds maximum depth of {MAX_EXPRESSION_DEPTH}"
        ));
    }
    state.nodes += 1;
    if state.nodes > MAX_EXPRESSION_NODES {
        return Err(format!(
            "{path} exceeds maximum node count of {MAX_EXPRESSION_NODES}"
        ));
    }
    let kind = expression.get("type").and_then(Value::as_str);
    match kind {
        Some("none") => Ok(()),
        Some("regex") => {
            let pattern = expression
                .get("regex")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{path}.regex must be a non-empty string"))?;
            if pattern.len() > MAX_REGEX_LENGTH {
                return Err(format!(
                    "{path}.regex exceeds maximum length of {MAX_REGEX_LENGTH}"
                ));
            }
            Regex::new(pattern).map_err(|error| format!("{path}.regex is invalid: {error}"))?;
            if let Some(source) = expression.get("source") {
                let source = source
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("{path}.source must be a non-empty string"))?;
                state.sources.insert(source.to_string());
                if state.sources.len() > MAX_RULE_SOURCES {
                    return Err(format!(
                        "{path} exceeds maximum source count of {MAX_RULE_SOURCES}"
                    ));
                }
            }
            Ok(())
        }
        Some("all" | "any") => {
            let children = expression
                .get("rules")
                .or_else(|| expression.get("children"))
                .and_then(Value::as_array)
                .filter(|rules| !rules.is_empty())
                .ok_or_else(|| format!("{path}.rules must be a non-empty array"))?;
            for (index, child) in children.iter().enumerate() {
                validate_expression_boundary(
                    child,
                    &format!("{path}.rules[{index}]"),
                    depth + 1,
                    state,
                )?;
            }
            Ok(())
        }
        _ => Err(format!("{path}.type is unsupported")),
    }
}

fn required_string_array<'a>(value: &'a Value, path: &str) -> Result<Vec<&'a str>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{path} must be an array"))?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{path}[{index}] must be a non-empty string"))
        })
        .collect()
}

fn validate_source_boundaries(document: &Value) -> Result<(), String> {
    let Some(profiles) = document
        .get("activity_profiles_v2")
        .and_then(Value::as_array)
    else {
        return Ok(()); // The typed envelope reports the enclosing shape error.
    };
    for (profile_index, profile) in profiles.iter().enumerate() {
        let Some(profile) = profile.as_object() else {
            continue;
        };
        let Some(sources) = profile.get("sources").and_then(Value::as_array) else {
            continue;
        };
        let profile_path = format!("rules_v2.activity_profiles_v2[{profile_index}]");
        if sources.len() > MAX_RULE_SOURCES {
            return Err(format!(
                "{profile_path}.sources exceeds maximum count of {MAX_RULE_SOURCES}"
            ));
        }
        for (source_index, source) in sources.iter().enumerate() {
            let path = format!("{profile_path}.sources[{source_index}]");
            let source = source
                .as_object()
                .ok_or_else(|| format!("{path} must be an object"))?;
            let id = source
                .get("id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{path}.id must be a non-empty string"))?;
            if !id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            }) {
                return Err(format!("{path}.id contains unsupported characters"));
            }
            source
                .get("label")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{path}.label must be a non-empty string"))?;
            let bucket_ids = required_string_array(
                source.get("bucket_ids").unwrap_or(&Value::Null),
                &format!("{path}.bucket_ids"),
            )?;
            let fields = required_string_array(
                source.get("fields").unwrap_or(&Value::Null),
                &format!("{path}.fields"),
            )?;
            if fields.is_empty() {
                return Err(format!("{path}.fields must be a non-empty array"));
            }
            if bucket_ids.iter().collect::<BTreeSet<_>>().len() != bucket_ids.len() {
                return Err(format!("{path}.bucket_ids must be unique"));
            }
            if fields.iter().collect::<BTreeSet<_>>().len() != fields.len() {
                return Err(format!("{path}.fields must be unique"));
            }
            let builtin = match source.get("builtin") {
                None => None,
                Some(value) => Some(
                    value
                        .as_str()
                        .ok_or_else(|| format!("{path}.builtin is unsupported"))?,
                ),
            };
            let expected_id = match builtin {
                Some("window") => Some(BUILTIN_WINDOW_SOURCE_ID),
                Some("browser") => Some(BUILTIN_BROWSER_SOURCE_ID),
                Some("stopwatch") => Some(BUILTIN_STOPWATCH_SOURCE_ID),
                Some(_) => return Err(format!("{path}.builtin is unsupported")),
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
            if let Some(interval_policy) = source.get("interval_policy") {
                if !matches!(interval_policy.as_str(), Some("exact") | Some("heartbeat")) {
                    return Err(format!("{path}.interval_policy must be exact or heartbeat"));
                }
            }
            if let Some(field_types) = source.get("field_types") {
                let field_types = field_types
                    .as_object()
                    .ok_or_else(|| format!("{path}.field_types must be an object"))?;
                for (field, field_type) in field_types {
                    if !fields.contains(&field.as_str()) {
                        return Err(format!(
                            "{path}.field_types may only describe configured fields"
                        ));
                    }
                    if !matches!(field_type.as_str(), Some("string") | Some("scalar")) {
                        return Err(format!(
                            "{path}.field_types values must be string or scalar"
                        ));
                    }
                }
            }
            for flag in ["creates_activity", "keeps_active", "auto_generated"] {
                if source.get(flag).is_some_and(|value| !value.is_boolean()) {
                    return Err(format!("{path}.{flag} must be boolean"));
                }
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
            if let Some(host) = source.get("host") {
                if host.as_str().is_none_or(str::is_empty) {
                    return Err(format!("{path}.host must be a non-empty string"));
                }
            }
            let bucket_hosts = match source.get("bucket_hosts") {
                Some(value) => Some(
                    value
                        .as_object()
                        .ok_or_else(|| format!("{path}.bucket_hosts must be an object"))?,
                ),
                None => None,
            };
            if let Some(hosts) = bucket_hosts {
                if hosts
                    .values()
                    .any(|host| host.as_str().is_none_or(str::is_empty))
                {
                    return Err(format!(
                        "{path}.bucket_hosts values must be non-empty strings"
                    ));
                }
            }
            let scope = match source.get("scope") {
                None if source.contains_key("host") || bucket_hosts.is_some() => Some("host"),
                None => None,
                Some(value) => Some(
                    value
                        .as_str()
                        .filter(|scope| matches!(*scope, "host" | "global"))
                        .ok_or_else(|| format!("{path}.scope must be host or global"))?,
                ),
            };
            if scope == Some("global") && (source.contains_key("host") || bucket_hosts.is_some()) {
                return Err(format!("{path} global scope cannot define host ownership"));
            }
            if scope == Some("host") && source.contains_key("host") && bucket_hosts.is_some() {
                return Err(format!(
                    "{path} host scope must use either host or bucket_hosts"
                ));
            }
            // Empty builtin declarations are resolved against the selected host.
            if builtin.is_some() && bucket_ids.is_empty() {
                continue;
            }
            if let Some(hosts) = bucket_hosts {
                if hosts.len() != bucket_ids.len()
                    || bucket_ids
                        .iter()
                        .any(|bucket_id| !hosts.contains_key(*bucket_id))
                {
                    return Err(format!(
                        "{path}.bucket_hosts must map every and only configured bucket id"
                    ));
                }
            }
            if !matches!(scope, Some("host") | Some("global")) {
                return Err(format!("{path}.scope must be host or global"));
            }
            if scope == Some("host") && !source.contains_key("host") && bucket_hosts.is_none() {
                return Err(format!("{path} host scope requires host ownership"));
            }
        }
    }
    Ok(())
}

fn validate_document_boundary(envelope: &RulesEnvelope) -> Result<(), String> {
    if !(0..=MAX_SAFE_INTEGER).contains(&envelope.revision) {
        return Err("rules_v2.revision must be a non-negative safe integer".to_string());
    }
    if envelope.activity_profiles_v2.is_empty() || envelope.category_sets_v2.is_empty() {
        return Err("rules_v2 must contain at least one profile and category set".to_string());
    }
    let mut sets = BTreeMap::new();
    for (set_index, set) in envelope.category_sets_v2.iter().enumerate() {
        let path = format!("rules_v2.category_sets_v2[{set_index}]");
        if set.schema_version != RULES_SCHEMA_VERSION {
            return Err(format!(
                "{path}.schema_version must be {RULES_SCHEMA_VERSION}"
            ));
        }
        if set.id.is_empty() {
            return Err(format!("{path}.id must be a non-empty string"));
        }
        if let Some(priority) = set.priority {
            validate_ranking_integer(&json!(priority), &format!("{path}.priority"))?;
        }
        if set.categories.len() > MAX_CATEGORY_RULES {
            return Err(format!(
                "{path}.categories exceeds maximum count of {MAX_CATEGORY_RULES}"
            ));
        }
        if sets.insert(set.id.as_str(), set).is_some() {
            return Err(format!("{path}.id is duplicated"));
        }
        let mut ids = BTreeSet::new();
        let mut state = BoundaryExpressionState::default();
        for (category_index, category) in set.categories.iter().enumerate() {
            let category_path = format!("{path}.categories[{category_index}]");
            let category = category
                .as_object()
                .ok_or_else(|| format!("{category_path} must be an object"))?;
            let id = category
                .get("id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{category_path}.id must be a non-empty string"))?;
            if !ids.insert(id) {
                return Err(format!("{category_path}.id is duplicated"));
            }
            for field in ["priority", "set_priority"] {
                if let Some(value) = category.get(field) {
                    validate_ranking_integer(value, &format!("{category_path}.{field}"))?;
                }
            }
            let name = category
                .get("name")
                .and_then(Value::as_array)
                .filter(|name| {
                    !name.is_empty()
                        && name
                            .iter()
                            .all(|part| part.as_str().is_some_and(|part| !part.is_empty()))
                })
                .ok_or_else(|| format!("{category_path}.name must contain non-empty strings"))?;
            let _ = name;
            validate_expression_boundary(
                category.get("rule").unwrap_or(&Value::Null),
                &format!("{category_path}.rule"),
                1,
                &mut state,
            )?;
        }
    }

    let mut profile_ids = BTreeSet::new();
    for (profile_index, profile) in envelope.activity_profiles_v2.iter().enumerate() {
        let path = format!("rules_v2.activity_profiles_v2[{profile_index}]");
        if profile.schema_version != RULES_SCHEMA_VERSION {
            return Err(format!(
                "{path}.schema_version must be {RULES_SCHEMA_VERSION}"
            ));
        }
        if profile.id.is_empty() || !profile_ids.insert(profile.id.as_str()) {
            return Err(format!("{path}.id must be unique and non-empty"));
        }
        if profile.category_set_ids.is_empty() {
            return Err(format!("{path}.category_set_ids must be a non-empty array"));
        }
        let mut selected_ids = BTreeSet::new();
        let mut selected_count = 0;
        let mut aggregate_state = BoundaryExpressionState::default();
        for set_id in &profile.category_set_ids {
            if !selected_ids.insert(set_id) {
                return Err(format!("{path}.category_set_ids must be unique"));
            }
            let set = sets.get(set_id.as_str()).ok_or_else(|| {
                format!("{path}.category_set_ids references unknown set {set_id}")
            })?;
            selected_count += set.categories.len();
            if selected_count > MAX_CATEGORY_RULES {
                return Err(format!(
                    "{path}.category_set_ids select {selected_count} category rules; maximum is {MAX_CATEGORY_RULES}"
                ));
            }
            for (category_index, category) in set.categories.iter().enumerate() {
                validate_expression_boundary(
                    &category["rule"],
                    &format!("{path}.category_set_ids[{set_id}].categories[{category_index}].rule"),
                    1,
                    &mut aggregate_state,
                )?;
            }
        }
        if profile.sources.len() > MAX_RULE_SOURCES {
            return Err(format!(
                "{path}.sources exceeds maximum count of {MAX_RULE_SOURCES}"
            ));
        }
        let mut source_ids = BTreeSet::new();
        for (source_index, source) in profile.sources.iter().enumerate() {
            if source.id.is_empty() || !source_ids.insert(source.id.as_str()) {
                return Err(format!(
                    "{path}.sources[{source_index}].id must be unique and non-empty"
                ));
            }
            if source.label.is_empty() {
                return Err(format!(
                    "{path}.sources[{source_index}].label must be non-empty"
                ));
            }
            if source.fields.is_empty() {
                return Err(format!(
                    "{path}.sources[{source_index}].fields must be non-empty"
                ));
            }
        }
        if let Some(missing) = aggregate_state
            .sources
            .iter()
            .find(|source| !source_ids.contains(source.as_str()))
        {
            return Err(format!(
                "{path}.category_set_ids reference unknown source {missing}"
            ));
        }
        for (field, selector) in [
            ("app_title_source_id", profile.app_title_source_id.as_ref()),
            (
                "browser_focus_source_id",
                profile.browser_focus_source_id.as_ref(),
            ),
        ] {
            if selector.is_some_and(|selector| !source_ids.contains(selector.as_str())) {
                return Err(format!("{path}.{field} references an unknown source"));
            }
        }
        let active_time = profile
            .active_time
            .as_object()
            .ok_or_else(|| format!("{path}.active_time must be an object"))?;
        match active_time.get("type").and_then(Value::as_str) {
            Some("expression") => {
                let mut state = BoundaryExpressionState::default();
                validate_expression_boundary(
                    active_time.get("rule").unwrap_or(&Value::Null),
                    &format!("{path}.active_time.rule"),
                    1,
                    &mut state,
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
            Some("legacy") => {
                for field in ["use_afk", "include_audible"] {
                    if !active_time.get(field).is_some_and(Value::is_boolean) {
                        return Err(format!("{path}.active_time.{field} must be boolean"));
                    }
                }
                if !active_time
                    .get("always_active_pattern")
                    .is_some_and(Value::is_string)
                {
                    return Err(format!(
                        "{path}.active_time.always_active_pattern must be a string"
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "{path}.active_time.type must be legacy or expression"
                ))
            }
        }
    }
    Ok(())
}

pub fn compile_profile_v2(
    document: &Value,
    buckets: &HashMap<String, Bucket>,
    capabilities: Vec<String>,
    request: &ProfileQueryRequest,
) -> Result<MaterializedProfileV2, String> {
    if request.hostname.is_empty() {
        return Err("profile query requires a non-empty hostname".to_string());
    }
    for required in [
        crate::queries::OPTIONAL_BUCKET_RAW_CAPABILITY,
        crate::queries::QUERY_PERIOD_CAPABILITY,
        crate::queries::FLOOD_V2_CAPABILITY,
        crate::queries::CONTEXT_ENRICHMENT_CAPABILITY,
        crate::queries::ACTIVE_PERIODS_V2_CAPABILITY,
        crate::queries::CATEGORIZE_V2_CAPABILITY,
    ] {
        if !capabilities.iter().any(|item| item == required) {
            return Err(format!(
                "server cannot execute settings-aware profile; missing capability {required}"
            ));
        }
    }
    validate_source_boundaries(document)
        .map_err(|error| format!("invalid rules_v2 document: {error}"))?;
    let envelope: RulesEnvelope = serde_json::from_value(document.clone())
        .map_err(|error| format!("invalid rules_v2 document: {error}"))?;
    validate_document_boundary(&envelope)
        .map_err(|error| format!("invalid rules_v2 document: {error}"))?;
    let profile = envelope
        .activity_profiles_v2
        .iter()
        .find(|profile| {
            request
                .profile_id
                .as_ref()
                .map_or(true, |id| id == &profile.id)
        })
        .ok_or_else(|| format!("activity profile {:?} is unavailable", request.profile_id))?;
    let declared_by_id = profile
        .sources
        .iter()
        .map(|source| (source.id.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    let materialized = profile
        .sources
        .iter()
        .filter_map(|source| materialize_source(source, buckets, &request.hostname))
        .collect::<Vec<_>>();
    let by_id = materialized
        .iter()
        .map(|source| (source.id.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    if by_id.len() != materialized.len() {
        return Err("activity profile contains duplicate source ids".to_string());
    }

    let mut coverage = Vec::new();
    let mut context = Vec::new();
    for source in &materialized {
        if source.fields.is_empty() {
            return Err(format!("source {:?} fields must be non-empty", source.id));
        }
        if source.creates_activity {
            coverage.push(ActivityCoverageSource {
                source_id: source.id.clone(),
                bucket_ids: source.bucket_ids.clone(),
                fields: source.fields.clone(),
                keeps_active: source.keeps_active,
                scope: source.scope,
                bucket_hosts: source.bucket_hosts.clone(),
                host: source.host.clone(),
                interval_policy: policy(source),
            });
        } else {
            context.push(ContextSource {
                source_id: source.id.clone(),
                bucket_ids: source.bucket_ids.clone(),
                scope: source.scope,
                bucket_hosts: source.bucket_hosts.clone(),
                fields: source.fields.clone(),
                conflict: "base_wins".to_string(),
                host: source.host.clone(),
                interval_policy: policy(source),
            });
        }
    }

    let active_kind = profile
        .active_time
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "activity profile active_time.type is required".to_string())?;
    let mut generated_source_ids = profile
        .sources
        .iter()
        .map(|source| source.id.clone())
        .collect::<BTreeSet<_>>();
    let afk_source_id = (active_kind == "legacy"
        && profile
            .active_time
            .get("use_afk")
            .and_then(Value::as_bool)
            .unwrap_or(false))
    .then(|| allocate_generated_source_id(&mut generated_source_ids, AFK_SOURCE_ID));
    let mut active_rule = None;
    let mut active_sources = Vec::new();
    match active_kind {
        "expression" => {
            let rule = profile
                .active_time
                .get("rule")
                .cloned()
                .ok_or_else(|| "expression active_time requires a rule".to_string())?;
            let mut source_ids = BTreeSet::new();
            collect_source_ids(&rule, &mut source_ids);
            let has_keeps_active = coverage.iter().any(|source| source.keeps_active);
            for source_id in source_ids {
                if let Some(source) = by_id.get(source_id.as_str()) {
                    append_active_source(&mut active_sources, active_source(source))?;
                    continue;
                }
                let declared = declared_by_id.get(source_id.as_str()).ok_or_else(|| {
                    format!("active-time rule references unavailable source {source_id:?}")
                })?;
                if declared.builtin.is_none() || (request.filter_afk && !has_keeps_active) {
                    return Err(format!(
                        "active-time rule references unavailable source {source_id:?}"
                    ));
                }
                let mut empty = (*declared).clone();
                empty.bucket_ids.clear();
                empty.scope = Some(SourceScope::Global);
                empty.host = None;
                empty.bucket_hosts.clear();
                append_active_source(&mut active_sources, active_source(&empty))?;
            }
            active_rule = Some(rule);
        }
        "legacy" => {
            let mut branches = Vec::new();
            if profile
                .active_time
                .get("use_afk")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let mut afk_ids = buckets
                    .iter()
                    .filter(|(_, bucket)| {
                        bucket._type == "afkstatus" && bucket.hostname == request.hostname
                    })
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                afk_ids.sort();
                if !afk_ids.is_empty() {
                    let afk_source_id = afk_source_id
                        .as_ref()
                        .expect("AFK source id is allocated before browser sources");
                    append_active_source(
                        &mut active_sources,
                        ActiveTimeSource {
                            source_id: afk_source_id.clone(),
                            bucket_ids: afk_ids,
                            scope: Some(SourceScope::Host),
                            bucket_hosts: BTreeMap::new(),
                            host: Some(request.hostname.clone()),
                            interval_policy: IntervalPolicy::Heartbeat,
                        },
                    )?;
                    branches.push(json!({"type":"regex", "source":afk_source_id, "field":"status", "regex":"^not-afk$"}));
                }
            }
            let pattern = profile
                .active_time
                .get("always_active_pattern")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !pattern.is_empty() {
                if let Some(window) = by_id.get(BUILTIN_WINDOW_SOURCE_ID) {
                    append_active_source(&mut active_sources, active_source(window))?;
                    let rules = window
                        .fields
                        .iter()
                        .filter(|field| matches!(field.as_str(), "app" | "title"))
                        .map(|field| json!({"type":"regex", "source":window.id, "field":field, "regex":pattern}))
                        .collect::<Vec<_>>();
                    if !rules.is_empty() {
                        branches.push(if rules.len() == 1 {
                            rules[0].clone()
                        } else {
                            json!({"type":"any", "rules":rules})
                        });
                    }
                }
            }
            if profile
                .active_time
                .get("include_audible")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let browser = by_id.get(BUILTIN_BROWSER_SOURCE_ID).copied();
                let focus = match profile.browser_focus_source_id.as_deref() {
                    Some(id) => by_id.get(id).copied(),
                    None => materialized
                        .iter()
                        .find(|source| source.builtin.as_deref() == Some("window")),
                };
                if let (Some(browser), Some(focus)) = (browser, focus) {
                    if browser.fields.iter().any(|field| field == "audible")
                        && focus.fields.iter().any(|field| field == "app")
                    {
                        let mut audible_branches = Vec::new();
                        for (index, (_family, _exact_names, _app_pattern, family_bucket_ids)) in
                            crate::queries::current_browser_families(&browser.bucket_ids)
                                .into_iter()
                                .enumerate()
                        {
                            let source_id = allocate_generated_source_id(
                                &mut generated_source_ids,
                                &format!("browser_audible_{index}"),
                            );
                            let mut family_source = (*browser).clone();
                            family_source.id = source_id.clone();
                            family_source.bucket_ids = family_bucket_ids.clone();
                            if !family_source.bucket_hosts.is_empty() {
                                family_source.bucket_hosts = family_bucket_ids
                                    .iter()
                                    .map(|bucket_id| {
                                        family_source
                                            .bucket_hosts
                                            .get(bucket_id)
                                            .cloned()
                                            .map(|host| (bucket_id.clone(), host))
                                            .ok_or_else(|| {
                                                format!(
                                                    "browser source has no owner for bucket {bucket_id}"
                                                )
                                            })
                                    })
                                    .collect::<Result<_, _>>()?;
                            }
                            append_active_source(
                                &mut active_sources,
                                active_source(&family_source),
                            )?;
                            let focus_rule =
                                crate::queries::current_browser_focus_rule(&focus.id, _family);
                            audible_branches.push(json!({"type":"all", "rules":[
                                {"type":"regex", "source":source_id, "field":"audible", "regex":"^true$", "value_mode":"scalar"},
                                focus_rule
                            ]}));
                        }
                        if !audible_branches.is_empty() {
                            append_active_source(&mut active_sources, active_source(focus))?;
                            branches.push(if audible_branches.len() == 1 {
                                audible_branches.remove(0)
                            } else {
                                json!({"type":"any", "rules":audible_branches})
                            });
                        }
                    }
                }
            }
            if !branches.is_empty() {
                active_rule = Some(if branches.len() == 1 {
                    branches[0].clone()
                } else {
                    json!({"type":"any", "rules":branches})
                });
            }
        }
        other => return Err(format!("unsupported active_time type {other:?}")),
    }
    let mut category_specs = flatten_category_sets(profile, &envelope.category_sets_v2)?;
    for category in &mut category_specs {
        if let Some(rule) = category.get("rule").cloned() {
            category.as_object_mut().unwrap().insert(
                "rule".to_string(),
                qualify_legacy_expression(&rule, BUILTIN_WINDOW_SOURCE_ID),
            );
        }
    }
    let active_rule = active_rule
        .as_ref()
        .map(crate::queries::semantic_rule_expression)
        .transpose()?;
    let category_specs = crate::queries::semantic_category_specs(&category_specs)?;
    Ok(MaterializedProfileV2 {
        profile_id: profile.id.clone(),
        app_title_source_id: profile.app_title_source_id.clone(),
        browser_focus_source_id: profile.browser_focus_source_id.clone(),
        options: CanonicalQueryV2Options {
            hostname: Some(request.hostname.clone()),
            category_specs: Some(category_specs),
            activity_coverage_sources: coverage,
            context_sources: context,
            active_time_rule: active_rule,
            active_time_sources: active_sources,
            capabilities,
            filter_afk: request.filter_afk,
            filter_categories: request.filter_categories.clone(),
            explain_categories: request.explain_categories,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flattening_is_stable_and_rewrites_prerequisites() {
        let document = json!({
            "revision": 7,
            "activity_profiles_v2": [{"schema_version":2, "id":"p", "category_set_ids":["primary", "secondary"], "sources":[], "active_time":{"type":"expression", "rule":{"type":"none"}}}],
            "category_sets_v2": [
                {"schema_version":2, "id":"primary", "categories":[{"id":"child", "name":["Child"], "requires":["parent"], "rule":{"type":"none"}}, {"id":"parent", "name":["Parent"], "rule":{"type":"none"}}]},
                {"schema_version":2, "id":"secondary", "categories":[{"id":"parent", "name":["Other"], "rule":{"type":"none"}}]}
            ]
        });
        let envelope: RulesEnvelope = serde_json::from_value(document).unwrap();
        let flat = flatten_category_sets(
            &envelope.activity_profiles_v2[0],
            &envelope.category_sets_v2,
        )
        .unwrap();
        assert_eq!(flat[0]["id"], "set:7:primary:rule:child");
        assert_eq!(flat[0]["requires"][0], "set:7:primary:rule:parent");
        assert_eq!(flat[0]["set_priority"], 2);
        assert_eq!(flat[2]["id"], "set:9:secondary:rule:parent");
    }

    #[test]
    fn pre_atomic_v2_arrays_win_over_lossy_classes() {
        let migrated = migrate_legacy_settings(&json!({
            "activity_profiles_v2": [{"id":"advanced"}],
            "category_sets_v2": [{"id":"advanced-set"}],
            "classes": [{"id":"lossy", "name":["Wrong"], "rule":{"type":"none"}}]
        }));
        assert_eq!(migrated["activity_profiles_v2"][0]["id"], "advanced");
        assert_eq!(migrated["category_sets_v2"][0]["id"], "advanced-set");
        assert_eq!(migrated["revision"], 0);
    }

    fn capabilities() -> Vec<String> {
        vec![
            crate::queries::OPTIONAL_BUCKET_RAW_CAPABILITY.into(),
            crate::queries::QUERY_PERIOD_CAPABILITY.into(),
            crate::queries::FLOOD_V2_CAPABILITY.into(),
            crate::queries::CONTEXT_ENRICHMENT_CAPABILITY.into(),
            crate::queries::ACTIVE_PERIODS_V2_CAPABILITY.into(),
            crate::queries::CATEGORIZE_V2_CAPABILITY.into(),
        ]
    }

    #[test]
    fn meeting_only_profile_does_not_inject_window() {
        let document = json!({
            "revision":1,
            "activity_profiles_v2":[{"schema_version":2, "id":"meeting", "category_set_ids":["empty"], "sources":[{"id":"meeting", "label":"Meeting", "bucket_ids":["meet"], "scope":"global", "fields":["subject"], "creates_activity":true, "keeps_active":true}], "active_time":{"type":"expression", "rule":{"type":"none"}}}],
            "category_sets_v2":[{"schema_version":2, "id":"empty", "categories":[]}]
        });
        let materialized = compile_profile_v2(
            &document,
            &HashMap::new(),
            capabilities(),
            &ProfileQueryRequest::for_hostname("host"),
        )
        .unwrap();
        let query = materialized.query().unwrap();
        assert!(query.contains("query_bucket_optional_raw(\"meet\")"));
        assert!(!query.contains("aw-watcher-window"));
        assert!(!query.contains("flood_v2(coverage_source_0_raw)"));
    }

    fn source_document(count: usize) -> Value {
        let sources = (0..count)
            .map(|index| {
                json!({
                    "id": format!("source_{index}"),
                    "label": format!("Source {index}"),
                    "bucket_ids": [format!("bucket-{index}")],
                    "scope": "global",
                    "fields": ["value"]
                })
            })
            .collect::<Vec<_>>();
        json!({
            "revision": 0,
            "activity_profiles_v2": [{
                "schema_version": 2,
                "id": "profile",
                "category_set_ids": ["empty"],
                "sources": sources,
                "active_time": {"type":"expression", "rule":{"type":"none"}}
            }],
            "category_sets_v2": [{"schema_version":2, "id":"empty", "categories":[]}]
        })
    }

    #[test]
    fn builtin_discovery_order_is_deterministic() {
        let bucket = |id: &str| {
            serde_json::from_value::<Bucket>(json!({
                "id": id,
                "type": "web.tab.current",
                "client": "test",
                "hostname": "host",
                "created": null,
                "events": null,
                "last_updated": null
            }))
            .unwrap()
        };
        let buckets = [
            ("aw-watcher-web-chrome-z".to_string(), bucket("z")),
            ("aw-watcher-web-chrome-a".to_string(), bucket("a")),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();
        assert_eq!(
            discover_builtin("browser", &buckets, "host").0,
            vec![
                "aw-watcher-web-chrome-a".to_string(),
                "aw-watcher-web-chrome-z".to_string()
            ]
        );
    }

    #[test]
    fn source_boundary_rejects_complete_known_schema_and_accepts_limits() {
        for (case, expected) in [
            (
                "creates_activity_string",
                "creates_activity must be boolean",
            ),
            ("keeps_active_string", "keeps_active must be boolean"),
            ("missing_bucket_ids", "bucket_ids must be an array"),
            ("missing_fields", "fields must be an array"),
            ("invalid_builtin", "builtin is unsupported"),
            ("invalid_builtin_id", "builtin is unsupported"),
            ("invalid_scope", "scope must be host or global"),
            (
                "invalid_policy",
                "interval_policy must be exact or heartbeat",
            ),
            (
                "invalid_field_types",
                "field_types values must be string or scalar",
            ),
            ("global_host", "global scope cannot define host ownership"),
            ("host_without_owner", "host scope requires host ownership"),
        ] {
            let mut document = source_document(1);
            let source = document["activity_profiles_v2"][0]["sources"][0]
                .as_object_mut()
                .unwrap();
            match case {
                "creates_activity_string" => {
                    source.insert("creates_activity".into(), json!("false"));
                }
                "keeps_active_string" => {
                    source.insert("keeps_active".into(), json!("true"));
                }
                "missing_bucket_ids" => {
                    source.remove("bucket_ids");
                }
                "missing_fields" => {
                    source.remove("fields");
                }
                "invalid_builtin" => {
                    source.insert("builtin".into(), json!("bogus"));
                }
                "invalid_builtin_id" => {
                    source.insert("builtin".into(), json!("window"));
                }
                "invalid_scope" => {
                    source.insert("scope".into(), json!("machine"));
                }
                "invalid_policy" => {
                    source.insert("interval_policy".into(), json!("approximate"));
                }
                "invalid_field_types" => {
                    source.insert("field_types".into(), json!({"value":"number"}));
                }
                "global_host" => {
                    source.insert("host".into(), json!("host"));
                }
                "host_without_owner" => {
                    source.insert("scope".into(), json!("host"));
                }
                _ => unreachable!(),
            }
            let error = compile_profile_v2(
                &document,
                &HashMap::new(),
                capabilities(),
                &ProfileQueryRequest::for_hostname("host"),
            )
            .unwrap_err();
            assert!(error.contains(expected), "{case}: {error}");
        }

        compile_profile_v2(
            &source_document(128),
            &HashMap::new(),
            capabilities(),
            &ProfileQueryRequest::for_hostname("host"),
        )
        .unwrap();
        let error = compile_profile_v2(
            &source_document(129),
            &HashMap::new(),
            capabilities(),
            &ProfileQueryRequest::for_hostname("host"),
        )
        .unwrap_err();
        assert!(
            error.contains("sources exceeds maximum count of 128"),
            "{error}"
        );
    }

    #[test]
    fn empty_builtin_validates_present_fields_and_regex_ignores_irrelevant_metadata() {
        for (field, value, expected) in [
            ("scope", json!("bogus"), "scope must be host or global"),
            ("scope", Value::Null, "scope must be host or global"),
            ("bucket_hosts", json!(42), "bucket_hosts must be an object"),
        ] {
            let mut document = source_document(1);
            document["activity_profiles_v2"][0]["sources"][0] = json!({
                "id":"builtin_window", "label":"Window", "bucket_ids":[],
                "builtin":"window", "fields":["app", "title"]
            });
            document["activity_profiles_v2"][0]["sources"][0][field] = value;
            let error = compile_profile_v2(
                &document,
                &HashMap::new(),
                capabilities(),
                &ProfileQueryRequest::for_hostname("host"),
            )
            .unwrap_err();
            assert!(error.contains(expected), "{error}");
        }

        let mut discovered = source_document(1);
        discovered["activity_profiles_v2"][0]["sources"][0] = json!({
            "id":"builtin_window", "label":"Window", "bucket_ids":[],
            "builtin":"window", "fields":["app", "title"], "creates_activity":true,
            "bucket_hosts":{"future-window":"host"}
        });
        let window = serde_json::from_value::<Bucket>(json!({
            "id":"window", "type":"currentwindow", "client":"test", "hostname":"host",
            "created":null, "events":null, "last_updated":null
        }))
        .unwrap();
        let request = ProfileQueryRequest {
            filter_afk: false,
            ..ProfileQueryRequest::for_hostname("host")
        };
        let materialized = compile_profile_v2(
            &discovered,
            &[("window".to_string(), window)].into_iter().collect(),
            capabilities(),
            &request,
        )
        .unwrap();
        assert_eq!(
            materialized.options.activity_coverage_sources[0].bucket_ids,
            ["window"]
        );
        assert!(materialized.options.activity_coverage_sources[0]
            .bucket_hosts
            .is_empty());

        let mut document = source_document(1);
        document["category_sets_v2"][0]["categories"] = json!([{
            "id":"metadata", "name":["Metadata"],
            "rule":{"type":"regex", "source":"source_0", "regex":"x", "rules":42}
        }]);
        compile_profile_v2(
            &document,
            &HashMap::new(),
            capabilities(),
            &ProfileQueryRequest::for_hostname("host"),
        )
        .unwrap();
    }

    #[test]
    fn rejects_invalid_regex_before_query_execution() {
        let mut document = source_document(1);
        document["category_sets_v2"][0]["categories"] = json!([{
            "id":"broken", "name":["Broken"],
            "rule":{"type":"regex", "source":"source_0", "regex":"(unclosed"}
        }]);
        let error = compile_profile_v2(
            &document,
            &HashMap::new(),
            capabilities(),
            &ProfileQueryRequest::for_hostname("host"),
        )
        .unwrap_err();
        assert!(error.contains("regex is invalid"), "{error}");
    }

    #[test]
    fn rejects_forward_schema_and_aggregate_selected_set_budget() {
        let forward = json!({
            "revision": 1,
            "activity_profiles_v2": [{"schema_version":99, "id":"p", "category_set_ids":["empty"], "sources":[], "active_time":{"type":"expression", "rule":{"type":"none"}}}],
            "category_sets_v2": [{"schema_version":2, "id":"empty", "categories":[]}]
        });
        let error = compile_profile_v2(
            &forward,
            &HashMap::new(),
            capabilities(),
            &ProfileQueryRequest::for_hostname("host"),
        )
        .unwrap_err();
        assert!(error.contains("schema_version must be 2"), "{error}");

        let forward_set = json!({
            "revision": 1,
            "activity_profiles_v2": [{"schema_version":2, "id":"p", "category_set_ids":["empty"], "sources":[], "active_time":{"type":"expression", "rule":{"type":"none"}}}],
            "category_sets_v2": [{"schema_version":99, "id":"empty", "categories":[]}]
        });
        let error = compile_profile_v2(
            &forward_set,
            &HashMap::new(),
            capabilities(),
            &ProfileQueryRequest::for_hostname("host"),
        )
        .unwrap_err();
        assert!(error.contains("schema_version must be 2"), "{error}");

        let categories = |prefix: &str| {
            (0..501)
                .map(|index| {
                    json!({"id":format!("{prefix}-{index}"), "name":[prefix, index.to_string()], "rule":{"type":"none"}})
                })
                .collect::<Vec<_>>()
        };
        let aggregate = json!({
            "revision": 0,
            "activity_profiles_v2": [{"schema_version":2, "id":"p", "category_set_ids":["one", "two"], "sources":[], "active_time":{"type":"expression", "rule":{"type":"none"}}}],
            "category_sets_v2": [
                {"schema_version":2, "id":"one", "categories":categories("one")},
                {"schema_version":2, "id":"two", "categories":categories("two")}
            ]
        });
        let error = compile_profile_v2(
            &aggregate,
            &HashMap::new(),
            capabilities(),
            &ProfileQueryRequest::for_hostname("host"),
        )
        .unwrap_err();
        assert!(error.contains("select 1002 category rules"), "{error}");
    }

    #[test]
    fn migration_uses_defaults_but_preserves_explicit_empty_classes() {
        let defaults = migrate_legacy_settings(&json!({}));
        let names = defaults["category_sets_v2"][0]["categories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|category| category["name"].clone())
            .collect::<Vec<_>>();
        assert!(names.contains(&json!(["Work", "Programming"])));
        assert!(names.contains(&json!(["Media"])));
        assert!(names.contains(&json!(["Comms"])));
        assert!(names.contains(&json!(["Uncategorized"])));
        assert_eq!(
            defaults["category_sets_v2"][0]["categories"][0]["data"]["score"],
            10
        );

        let empty = migrate_legacy_settings(&json!({"classes": []}));
        assert!(empty["category_sets_v2"][0]["categories"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn migration_preserves_legacy_sets_selection_and_normalizes_null_rules() {
        let migrated = migrate_legacy_settings(&json!({
            "classes": [{"name":["Stale"], "rule":{"type":"regex", "regex":"x"}}],
            "category_sets": [
                {"id":"work", "categories":[{"name":["Work"], "rule":{"type":null}, "data":{"color":"green"}}]},
                {"id":"personal", "categories":[{"name":["Personal"], "rule":{"type":"regex", "regex":"game"}}]}
            ],
            "active_set_ids": ["personal"]
        }));
        assert_eq!(
            migrated["activity_profiles_v2"][0]["category_set_ids"],
            json!(["personal"])
        );
        assert_eq!(migrated["category_sets_v2"][0]["id"], "work");
        assert_eq!(migrated["category_sets_v2"][1]["id"], "personal");
        assert_eq!(
            migrated["category_sets_v2"][0]["categories"][0]["rule"],
            json!({"type":"none"})
        );
        assert_eq!(
            migrated["category_sets_v2"][0]["categories"][0]["data"]["color"],
            "green"
        );
    }

    #[test]
    fn migration_preserves_multiple_selected_sets_and_disables_stale_null_rules() {
        let migrated = migrate_legacy_settings(&json!({
            "category_sets": [
                {"id":"one", "categories":[{"name":["Shared"], "rule":{"type":"regex", "regex":"^emacs$"}}]},
                {"id":"two", "categories":[{"name":["Shared"], "rule":{"type":"regex", "regex":"vim"}}]}
            ],
            "active_set_ids": ["one", "two", "one", "missing"]
        }));
        assert_eq!(
            migrated["activity_profiles_v2"][0]["category_set_ids"],
            json!(["one", "two"])
        );
        assert_eq!(migrated["category_sets_v2"][0]["id"], "one");
        assert_eq!(migrated["category_sets_v2"][1]["id"], "two");

        let disabled = migrate_legacy_settings(&json!({
            "classes": [{"name":["Disabled"], "rule":{"type":null, "regex":"vim"}}]
        }));
        assert_eq!(
            disabled["category_sets_v2"][0]["categories"][0]["rule"],
            json!({"type":"none"})
        );
    }

    #[test]
    fn ranking_integers_and_revision_use_the_shared_domain() {
        for invalid in [json!(true), json!(1.5), json!(-1_000_001), json!(1_000_001)] {
            let mut document = source_document(1);
            document["category_sets_v2"][0]["categories"] = json!([{
                "id":"ranked", "name":["Ranked"],
                "rule":{"type":"regex", "source":"source_0", "regex":"x", "weight":invalid}
            }]);
            let error = compile_profile_v2(
                &document,
                &HashMap::new(),
                capabilities(),
                &ProfileQueryRequest::for_hostname("host"),
            )
            .unwrap_err();
            assert!(error.contains("must be an integer between"), "{error}");
        }
        let mut document = source_document(1);
        document["revision"] = json!(9_007_199_254_740_992_i64);
        let error = compile_profile_v2(
            &document,
            &HashMap::new(),
            capabilities(),
            &ProfileQueryRequest::for_hostname("host"),
        )
        .unwrap_err();
        assert!(error.contains("safe integer"), "{error}");
    }

    #[test]
    fn generated_active_ids_avoid_declared_sources_and_afk_is_sorted() {
        let document = json!({
            "revision":1,
            "activity_profiles_v2":[{
                "schema_version":2, "id":"default", "category_set_ids":["empty"],
                "sources":[
                    {"id":"builtin_window", "label":"Window", "bucket_ids":[], "builtin":"window", "fields":["app","title"], "creates_activity":true, "interval_policy":"heartbeat"},
                    {"id":"browser", "label":"Browser", "bucket_ids":[], "builtin":"browser", "fields":["audible"], "interval_policy":"heartbeat"},
                    {"id":"afk", "label":"Reserved AFK", "bucket_ids":["reserved-afk"], "scope":"global", "fields":["value"]},
                    {"id":"browser_audible_0", "label":"Focus", "bucket_ids":["focus"], "scope":"global", "fields":["app"], "creates_activity":true}
                ],
                "browser_focus_source_id":"browser_audible_0",
                "active_time":{"type":"legacy", "use_afk":true, "include_audible":true, "always_active_pattern":""}
            }],
            "category_sets_v2":[{"schema_version":2, "id":"empty", "categories":[]}]
        });
        let bucket = |id: &str, event_type: &str| {
            serde_json::from_value::<Bucket>(json!({
                "id":id, "type":event_type, "client":"test", "hostname":"host",
                "created":null, "events":null, "last_updated":null
            }))
            .unwrap()
        };
        let buckets = [
            ("window".to_string(), bucket("window", "currentwindow")),
            (
                "aw-watcher-web-chrome".to_string(),
                bucket("aw-watcher-web-chrome", "web.tab.current"),
            ),
            ("afk-z".to_string(), bucket("afk-z", "afkstatus")),
            ("afk-a".to_string(), bucket("afk-a", "afkstatus")),
            ("reserved-afk".to_string(), bucket("reserved-afk", "custom")),
            ("focus".to_string(), bucket("focus", "custom")),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();
        let materialized = compile_profile_v2(
            &document,
            &buckets,
            capabilities(),
            &ProfileQueryRequest::for_hostname("host"),
        )
        .unwrap();
        let sources = materialized
            .options
            .active_time_sources
            .iter()
            .map(|source| (source.source_id.as_str(), source))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(sources["afk_2"].bucket_ids, ["afk-a", "afk-z"]);
        assert_eq!(
            sources["browser_audible_0_2"].bucket_ids,
            ["aw-watcher-web-chrome"]
        );
        assert_eq!(sources["browser_audible_0"].bucket_ids, ["focus"]);
        assert_eq!(
            sources.len(),
            materialized.options.active_time_sources.len()
        );
        let query = materialized.query().unwrap();
        assert!(query.contains("\"source\":\"afk_2\""));
        assert!(query.contains("\"source\":\"browser_audible_0_2\""));
    }

    #[test]
    fn execution_specs_drop_irrelevant_metadata() {
        let mut document = source_document(1);
        document["activity_profiles_v2"][0]["active_time"] = json!({
            "type":"expression",
            "rule":{"type":"regex", "source":"source_0", "regex":"x", "rules":"\\", "presentation":{"label":"\\"}}
        });
        document["category_sets_v2"][0]["categories"] = json!([{
            "id":"metadata", "name":["Metadata"], "data":{"label":"\\"}, "simple_ui":true,
            "rule":{"type":"regex", "source":"source_0", "regex":"x", "rules":"\\"}
        }]);
        let mut request = ProfileQueryRequest::for_hostname("host");
        request.filter_afk = false;
        let materialized =
            compile_profile_v2(&document, &HashMap::new(), capabilities(), &request).unwrap();
        let query = materialized.query().unwrap();
        assert!(query.contains("\"regex\":\"x\""));
        assert!(!query.contains("presentation"));
        assert!(!query.contains("simple_ui"));
        assert!(!query.contains("\"rules\":\""));
        assert!(!query.contains("\"data\""));
    }

    #[test]
    fn unavailable_declared_active_builtin_is_empty_only_when_safe() {
        let mut document = source_document(1);
        document["activity_profiles_v2"][0]["sources"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"browser", "label":"Browser", "bucket_ids":[], "builtin":"browser",
                "fields":["audible"], "interval_policy":"heartbeat"
            }));
        document["activity_profiles_v2"][0]["active_time"] = json!({
            "type":"expression",
            "rule":{"type":"regex", "source":"browser", "field":"audible", "regex":"^true$", "value_mode":"scalar"}
        });
        let mut request = ProfileQueryRequest::for_hostname("host");
        request.filter_afk = false;
        let unfiltered =
            compile_profile_v2(&document, &HashMap::new(), capabilities(), &request).unwrap();
        assert!(unfiltered.options.active_time_sources[0]
            .bucket_ids
            .is_empty());
        assert!(unfiltered
            .query()
            .unwrap()
            .contains("active_source_0_raw = []"));

        request.filter_afk = true;
        let error =
            compile_profile_v2(&document, &HashMap::new(), capabilities(), &request).unwrap_err();
        assert!(error.contains("unavailable source \"browser\""), "{error}");

        document["activity_profiles_v2"][0]["sources"][0]["creates_activity"] = json!(true);
        document["activity_profiles_v2"][0]["sources"][0]["keeps_active"] = json!(true);
        compile_profile_v2(&document, &HashMap::new(), capabilities(), &request).unwrap();
    }
}
