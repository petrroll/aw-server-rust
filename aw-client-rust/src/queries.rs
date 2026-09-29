//! Query building utilities for ActivityWatch
//!
//! This module builds canonical Query2 programs. Desktop compatibility signatures
//! translate into the current source pipeline; explicitly selected old-server and
//! Android grammar lives in [`legacy_v1`]. Settings-aware callers should use
//! [`crate::AwClient::build_profile_query_v2`].
//!
//! ## Desktop compatibility
//!
//! ```rust
//! use aw_client_rust::queries::{DesktopQueryParams, QueryParams, QueryParamsBase};
//!
//! let params = DesktopQueryParams {
//!     base: QueryParamsBase {
//!         bid_browsers: vec![],
//!         classes: vec![], // Empty selects the shared built-in defaults.
//!         filter_classes: vec![],
//!         filter_afk: true,
//!         include_audible: true,
//!     },
//!     bid_window: "aw-watcher-window_example".to_string(),
//!     bid_afk: "aw-watcher-afk_example".to_string(),
//!     always_active_pattern: None,
//! };
//!
//! let query = QueryParams::Desktop(params.clone()).canonical_events();
//!
//! ```

use crate::classes::{CategoryId, CategorySpec};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Browser application names mapped by browser type
pub static BROWSER_APPNAMES: phf::Map<&'static str, &'static [&'static str]> = phf::phf_map! {
    "chrome" => &[
        // Chrome
        "Google Chrome",
        "Google-chrome",
        "chrome.exe",
        "google-chrome-stable",
        // Chromium
        "Chromium",
        "Chromium-browser",
        "Chromium-browser-chromium",
        "chromium.exe",
        // Pre-releases
        "Google-chrome-beta",
        "Google-chrome-unstable",
        // Brave (should this be merged with the brave entry?)
        "Brave-browser",
    ],
    "firefox" => &[
        "Firefox",
        "Firefox.exe",
        "firefox",
        "firefox.exe",
        "Firefox Developer Edition",
        "firefoxdeveloperedition",
        "Firefox-esr",
        "Firefox Beta",
        "Nightly",
        "org.mozilla.firefox",
    ],
    "opera" => &["opera.exe", "Opera"],
    "brave" => &["brave.exe"],
    "edge" => &[
        "msedge.exe",  // Windows
        "Microsoft Edge",  // macOS
    ],
    "vivaldi" => &["Vivaldi-stable", "Vivaldi-snapshot", "vivaldi.exe"],
};

pub(crate) const CURRENT_BROWSER_FAMILIES: &[(&str, &[&str], &str)] = &[
    (
        "chrome",
        &[
            "com.google.Chrome",
            "com.google.ChromeDev",
            "org.chromium.Chromium",
        ],
        "(?i)^(google[-_ ]?chrome|chrome|chromium)",
    ),
    (
        "firefox",
        &[
            "org.mozilla.firefox",
            "io.gitlab.librewolf-community",
            "net.waterfox.waterfox",
        ],
        "(?i)(firefox|librewolf|waterfox|nightly)",
    ),
    ("opera", &["com.opera.Opera"], "(?i)(opera)"),
    ("brave", &["com.brave.Browser"], "(?i)(brave)"),
    (
        "edge",
        &["com.microsoft.Edge", "com.microsoft.EdgeDev"],
        "(?i)^(microsoft[-_ ]?edge|msedge)",
    ),
    ("arc", &[], "(?i)^arc(\\.exe)?$"),
    ("vivaldi", &["com.vivaldi.Vivaldi"], "(?i)(vivaldi)"),
    ("orion", &["Orion"], "(?i)(orion)"),
    ("yandex", &["ru.yandex.Browser"], "(?i)(yandex)"),
    ("zen", &["app.zen_browser.zen"], "(?i)(zen)"),
    ("floorp", &["one.ablaze.floorp"], "(?i)(floorp)"),
    ("helium", &["net.imput.helium"], "(?i)(helium)"),
];

pub const DEFAULT_LIMIT: u32 = 100;
pub const CATEGORIZE_V2_CAPABILITY: &str = "query.categorize_v2.v1";
pub const CONTEXT_ENRICHMENT_CAPABILITY: &str = "query.merge_subwatcher_fields.source_namespace.v1";
pub const ACTIVE_PERIODS_V2_CAPABILITY: &str = "query.active_periods_v2.v1";
pub const MAP_EVENT_FIELDS_CAPABILITY: &str = "query.map_event_fields.v1";
pub const OPTIONAL_BUCKET_HOSTNAME_CAPABILITY: &str =
    "query.query_bucket_optional.expected_hostname.v1";
pub const OPTIONAL_BUCKET_RAW_CAPABILITY: &str = "query.query_bucket_optional_raw.v1";
pub const QUERY_PERIOD_CAPABILITY: &str = "query.query_period.v1";
pub const FLOOD_V2_CAPABILITY: &str = "query.flood_v2.v1";
pub const EXPLAIN_CATEGORIZE_V2_CAPABILITY: &str = "query.categorize_v2_explain.v1";

/// Type alias for categorization classes
pub type ClassRule = (CategoryId, CategorySpec);

/// Ownership scope for a configured bucket source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceScope {
    Host,
    Global,
}

/// How source heartbeat gaps contribute to facts and coverage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IntervalPolicy {
    #[default]
    Exact,
    Heartbeat,
}

/// Additional event fields to merge from one or more context buckets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSource {
    pub source_id: String,
    pub bucket_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<SourceScope>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bucket_hosts: BTreeMap<String, String>,
    pub fields: Vec<String>,
    #[serde(default = "default_context_conflict")]
    pub conflict: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub interval_policy: IntervalPolicy,
}

fn default_context_conflict() -> String {
    "base_wins".to_string()
}

/// A named source used to compile active time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveTimeSource {
    pub source_id: String,
    pub bucket_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<SourceScope>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bucket_hosts: BTreeMap<String, String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub interval_policy: IntervalPolicy,
}

/// A replacement activity stream with optional canonical field mappings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivitySource {
    pub source_id: String,
    pub bucket_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<SourceScope>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bucket_hosts: BTreeMap<String, String>,
    #[serde(default)]
    pub field_mappings: BTreeMap<String, String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub interval_policy: IntervalPolicy,
}

/// A source whose event periods contribute to abstract activity coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityCoverageSource {
    pub source_id: String,
    pub bucket_ids: Vec<String>,
    pub fields: Vec<String>,
    #[serde(default)]
    pub keeps_active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<SourceScope>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bucket_hosts: BTreeMap<String, String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub interval_policy: IntervalPolicy,
}

/// Source-only options for the canonical v2 pipeline.
///
/// Coverage sources are the only sources that create canonical event periods. Context sources
/// only add namespaced facts to those periods, and active-time sources only restrict them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalQueryV2Options {
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub category_specs: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub activity_coverage_sources: Vec<ActivityCoverageSource>,
    #[serde(default)]
    pub context_sources: Vec<ContextSource>,
    #[serde(default)]
    pub active_time_rule: Option<serde_json::Value>,
    #[serde(default)]
    pub active_time_sources: Vec<ActiveTimeSource>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default = "default_true")]
    pub filter_afk: bool,
    #[serde(default)]
    pub filter_categories: Option<Vec<Vec<String>>>,
    #[serde(default)]
    pub explain_categories: bool,
}

impl Default for CanonicalQueryV2Options {
    fn default() -> Self {
        Self {
            hostname: None,
            category_specs: None,
            activity_coverage_sources: Vec::new(),
            context_sources: Vec::new(),
            active_time_rule: None,
            active_time_sources: Vec::new(),
            capabilities: Vec::new(),
            filter_afk: true,
            filter_categories: None,
            explain_categories: false,
        }
    }
}

/// Legacy compatibility options for mixing advanced sources into desktop/Android queries.
///
/// New source-only canonical queries should use [`CanonicalQueryV2Options`] and
/// [`try_build_canonical_events_v2`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdvancedQueryOptions {
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub category_specs: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub context_sources: Vec<ContextSource>,
    #[serde(default)]
    pub active_time_rule: Option<serde_json::Value>,
    #[serde(default)]
    pub active_time_sources: Vec<ActiveTimeSource>,
    #[serde(default)]
    pub activity_coverage_sources: Vec<ActivityCoverageSource>,
    #[serde(default)]
    pub activity_sources: Vec<ActivitySource>,
    #[serde(default)]
    pub background_sources: Vec<ActivitySource>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub legacy_window_mode: LegacyWindowMode,
    #[serde(default = "default_legacy_window_fields")]
    pub legacy_window_fields: Vec<String>,
}

fn default_legacy_window_fields() -> Vec<String> {
    vec!["app".to_string(), "title".to_string()]
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyWindowMode {
    #[default]
    Activity,
    Context,
    None,
}

/// Base query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParamsBase {
    #[serde(default)]
    pub bid_browsers: Vec<String>,
    #[serde(default)]
    pub classes: Vec<ClassRule>,
    #[serde(default)]
    pub filter_classes: Vec<Vec<String>>,
    #[serde(default = "default_true")]
    pub filter_afk: bool,
    #[serde(default = "default_true")]
    pub include_audible: bool,
}

fn default_true() -> bool {
    true
}

/// Query parameters specific to desktop
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopQueryParams {
    #[serde(flatten)]
    pub base: QueryParamsBase,
    pub bid_window: String,
    pub bid_afk: String,
    #[serde(default)]
    pub always_active_pattern: Option<String>,
}

/// Query parameters specific to Android
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidQueryParams {
    #[serde(flatten)]
    pub base: QueryParamsBase,
    pub bid_android: String,
}

/// Enum to represent different types of query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QueryParams {
    Desktop(DesktopQueryParams),
    Android(AndroidQueryParams),
}

impl QueryParams {
    /// Build canonical events through the current desktop pipeline.
    ///
    /// Android is an explicit legacy platform target and retains its frozen grammar.
    pub fn canonical_events(&self) -> String {
        match self {
            QueryParams::Desktop(params) => build_desktop_canonical_events(params),
            QueryParams::Android(params) => legacy_v1::android(params)
                .expect("Android query parameters must be representable in Query2"),
        }
    }

    /// Build canonical events with validated legacy compatibility options.
    #[deprecated(
        note = "this API mixes legacy platform parameters with advanced sources; use try_build_canonical_events_v2"
    )]
    #[allow(deprecated)]
    pub fn try_canonical_events_with_options(
        &self,
        options: &AdvancedQueryOptions,
    ) -> Result<String, String> {
        match self {
            QueryParams::Desktop(params) => {
                try_build_desktop_canonical_events_with_options(params, options)
            }
            QueryParams::Android(_) => Err(
                "Android grammar is legacy-v1 only; use queries::legacy_v1 explicitly".to_string(),
            ),
        }
    }
}

/// Serialize legacy classes using Query2's raw-backslash string grammar.
fn serialize_classes(classes: &[ClassRule]) -> String {
    serialize_query_json(classes)
}

fn escape_regex_literal(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if ".*+?^$()[]{}|\\".contains(character) {
            output.push('\\');
        }
        output.push(character);
    }
    output
}

pub(crate) fn current_browser_families(
    bucket_ids: &[String],
) -> Vec<(
    &'static str,
    &'static [&'static str],
    &'static str,
    Vec<String>,
)> {
    CURRENT_BROWSER_FAMILIES
        .iter()
        .filter_map(|(family, names, pattern)| {
            let family_buckets = bucket_ids
                .iter()
                .filter(|bucket_id| bucket_id.contains(family))
                .cloned()
                .collect::<Vec<_>>();
            (!family_buckets.is_empty()).then_some((*family, *names, *pattern, family_buckets))
        })
        .collect()
}

pub(crate) fn current_browser_focus_rule(source_id: &str, family: &str) -> serde_json::Value {
    let (_, exact_names, app_pattern) = CURRENT_BROWSER_FAMILIES
        .iter()
        .find(|(candidate, _, _)| *candidate == family)
        .expect("browser family is registered");
    let mut rules = Vec::new();
    if !exact_names.is_empty() {
        let names = exact_names
            .iter()
            .map(|name| escape_regex_literal(name))
            .collect::<Vec<_>>()
            .join("|");
        rules.push(serde_json::json!({
            "type":"regex", "source":source_id, "field":"app",
            "regex":format!("^(?:{names})$")
        }));
    }
    rules.push(serde_json::json!({
        "type":"regex", "source":source_id, "field":"app", "regex":app_pattern
    }));
    if rules.len() == 1 {
        rules.remove(0)
    } else {
        serde_json::json!({"type":"any", "rules":rules})
    }
}

pub(crate) fn semantic_rule_expression(
    expression: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let expression = expression
        .as_object()
        .ok_or_else(|| "rule expression must be an object".to_string())?;
    let kind = expression
        .get("type")
        .and_then(serde_json::Value::as_str)
        .or_else(|| expression.contains_key("regex").then_some("regex"));
    match kind {
        Some("none") => Ok(serde_json::json!({"type":"none"})),
        Some(kind @ ("all" | "any")) => {
            let children = expression
                .get("rules")
                .or_else(|| expression.get("children"))
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| format!("{kind} rule requires child rules"))?;
            Ok(serde_json::json!({
                "type": kind,
                "rules": children
                    .iter()
                    .map(semantic_rule_expression)
                    .collect::<Result<Vec<_>, _>>()?
            }))
        }
        Some("regex") => {
            let mut result = serde_json::Map::new();
            result.insert("type".to_string(), serde_json::json!("regex"));
            result.insert(
                "regex".to_string(),
                expression
                    .get("regex")
                    .cloned()
                    .ok_or_else(|| "regex rule requires regex".to_string())?,
            );
            for key in [
                "source",
                "host",
                "ignore_case",
                "negate",
                "weight",
                "value_mode",
            ] {
                if let Some(value) = expression.get(key) {
                    result.insert(key.to_string(), value.clone());
                }
            }
            for key in ["fields", "field", "select_keys"] {
                if let Some(value) = expression.get(key) {
                    result.insert(key.to_string(), value.clone());
                    break;
                }
            }
            Ok(serde_json::Value::Object(result))
        }
        kind => Err(format!("unsupported rule expression type {kind:?}")),
    }
}

pub(crate) fn semantic_category_specs(
    categories: &[serde_json::Value],
) -> Result<Vec<serde_json::Value>, String> {
    categories
        .iter()
        .map(|category| {
            let category = category
                .as_object()
                .ok_or_else(|| "category spec must be an object".to_string())?;
            let mut result = serde_json::Map::new();
            for key in ["id", "name"] {
                if let Some(value) = category.get(key) {
                    result.insert(key.to_string(), value.clone());
                }
            }
            result.insert(
                "rule".to_string(),
                semantic_rule_expression(
                    category
                        .get("rule")
                        .ok_or_else(|| "category spec requires rule".to_string())?,
                )?,
            );
            for key in ["priority", "set_priority", "requires"] {
                if let Some(value) = category.get(key) {
                    result.insert(key.to_string(), value.clone());
                }
            }
            Ok(serde_json::Value::Object(result))
        })
        .collect()
}

fn serialize_query_json(value: &(impl Serialize + ?Sized)) -> String {
    let json = serde_json::to_string(value).expect("query parameters must be JSON serializable");
    let mut serialized = String::with_capacity(json.len());
    let mut chars = json.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\\' {
            serialized.push(character);
            continue;
        }
        let mut count = 1;
        while chars.peek() == Some(&'\\') {
            chars.next();
            count += 1;
        }
        let output_count = if count % 2 == 0 { count / 2 } else { count };
        for _ in 0..output_count {
            serialized.push('\\');
        }
    }
    serialized
}

fn validate_query_strings(value: &(impl Serialize + ?Sized)) -> Result<(), String> {
    fn validate(value: &serde_json::Value, path: &str) -> Result<(), String> {
        match value {
            serde_json::Value::String(value) => {
                if value
                    .chars()
                    .rev()
                    .take_while(|character| *character == '\\')
                    .count()
                    % 2
                    == 1
                {
                    return Err(format!(
                        "{path} cannot end with an odd number of backslashes in Query2"
                    ));
                }
            }
            serde_json::Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    validate(value, &format!("{path}[{index}]"))?;
                }
            }
            serde_json::Value::Object(values) => {
                for (key, value) in values {
                    validate(
                        &serde_json::Value::String(key.clone()),
                        &format!("{path} key"),
                    )?;
                    validate(value, &format!("{path}.{key}"))?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    let value = serde_json::to_value(value)
        .map_err(|error| format!("query parameters must be JSON serializable: {error}"))?;
    validate(&value, "value")
}

fn validate_advanced_options(options: &AdvancedQueryOptions) -> Result<(), String> {
    validate_query_strings(&options.hostname)?;
    validate_query_strings(&options.context_sources)?;
    validate_query_strings(&options.active_time_sources)?;
    validate_query_strings(&options.activity_coverage_sources)?;
    validate_query_strings(&options.activity_sources)?;
    validate_query_strings(&options.background_sources)?;
    validate_query_strings(&options.legacy_window_fields)?;
    if let Some(rule) = &options.active_time_rule {
        validate_query_strings(&semantic_rule_expression(rule)?)?;
    }
    if let Some(categories) = &options.category_specs {
        validate_query_strings(&semantic_category_specs(categories)?)?;
    }
    if options.hostname.as_ref().is_some_and(String::is_empty) {
        return Err("hostname must be non-empty".to_string());
    }
    if options.category_specs.is_some()
        && !options
            .capabilities
            .iter()
            .any(|capability| capability == CATEGORIZE_V2_CAPABILITY)
    {
        return Err(format!(
            "Flexible categorization requires server capability {CATEGORIZE_V2_CAPABILITY}"
        ));
    }
    if (!options.context_sources.is_empty() || !options.activity_coverage_sources.is_empty())
        && !options
            .capabilities
            .iter()
            .any(|capability| capability == CONTEXT_ENRICHMENT_CAPABILITY)
    {
        return Err(format!(
            "Context enrichment requires server capability {CONTEXT_ENRICHMENT_CAPABILITY}"
        ));
    }
    if options.legacy_window_mode == LegacyWindowMode::Context
        && !options
            .capabilities
            .iter()
            .any(|capability| capability == CONTEXT_ENRICHMENT_CAPABILITY)
    {
        return Err(format!(
            "Legacy window context requires server capability {CONTEXT_ENRICHMENT_CAPABILITY}"
        ));
    }
    validate_context_sources(&options.context_sources, options.hostname.as_deref())?;
    validate_activity_coverage_sources(
        &options.activity_coverage_sources,
        options.hostname.as_deref(),
    )?;
    if options.active_time_rule.is_some() || !options.active_time_sources.is_empty() {
        if !options
            .capabilities
            .iter()
            .any(|capability| capability == ACTIVE_PERIODS_V2_CAPABILITY)
        {
            return Err(format!(
                "Active-time rules require server capability {ACTIVE_PERIODS_V2_CAPABILITY}"
            ));
        }
        if options.active_time_rule.is_none() {
            return Err("active-time sources require a rule".to_string());
        }
        validate_active_time_sources(&options.active_time_sources, options.hostname.as_deref())?;
        validate_active_time_rule_sources(
            options.active_time_rule.as_ref().unwrap(),
            &options.active_time_sources,
        )?;
    }
    if !options.activity_sources.is_empty() {
        if !options
            .capabilities
            .iter()
            .any(|capability| capability == MAP_EVENT_FIELDS_CAPABILITY)
        {
            return Err(format!(
                "Replacement activity sources require server capability {MAP_EVENT_FIELDS_CAPABILITY}"
            ));
        }
        validate_activity_sources(&options.activity_sources, options.hostname.as_deref())?;
    }
    if !options.background_sources.is_empty() {
        if !options
            .capabilities
            .iter()
            .any(|capability| capability == MAP_EVENT_FIELDS_CAPABILITY)
        {
            return Err(format!(
                "Background activity sources require server capability {MAP_EVENT_FIELDS_CAPABILITY}"
            ));
        }
        validate_background_sources(&options.background_sources, options.hostname.as_deref())?;
    }
    Ok(())
}

fn validate_canonical_query_v2_options(options: &CanonicalQueryV2Options) -> Result<(), String> {
    validate_query_strings(&options.hostname)?;
    validate_query_strings(&options.activity_coverage_sources)?;
    validate_query_strings(&options.context_sources)?;
    validate_query_strings(&options.active_time_sources)?;
    validate_query_strings(&options.filter_categories)?;
    if let Some(rule) = &options.active_time_rule {
        validate_query_strings(&semantic_rule_expression(rule)?)?;
    }
    if let Some(categories) = &options.category_specs {
        validate_query_strings(&semantic_category_specs(categories)?)?;
    }
    if options.hostname.as_ref().is_some_and(String::is_empty) {
        return Err("hostname must be non-empty".to_string());
    }
    if options.category_specs.is_some()
        && !options
            .capabilities
            .iter()
            .any(|capability| capability == CATEGORIZE_V2_CAPABILITY)
    {
        return Err(format!(
            "Flexible categorization requires server capability {CATEGORIZE_V2_CAPABILITY}"
        ));
    }
    if (!options.context_sources.is_empty() || !options.activity_coverage_sources.is_empty())
        && !options
            .capabilities
            .iter()
            .any(|capability| capability == CONTEXT_ENRICHMENT_CAPABILITY)
    {
        return Err(format!(
            "Context enrichment requires server capability {CONTEXT_ENRICHMENT_CAPABILITY}"
        ));
    }
    validate_context_sources(&options.context_sources, options.hostname.as_deref())?;
    validate_activity_coverage_sources(
        &options.activity_coverage_sources,
        options.hostname.as_deref(),
    )?;

    let mut fact_source_ids = std::collections::BTreeSet::new();
    for source_id in options
        .activity_coverage_sources
        .iter()
        .map(|source| source.source_id.as_str())
        .chain(
            options
                .context_sources
                .iter()
                .map(|source| source.source_id.as_str()),
        )
    {
        if !fact_source_ids.insert(source_id) {
            return Err(format!("duplicate canonical fact source id: {source_id:?}"));
        }
    }

    if options.active_time_rule.is_some() || !options.active_time_sources.is_empty() {
        if !options
            .capabilities
            .iter()
            .any(|capability| capability == ACTIVE_PERIODS_V2_CAPABILITY)
        {
            return Err(format!(
                "Active-time rules require server capability {ACTIVE_PERIODS_V2_CAPABILITY}"
            ));
        }
        if options.active_time_rule.is_none() {
            return Err("active-time sources require a rule".to_string());
        }
        validate_active_time_sources(&options.active_time_sources, options.hostname.as_deref())?;
        validate_active_time_rule_sources(
            options.active_time_rule.as_ref().unwrap(),
            &options.active_time_sources,
        )?;
    }
    if options.explain_categories
        && !options
            .capabilities
            .iter()
            .any(|item| item == EXPLAIN_CATEGORIZE_V2_CAPABILITY)
    {
        return Err(format!(
            "category explanations require server capability {EXPLAIN_CATEGORIZE_V2_CAPABILITY}"
        ));
    }
    if options.filter_afk
        && options.active_time_rule.is_none()
        && !options
            .activity_coverage_sources
            .iter()
            .any(|source| source.keeps_active)
    {
        return Err(
            "active filtering requires an active-time rule or keeps_active coverage".to_string(),
        );
    }
    Ok(())
}

fn validate_source_id(source_id: &str, source_kind: &str) -> Result<(), String> {
    if source_id.is_empty()
        || !source_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!(
            "{source_kind} source_id may only contain letters, numbers, '_' and '-'"
        ));
    }
    Ok(())
}

fn validate_unique_source_ids<'a>(
    source_ids: impl IntoIterator<Item = &'a str>,
    source_kind: &str,
) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for source_id in source_ids {
        validate_source_id(source_id, source_kind)?;
        if !seen.insert(source_id) {
            return Err(format!("duplicate {source_kind} source id: {source_id:?}"));
        }
    }
    Ok(())
}

fn validate_context_sources(
    sources: &[ContextSource],
    hostname: Option<&str>,
) -> Result<(), String> {
    validate_unique_source_ids(
        sources.iter().map(|source| source.source_id.as_str()),
        "context",
    )?;
    for source in sources {
        if source.fields.is_empty() {
            return Err("context source must contain at least one field".to_string());
        }
        resolve_source_buckets(
            source.scope,
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            hostname,
            "context",
        )?;
    }
    Ok(())
}

fn validate_active_time_sources(
    sources: &[ActiveTimeSource],
    hostname: Option<&str>,
) -> Result<(), String> {
    validate_unique_source_ids(
        sources.iter().map(|source| source.source_id.as_str()),
        "active-time",
    )?;
    for source in sources {
        if source.bucket_ids.is_empty() {
            continue;
        }
        resolve_source_buckets(
            source.scope,
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            hostname,
            "active-time",
        )?;
    }
    Ok(())
}

fn validate_active_time_rule_sources(
    rule: &serde_json::Value,
    sources: &[ActiveTimeSource],
) -> Result<(), String> {
    fn collect(rule: &serde_json::Value, referenced: &mut std::collections::BTreeSet<String>) {
        let rule_type = match rule.get("type") {
            Some(serde_json::Value::String(rule_type)) => Some(rule_type.as_str()),
            Some(serde_json::Value::Null) | None if rule.get("regex").is_some() => Some("regex"),
            _ => None,
        };
        match rule_type {
            Some("regex") => {
                if let Some(source) = rule.get("source").and_then(serde_json::Value::as_str) {
                    referenced.insert(source.to_string());
                }
            }
            Some("all" | "any") => {
                if let Some(children) = rule
                    .get("rules")
                    .or_else(|| rule.get("children"))
                    .and_then(serde_json::Value::as_array)
                {
                    for child in children {
                        collect(child, referenced);
                    }
                }
            }
            _ => {}
        }
    }

    let available = sources
        .iter()
        .map(|source| source.source_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut referenced = std::collections::BTreeSet::new();
    collect(rule, &mut referenced);
    let missing = referenced
        .iter()
        .filter(|source| !available.contains(source.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "active-time rule references unknown source(s): {}",
            missing.join(", ")
        ))
    }
}

fn validate_activity_coverage_sources(
    sources: &[ActivityCoverageSource],
    hostname: Option<&str>,
) -> Result<(), String> {
    validate_unique_source_ids(
        sources.iter().map(|source| source.source_id.as_str()),
        "activity coverage",
    )?;
    for source in sources {
        if source.fields.is_empty() {
            return Err("activity coverage source must contain at least one field".to_string());
        }
        resolve_source_buckets(
            source.scope,
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            hostname,
            "activity coverage",
        )?;
    }
    Ok(())
}

fn validate_activity_sources(
    sources: &[ActivitySource],
    hostname: Option<&str>,
) -> Result<(), String> {
    validate_mapped_activity_sources(sources, hostname, "activity")
}

fn validate_background_sources(
    sources: &[ActivitySource],
    hostname: Option<&str>,
) -> Result<(), String> {
    validate_mapped_activity_sources(sources, hostname, "background activity")
}

fn validate_mapped_activity_sources(
    sources: &[ActivitySource],
    hostname: Option<&str>,
    source_kind: &str,
) -> Result<(), String> {
    validate_unique_source_ids(
        sources.iter().map(|source| source.source_id.as_str()),
        source_kind,
    )?;
    for source in sources {
        if source
            .field_mappings
            .iter()
            .any(|(target, source_field)| target.is_empty() || source_field.is_empty())
        {
            return Err(format!(
                "{source_kind} source field mappings may not be empty"
            ));
        }
        resolve_source_buckets(
            source.scope,
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            hostname,
            source_kind,
        )?;
    }
    Ok(())
}

fn resolve_source_buckets<'a>(
    scope: Option<SourceScope>,
    bucket_ids: &'a [String],
    bucket_hosts: &BTreeMap<String, String>,
    host: Option<&str>,
    hostname: Option<&str>,
    source_kind: &str,
) -> Result<Vec<&'a str>, String> {
    if bucket_ids.is_empty() {
        return Err(format!(
            "{source_kind} source must contain at least one bucket_id"
        ));
    }
    let mut unique_bucket_ids = std::collections::BTreeSet::new();
    for bucket_id in bucket_ids {
        if bucket_id.is_empty() {
            return Err(format!("{source_kind} source bucket_id must be non-empty"));
        }
        if !unique_bucket_ids.insert(bucket_id.as_str()) {
            return Err(format!(
                "{source_kind} source contains duplicate bucket_id: {bucket_id:?}"
            ));
        }
    }
    if host.is_some_and(str::is_empty) {
        return Err(format!("{source_kind} source host must be non-empty"));
    }
    if !bucket_hosts.is_empty()
        && (bucket_hosts.len() != bucket_ids.len()
            || bucket_ids.iter().any(|id| {
                bucket_hosts
                    .get(id)
                    .map_or(true, |mapped_host| mapped_host.is_empty())
            })
            || bucket_hosts
                .keys()
                .any(|id| !unique_bucket_ids.contains(id.as_str())))
    {
        return Err(format!(
            "{source_kind} source bucket_hosts must map every bucket exactly once"
        ));
    }

    let resolved_scope = match scope {
        Some(scope) => scope,
        None if host.is_some() || !bucket_hosts.is_empty() => SourceScope::Host,
        None => {
            return Err(format!(
                "{source_kind} source scope is required without ownership metadata"
            ))
        }
    };

    match resolved_scope {
        SourceScope::Global => {
            if host.is_some() || !bucket_hosts.is_empty() {
                return Err(format!(
                    "{source_kind} global source may not contain host ownership metadata"
                ));
            }
            Ok(bucket_ids.iter().map(String::as_str).collect())
        }
        SourceScope::Host => {
            if host.is_none() && bucket_hosts.is_empty() {
                return Err(format!(
                    "{source_kind} host source requires host or complete bucket_hosts"
                ));
            }
            if host.is_some() && !bucket_hosts.is_empty() {
                return Err(format!(
                    "{source_kind} host source must use either host or bucket_hosts, not both"
                ));
            }
            let hostname = hostname.ok_or_else(|| {
                format!("{source_kind} host-scoped source requires query hostname")
            })?;
            if hostname.is_empty() {
                return Err("hostname must be non-empty".to_string());
            }
            if let Some(source_host) = host {
                if source_host != hostname {
                    return Ok(Vec::new());
                }
            }
            Ok(bucket_ids
                .iter()
                .filter(|bucket_id| {
                    bucket_hosts.is_empty()
                        || bucket_hosts
                            .get(*bucket_id)
                            .is_some_and(|bucket_host| bucket_host == hostname)
                })
                .map(String::as_str)
                .collect())
        }
    }
}

fn expected_source_hostname(
    scope: Option<SourceScope>,
    hostname: Option<&str>,
    enforce_hostname: bool,
) -> String {
    if enforce_hostname && scope != Some(SourceScope::Global) {
        hostname
            .map(|hostname| format!(", {}", serialize_query_json(hostname)))
            .unwrap_or_default()
    } else {
        String::new()
    }
}

#[derive(Default)]
struct CurrentPipelineInternals {
    bucket_expressions: BTreeMap<String, Vec<String>>,
    active_aliases: BTreeMap<String, String>,
    auxiliary_sources: Vec<ActiveTimeSource>,
}

fn build_current_raw_source(
    variable: &str,
    bucket_ids: &[String],
    bucket_hosts: &BTreeMap<String, String>,
    host: Option<&str>,
    scope: Option<SourceScope>,
    policy: IntervalPolicy,
    hostname: Option<&str>,
    source_kind: &str,
    bucket_expressions: Option<&[String]>,
) -> Result<String, String> {
    if bucket_ids.is_empty() && source_kind == "active-time" {
        return Ok(format!("{variable}_raw = [];\n{variable} = {variable}_raw"));
    }
    if bucket_expressions.is_some_and(|expressions| expressions.len() != bucket_ids.len()) {
        return Err("internal bucket selector count does not match source bucket ids".to_string());
    }
    let expression_by_id = bucket_ids
        .iter()
        .map(String::as_str)
        .zip(bucket_expressions.unwrap_or_default())
        .collect::<BTreeMap<_, _>>();
    let mut query = vec![format!("{variable}_raw = []")];
    for bucket_id in
        resolve_source_buckets(scope, bucket_ids, bucket_hosts, host, hostname, source_kind)?
    {
        let first_argument = match expression_by_id.get(bucket_id) {
            Some(expression) => (*expression).clone(),
            None => serialize_bucket_id(bucket_id)?,
        };
        let mut arguments = vec![first_argument];
        if scope != Some(SourceScope::Global) {
            if let Some(hostname) = hostname {
                arguments.push(serialize_query_json(hostname));
            } else if policy == IntervalPolicy::Heartbeat {
                arguments.push("null".to_string());
            }
        } else if policy == IntervalPolicy::Heartbeat {
            arguments.push("null".to_string());
        }
        if policy == IntervalPolicy::Heartbeat {
            arguments.push("5".to_string());
        }
        query.push(format!(
            "{variable}_raw = concat({variable}_raw, query_bucket_optional_raw({}))",
            arguments.join(", ")
        ));
    }
    query.push(match policy {
        IntervalPolicy::Exact => format!("{variable} = {variable}_raw"),
        IntervalPolicy::Heartbeat => format!("{variable} = flood_v2({variable}_raw)"),
    });
    Ok(query.join(";\n"))
}

/// Build canonical events exclusively from explicit coverage, context, and active-time sources.
///
/// This is the sole current-server pipeline. Raw loads concatenate competing
/// originals, coverage alone creates output periods, and the effective active
/// mask is computed even when the caller requests unfiltered output.
pub fn try_build_canonical_events_v2(options: &CanonicalQueryV2Options) -> Result<String, String> {
    try_build_canonical_events_v2_internal(options, &CurrentPipelineInternals::default())
}

/// Add category totals to a canonical event program.
pub fn category_totals_query(canonical_events: &str) -> String {
    format!(
        r#"{canonical_events}
duration = sum_durations(events);
cat_events = sort_by_duration(merge_events_by_keys(events, ["$category"]));
RETURN = {{"duration": duration, "cat_events": cat_events}};"#
    )
}

/// Add the active-duration result used by current-status consumers.
pub fn active_status_query(canonical_events: &str) -> String {
    format!(
        r#"{canonical_events}
duration = sum_durations(events);
RETURN = {{"duration": duration}};"#
    )
}

fn try_build_canonical_events_v2_internal(
    options: &CanonicalQueryV2Options,
    internals: &CurrentPipelineInternals,
) -> Result<String, String> {
    validate_canonical_query_v2_options(options)?;
    let hostname = options.hostname.as_deref();
    let mut query = vec![
        "query_window = query_period()".to_string(),
        "coverage = []".to_string(),
    ];

    for (index, source) in options.activity_coverage_sources.iter().enumerate() {
        let variable = format!("coverage_source_{index}");
        query.push(build_current_raw_source(
            &variable,
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            source.scope,
            source.interval_policy,
            hostname,
            "activity coverage",
            internals
                .bucket_expressions
                .get(&source.source_id)
                .map(Vec::as_slice),
        )?);
        query.push(format!(
            "coverage_period_{index} = filter_period_intersect({variable}, query_window)"
        ));
        query.push(format!(
            "coverage = period_union(coverage, coverage_period_{index})"
        ));
    }
    for (index, source) in options.context_sources.iter().enumerate() {
        query.push(build_current_raw_source(
            &format!("context_source_{index}"),
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            source.scope,
            source.interval_policy,
            hostname,
            "context",
            internals
                .bucket_expressions
                .get(&source.source_id)
                .map(Vec::as_slice),
        )?);
    }
    for (index, source) in options.active_time_sources.iter().enumerate() {
        let variable = format!("active_source_{index}");
        if let Some(alias) = internals.active_aliases.get(&source.source_id) {
            query.push(format!("{variable} = {alias}"));
        } else {
            query.push(build_current_raw_source(
                &variable,
                &source.bucket_ids,
                &source.bucket_hosts,
                source.host.as_deref(),
                source.scope,
                source.interval_policy,
                hostname,
                "active-time",
                internals
                    .bucket_expressions
                    .get(&source.source_id)
                    .map(Vec::as_slice),
            )?);
        }
    }
    for (index, source) in internals.auxiliary_sources.iter().enumerate() {
        query.push(build_current_raw_source(
            &format!("auxiliary_source_{index}"),
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            source.scope,
            source.interval_policy,
            hostname,
            "legacy auxiliary",
            internals
                .bucket_expressions
                .get(&source.source_id)
                .map(Vec::as_slice),
        )?);
    }

    query.push("coverage = filter_period_intersect(coverage, query_window)".to_string());
    query.push("events = coverage".to_string());
    for (index, source) in options.activity_coverage_sources.iter().enumerate() {
        let merge_options = serde_json::json!({
            "source_id": source.source_id,
            "conflict": "base_wins",
        });
        query.push(format!(
            "events = merge_subwatcher_fields(events, coverage_source_{index}, {}, {})",
            serialize_query_json(&source.fields),
            serialize_query_json(&merge_options),
        ));
    }
    for (index, source) in options.context_sources.iter().enumerate() {
        let merge_options = serde_json::json!({
            "source_id": source.source_id,
            "conflict": source.conflict,
        });
        query.push(format!(
            "events = merge_subwatcher_fields(events, context_source_{index}, {}, {})",
            serialize_query_json(&source.fields),
            serialize_query_json(&merge_options),
        ));
    }

    if let Some(active_time_rule) = &options.active_time_rule {
        let named = options
            .active_time_sources
            .iter()
            .enumerate()
            .map(|(index, source)| {
                format!(
                    "[{}, active_source_{index}]",
                    serialize_query_json(&source.source_id)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        query.push(format!("active_time_sources = [{named}]"));
        query.push(format!(
            "active_time_rule = {}",
            serialize_query_json(&semantic_rule_expression(active_time_rule)?)
        ));
        let host = hostname
            .map(|value| format!(", {}", serialize_query_json(value)))
            .unwrap_or_default();
        query.push(format!(
            "not_afk = active_periods_v2(active_time_sources, active_time_rule{host})"
        ));
    } else {
        query.push("not_afk = []".to_string());
    }
    for (index, source) in options.activity_coverage_sources.iter().enumerate() {
        if source.keeps_active {
            query.push(format!(
                "not_afk = period_union(not_afk, coverage_period_{index})"
            ));
        }
    }
    query.push("not_afk = period_union(not_afk, [])".to_string());
    query.push("not_afk = filter_period_intersect(not_afk, coverage)".to_string());
    if options.filter_afk {
        query.push("events = filter_period_intersect(events, not_afk)".to_string());
    }

    if let Some(category_specs) = &options.category_specs {
        let function = if options.explain_categories {
            "categorize_v2_explain"
        } else {
            "categorize_v2"
        };
        let host = hostname
            .map(|value| format!(", {}", serialize_query_json(value)))
            .unwrap_or_default();
        query.push(format!(
            "events = {function}(events, {}{host})",
            serialize_query_json(&semantic_category_specs(category_specs)?)
        ));
    }
    if let Some(filter_categories) = &options.filter_categories {
        if !filter_categories.is_empty() {
            query.push(format!(
                "events = filter_keyvals(events, \"$category\", {})",
                serialize_query_json(filter_categories)
            ));
        }
    }
    Ok(query.join(";\n") + ";")
}

/// Build a standalone legacy AFK query without requiring a window bucket.
pub fn try_build_legacy_afk_query(bid_afk: &str, hostname: Option<&str>) -> Result<String, String> {
    legacy_v1::legacy_afk_query(bid_afk, hostname)
}

fn adapt_legacy_desktop_to_current_v2(
    params: &DesktopQueryParams,
    options: &AdvancedQueryOptions,
) -> Result<String, String> {
    validate_query_strings(params)?;
    let default_classes;
    let classes = if params.base.classes.is_empty() {
        default_classes = crate::classes::default_classes();
        default_classes.as_slice()
    } else {
        params.base.classes.as_slice()
    };
    if !options.activity_sources.is_empty() || !options.background_sources.is_empty() {
        return Err("replacement/background source semantics are legacy-v1 only; use explicit coverage/context roles on current servers".to_string());
    }
    let mut coverage = options.activity_coverage_sources.clone();
    let mut context = options.context_sources.clone();
    let mut internals = CurrentPipelineInternals::default();
    let mut projection_source = None;
    let mut projection_variable = "events".to_string();
    if options.legacy_window_mode == LegacyWindowMode::None
        && params
            .always_active_pattern
            .as_deref()
            .is_some_and(|pattern| !pattern.is_empty())
    {
        return Err("always_active_pattern requires a legacy window projection; legacy_window_mode=none is unsupported".to_string());
    }
    if !params.bid_window.is_empty() && options.legacy_window_mode != LegacyWindowMode::None {
        let source_id = "legacy_window".to_string();
        let window_bucket_id = params.bid_window.clone();
        let mut selector_arguments = vec![serialize_bucket_id(&params.bid_window)?];
        if let Some(hostname) = &options.hostname {
            selector_arguments.push(serialize_query_json(hostname));
        }
        internals.bucket_expressions.insert(
            source_id.clone(),
            vec![format!("find_bucket({})", selector_arguments.join(", "))],
        );
        projection_source = Some(source_id.clone());
        let scope = Some(if options.hostname.is_some() {
            SourceScope::Host
        } else {
            SourceScope::Global
        });
        if options.legacy_window_mode == LegacyWindowMode::Activity {
            projection_variable = "coverage_source_0".to_string();
            coverage.insert(
                0,
                ActivityCoverageSource {
                    source_id,
                    bucket_ids: vec![window_bucket_id.clone()],
                    fields: if options.legacy_window_fields.is_empty() {
                        default_legacy_window_fields()
                    } else {
                        options.legacy_window_fields.clone()
                    },
                    keeps_active: false,
                    scope,
                    bucket_hosts: BTreeMap::new(),
                    host: options.hostname.clone(),
                    interval_policy: IntervalPolicy::Heartbeat,
                },
            );
        } else {
            projection_variable = "context_source_0".to_string();
            context.insert(
                0,
                ContextSource {
                    source_id,
                    bucket_ids: vec![window_bucket_id.clone()],
                    scope,
                    bucket_hosts: BTreeMap::new(),
                    fields: if options.legacy_window_fields.is_empty() {
                        default_legacy_window_fields()
                    } else {
                        options.legacy_window_fields.clone()
                    },
                    conflict: "base_wins".to_string(),
                    host: options.hostname.clone(),
                    interval_policy: IntervalPolicy::Heartbeat,
                },
            );
        }
    }

    let has_custom_active_rule = options.active_time_rule.is_some();
    let mut active_rule = options.active_time_rule.clone();
    let mut active_sources = options.active_time_sources.clone();
    if active_rule.is_none() && !params.bid_afk.is_empty() {
        active_sources = vec![ActiveTimeSource {
            source_id: "legacy_afk".to_string(),
            bucket_ids: vec![params.bid_afk.clone()],
            scope: Some(if options.hostname.is_some() {
                SourceScope::Host
            } else {
                SourceScope::Global
            }),
            bucket_hosts: BTreeMap::new(),
            host: options.hostname.clone(),
            interval_policy: IntervalPolicy::Heartbeat,
        }];
        let mut selector_arguments = vec![serialize_bucket_id(&params.bid_afk)?];
        if let Some(hostname) = &options.hostname {
            selector_arguments.push(serialize_query_json(hostname));
        }
        internals.bucket_expressions.insert(
            "legacy_afk".to_string(),
            vec![format!("find_bucket({})", selector_arguments.join(", "))],
        );
        let mut branches = vec![serde_json::json!({
            "type":"regex", "source":"legacy_afk", "field":"status", "regex":"^not-afk$"
        })];
        if let (Some(pattern), Some(source_id)) = (
            params.always_active_pattern.as_deref(),
            projection_source.as_deref(),
        ) {
            active_sources.push(ActiveTimeSource {
                source_id: source_id.to_string(),
                bucket_ids: vec![params.bid_window.clone()],
                scope: Some(if options.hostname.is_some() {
                    SourceScope::Host
                } else {
                    SourceScope::Global
                }),
                bucket_hosts: BTreeMap::new(),
                host: options.hostname.clone(),
                interval_policy: IntervalPolicy::Heartbeat,
            });
            internals
                .active_aliases
                .insert(source_id.to_string(), projection_variable.clone());
            branches.push(serde_json::json!({"type":"any", "rules":[
                {"type":"regex", "source":source_id, "field":"app", "regex":pattern},
                {"type":"regex", "source":source_id, "field":"title", "regex":pattern}
            ]}));
        }
        active_rule = Some(if branches.len() == 1 {
            branches.remove(0)
        } else {
            serde_json::json!({"type":"any", "rules":branches})
        });
    }

    let mut browser_streams = Vec::<(String, String)>::new();
    let audible_enabled = params.base.include_audible
        && !has_custom_active_rule
        && active_rule.is_some()
        && projection_source.is_some();
    let mut audible_rules = Vec::new();
    for (browser_name, _app_names, _app_pattern, family_bucket_ids) in
        current_browser_families(&params.base.bid_browsers)
    {
        let source_id = format!("legacy_browser_{browser_name}");
        let source = ActiveTimeSource {
            source_id: source_id.clone(),
            bucket_ids: family_bucket_ids,
            scope: Some(SourceScope::Global),
            bucket_hosts: BTreeMap::new(),
            host: None,
            interval_policy: IntervalPolicy::Heartbeat,
        };
        if audible_enabled {
            let active_index = active_sources.len();
            active_sources.push(source);
            browser_streams.push((
                (*browser_name).to_string(),
                format!("active_source_{active_index}"),
            ));
            audible_rules.push(serde_json::json!({
                "type":"all",
                "rules":[
                    {"type":"regex", "source":source_id, "field":"audible", "regex":"^true$", "value_mode":"scalar"},
                    current_browser_focus_rule(projection_source.as_deref().unwrap(), browser_name)
                ]
            }));
        } else {
            let auxiliary_index = internals.auxiliary_sources.len();
            internals.auxiliary_sources.push(source);
            browser_streams.push((
                (*browser_name).to_string(),
                format!("auxiliary_source_{auxiliary_index}"),
            ));
        }
    }
    if !audible_rules.is_empty() {
        let focus_id = projection_source.as_ref().unwrap();
        if !active_sources
            .iter()
            .any(|source| &source.source_id == focus_id)
        {
            active_sources.push(ActiveTimeSource {
                source_id: focus_id.clone(),
                bucket_ids: vec![params.bid_window.clone()],
                scope: Some(if options.hostname.is_some() {
                    SourceScope::Host
                } else {
                    SourceScope::Global
                }),
                bucket_hosts: BTreeMap::new(),
                host: options.hostname.clone(),
                interval_policy: IntervalPolicy::Heartbeat,
            });
            internals
                .active_aliases
                .insert(focus_id.clone(), projection_variable.clone());
        }
        let mut rules = vec![active_rule.take().unwrap()];
        rules.extend(audible_rules);
        active_rule = Some(serde_json::json!({"type":"any", "rules":rules}));
    }

    let canonical_options = CanonicalQueryV2Options {
        hostname: options.hostname.clone(),
        category_specs: None,
        activity_coverage_sources: coverage,
        context_sources: context,
        active_time_rule: active_rule,
        active_time_sources: active_sources,
        capabilities: options.capabilities.clone(),
        filter_afk: params.base.filter_afk,
        filter_categories: None,
        explain_categories: false,
    };
    let mut query = try_build_canonical_events_v2_internal(&canonical_options, &internals)?;
    if projection_source.is_some() {
        let fields = if options.legacy_window_fields.is_empty() {
            default_legacy_window_fields()
        } else {
            options.legacy_window_fields.clone()
        };
        let source_variable = projection_variable.as_str();
        query.push_str(&format!(
            "\nevents = period_union([], events);\nevents = merge_subwatcher_fields(events, {source_variable}, {});",
            serialize_query_json(&fields),
        ));
        let coverage_offset = usize::from(options.legacy_window_mode == LegacyWindowMode::Activity);
        for (index, source) in options.activity_coverage_sources.iter().enumerate() {
            let merge_options = serde_json::json!({
                "source_id": source.source_id,
                "conflict": "base_wins",
            });
            query.push_str(&format!(
                "\nevents = merge_subwatcher_fields(events, coverage_source_{}, {}, {});",
                index + coverage_offset,
                serialize_query_json(&source.fields),
                serialize_query_json(&merge_options),
            ));
        }
        let context_offset = usize::from(options.legacy_window_mode == LegacyWindowMode::Context);
        for (index, source) in options.context_sources.iter().enumerate() {
            let merge_options = serde_json::json!({
                "source_id": source.source_id,
                "conflict": source.conflict,
            });
            query.push_str(&format!(
                "\nevents = merge_subwatcher_fields(events, context_source_{}, {}, {});",
                index + context_offset,
                serialize_query_json(&source.fields),
                serialize_query_json(&merge_options),
            ));
        }
        if let Some(category_specs) = &options.category_specs {
            let merge_options = serde_json::json!({
                "source_id": projection_source.as_deref().unwrap(),
                "conflict": "base_wins",
            });
            let host = options
                .hostname
                .as_ref()
                .map(|hostname| format!(", {}", serialize_query_json(hostname)))
                .unwrap_or_default();
            query.push_str(&format!(
                "\nevents = merge_subwatcher_fields(events, {source_variable}, {}, {});\nevents = categorize_v2(events, {}{host});",
                serialize_query_json(&fields),
                serialize_query_json(&merge_options),
                serialize_query_json(&semantic_category_specs(category_specs)?),
            ));
        } else if !classes.is_empty() {
            query.push_str(&format!(
                "\nevents = categorize(events, {});",
                serialize_classes(classes)
            ));
        }
        if !params.base.filter_classes.is_empty() {
            query.push_str(&format!(
                "\nevents = filter_keyvals(events, \"$category\", {});",
                serialize_query_json(&params.base.filter_classes)
            ));
        }
    } else {
        if let Some(category_specs) = &options.category_specs {
            let host = options
                .hostname
                .as_ref()
                .map(|hostname| format!(", {}", serialize_query_json(hostname)))
                .unwrap_or_default();
            query.push_str(&format!(
                "\nevents = categorize_v2(events, {}{host});",
                serialize_query_json(&semantic_category_specs(category_specs)?),
            ));
        } else if !classes.is_empty() {
            query.push_str(&format!(
                "\nevents = categorize(events, {});",
                serialize_classes(classes)
            ));
        }
        if !params.base.filter_classes.is_empty() {
            query.push_str(&format!(
                "\nevents = filter_keyvals(events, \"$category\", {});",
                serialize_query_json(&params.base.filter_classes)
            ));
        }
    }
    query.push_str("\nbrowser_events = [];");
    for (browser_name, variable) in browser_streams {
        let Some(focus_id) = projection_source.as_ref() else {
            continue;
        };
        let focus_rule = current_browser_focus_rule(focus_id, &browser_name);
        let browser_fields = ["url", "title", "audible", "incognito", "tabCount"];
        query.push_str(&format!(
            "\nbrowser_focus_{browser_name} = active_periods_v2([[{}, {projection_variable}]], {});\nbrowser_facts_{browser_name} = merge_subwatcher_fields({variable}, [], {});\nbrowser_presence_{browser_name} = period_union({variable}, []);\nbrowser_presence_{browser_name} = filter_period_intersect(browser_presence_{browser_name}, browser_focus_{browser_name});\nbrowser_resolved_{browser_name} = merge_subwatcher_fields(browser_presence_{browser_name}, browser_facts_{browser_name}, {});\nbrowser_{browser_name} = split_url_events(browser_resolved_{browser_name});\nbrowser_events = concat(browser_events, browser_{browser_name});",
            serialize_query_json(focus_id),
            serialize_query_json(&focus_rule),
            serialize_query_json(&browser_fields),
            serialize_query_json(&browser_fields),
        ));
    }
    if !params.base.bid_browsers.is_empty() {
        // Derived report output cannot escape selected canonical activity.
        query.push_str(
            "\nbrowser_events = sort_by_timestamp(browser_events);\nbrowser_events = filter_period_intersect(browser_events, query_window);\nbrowser_events = filter_period_intersect(browser_events, events);",
        );
    }
    Ok(query)
}

fn current_compatibility_options(options: &AdvancedQueryOptions) -> AdvancedQueryOptions {
    let mut current = options.clone();
    for capability in [
        OPTIONAL_BUCKET_RAW_CAPABILITY,
        QUERY_PERIOD_CAPABILITY,
        FLOOD_V2_CAPABILITY,
        CONTEXT_ENRICHMENT_CAPABILITY,
        ACTIVE_PERIODS_V2_CAPABILITY,
        CATEGORIZE_V2_CAPABILITY,
    ] {
        if !current.capabilities.iter().any(|item| item == capability) {
            current.capabilities.push(capability.to_string());
        }
    }
    current
}

pub fn build_desktop_canonical_events(params: &DesktopQueryParams) -> String {
    let options = current_compatibility_options(&AdvancedQueryOptions::default());
    adapt_legacy_desktop_to_current_v2(params, &options)
        .expect("desktop query parameters must be representable in Query2")
}

#[deprecated(
    note = "this API mixes legacy desktop parameters with advanced sources; use try_build_canonical_events_v2"
)]
pub fn try_build_desktop_canonical_events_with_options(
    params: &DesktopQueryParams,
    options: &AdvancedQueryOptions,
) -> Result<String, String> {
    validate_query_strings(params)?;
    let options = current_compatibility_options(options);
    validate_advanced_options(&options)?;
    adapt_legacy_desktop_to_current_v2(params, &options)
}

pub fn build_android_canonical_events(params: &AndroidQueryParams) -> String {
    build_android_canonical_events_with_options(params, &AdvancedQueryOptions::default())
        .expect("legacy Android query parameters are valid")
}

pub fn try_build_android_canonical_events_with_options(
    params: &AndroidQueryParams,
    options: &AdvancedQueryOptions,
) -> Result<String, String> {
    validate_query_strings(params)?;
    if options.active_time_rule.is_some() || !options.active_time_sources.is_empty() {
        return Err("Active-time options are not supported for Android queries".to_string());
    }
    if !options.activity_sources.is_empty() {
        return Err(
            "Replacement activity sources are not supported for Android queries".to_string(),
        );
    }
    if !options.activity_coverage_sources.is_empty() {
        return Err("Activity coverage sources are not supported for Android queries".to_string());
    }
    if !options.background_sources.is_empty() {
        return Err(
            "Background activity sources are not supported for Android queries".to_string(),
        );
    }
    validate_advanced_options(options)?;
    build_android_canonical_events_with_options(params, options)
}

fn build_android_canonical_events_with_options(
    params: &AndroidQueryParams,
    options: &AdvancedQueryOptions,
) -> Result<String, String> {
    legacy_v1::android_with_options(params, options)
}

pub fn try_build_browser_events(params: &DesktopQueryParams) -> Result<String, String> {
    legacy_v1::browser_events(params)
}

pub fn build_browser_events(params: &DesktopQueryParams) -> String {
    try_build_browser_events(params).expect("browser bucket IDs must be representable in Query2")
}

/// Build a full desktop query using default localhost:5600 configuration
pub fn full_desktop_query(params: &DesktopQueryParams) -> String {
    let mut query = QueryParams::Desktop(params.clone()).canonical_events();

    // Add basic event aggregations
    query.push_str(&format!(
        "
        title_events = sort_by_duration(merge_events_by_keys(events, [\"app\", \"title\"]));
        app_events = sort_by_duration(merge_events_by_keys(title_events, [\"app\"]));
        cat_events = sort_by_duration(merge_events_by_keys(events, [\"$category\"]));
        app_events = limit_events(app_events, {});
        title_events = limit_events(title_events, {});
        duration = sum_durations(events);
        ",
        DEFAULT_LIMIT, DEFAULT_LIMIT
    ));

    // Add browser-specific query parts if browser buckets exist
    if !params.base.bid_browsers.is_empty() {
        query.push_str(&format!(
            "
            browser_urls = merge_events_by_keys(browser_events, [\"url\"]);
            browser_urls = sort_by_duration(browser_urls);
            browser_urls = limit_events(browser_urls, {});
            browser_domains = merge_events_by_keys(browser_events, [\"$domain\"]);
            browser_domains = sort_by_duration(browser_domains);
            browser_domains = limit_events(browser_domains, {});
            browser_duration = sum_durations(browser_events);
            ",
            DEFAULT_LIMIT, DEFAULT_LIMIT
        ));
    } else {
        query.push_str(
            "
            browser_events = [];
            browser_urls = [];
            browser_domains = [];
            browser_duration = 0;
            ",
        );
    }

    // Add return statement
    query.push_str(
        "
        RETURN = {
            \"events\": events,
            \"window\": {
                \"app_events\": app_events,
                \"title_events\": title_events,
                \"cat_events\": cat_events,
                \"active_events\": not_afk,
                \"duration\": duration
            },
            \"browser\": {
                \"domains\": browser_domains,
                \"urls\": browser_urls,
                \"duration\": browser_duration
            }
        };
        ",
    );

    query
}

/// Explicit compatibility namespace for genuinely old server grammar.
pub mod legacy_v1;

fn serialize_bucket_id(bucket_id: &str) -> Result<String, String> {
    let trailing_backslashes = bucket_id
        .chars()
        .rev()
        .take_while(|character| *character == '\\')
        .count();
    if trailing_backslashes % 2 == 1 {
        return Err("bucket ID cannot end with an odd number of backslashes in Query2".to_string());
    }
    Ok(serialize_query_json(bucket_id))
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_desktop_query_without_afk_filter_returns_empty_active_events() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![],
                filter_classes: vec![],
                filter_afk: false,
                include_audible: false,
            },
            bid_window: "aw-watcher-window_".to_string(),
            bid_afk: String::new(),
            always_active_pattern: None,
        };

        let query = full_desktop_query(&params);
        assert!(query.contains("not_afk = []"));
        assert!(query.contains("\"active_events\": not_afk"));
    }

    #[test]
    fn test_classes_serialization() {
        let classes = vec![
            (
                vec!["Work".to_string()],
                crate::classes::CategorySpec {
                    spec_type: "regex".to_string(),
                    regex: "Google Docs".to_string(),
                    ignore_case: false,
                    select_keys: Vec::new(),
                },
            ),
            (
                vec!["Work".to_string(), "Programming".to_string()],
                crate::classes::CategorySpec {
                    spec_type: "regex".to_string(),
                    regex: "GitHub|vim".to_string(),
                    ignore_case: true,
                    select_keys: Vec::new(),
                },
            ),
        ];

        let serialized = serialize_classes(&classes);

        // Should contain the category names and rules in the correct format
        assert!(serialized.contains("Work"));
        assert!(serialized.contains("Programming"));
        assert!(serialized.contains("Google Docs"));
        assert!(serialized.contains("GitHub|vim"));
        assert!(serialized.contains("\"type\":\"regex\""));
        assert!(serialized.contains("\"ignore_case\":false"));
        assert!(serialized.contains("\"ignore_case\":true"));
    }

    #[test]
    fn test_query_json_serialization_preserves_regex_escapes() {
        assert_eq!(
            serialize_query_json(&serde_json::json!({"regex": r"\d+"})),
            r#"{"regex":"\d+"}"#
        );
        assert_eq!(
            serialize_query_json(&serde_json::json!({"regex": "a\\\"b"})),
            r#"{"regex":"a\\\"b"}"#
        );
        assert_eq!(
            serialize_query_json(&serde_json::json!({"regex": r"path\\"})),
            r#"{"regex":"path\\"}"#
        );
        assert_eq!(
            serialize_query_json(&serde_json::json!({"path\\name": "source\\field"})),
            r#"{"path\name":"source\field"}"#
        );
    }

    #[test]
    fn test_bucket_id_serialization_rejects_odd_trailing_backslashes() {
        assert_eq!(
            serialize_bucket_id(r"window\bucket").unwrap(),
            r#""window\bucket""#
        );
        assert!(serialize_bucket_id("window\\")
            .unwrap_err()
            .contains("odd number of backslashes"));
        assert!(
            validate_query_strings(&serde_json::json!({"category": ["invalid\\"]}))
                .unwrap_err()
                .contains("odd number of backslashes")
        );
    }

    #[test]
    fn test_canonical_events_with_existing_classes() {
        let classes = vec![(
            vec!["Test".to_string()],
            crate::classes::CategorySpec {
                spec_type: "regex".to_string(),
                regex: "test".to_string(),
                ignore_case: false,
                select_keys: Vec::new(),
            },
        )];

        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes,
                filter_classes: vec![],
                filter_afk: true,
                include_audible: true,
            },
            bid_window: "test-window".to_string(),
            bid_afk: "test-afk".to_string(),
            always_active_pattern: None,
        };

        let query_params = QueryParams::Desktop(params);
        let query = query_params.canonical_events();

        // Should contain categorization
        assert!(query.contains("events = categorize"));
        assert!(query.contains("test"));
    }

    #[test]
    fn test_legacy_categorization_remains_default() {
        let params = AndroidQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![(
                    vec!["Legacy".to_string()],
                    crate::classes::CategorySpec {
                        spec_type: "regex".to_string(),
                        regex: "legacy".to_string(),
                        ignore_case: false,
                        select_keys: Vec::new(),
                    },
                )],
                filter_classes: vec![],
                filter_afk: true,
                include_audible: true,
            },
            bid_android: "test-android".to_string(),
        };

        let query = QueryParams::Android(params).canonical_events();
        assert!(query.contains("events = categorize(events"));
        assert!(!query.contains("categorize_v2"));
    }

    #[test]
    fn test_android_find_bucket_uses_hostname() {
        let params = AndroidQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![],
                filter_classes: vec![],
                filter_afk: false,
                include_audible: false,
            },
            bid_android: "test-android".to_string(),
        };
        let options = AdvancedQueryOptions {
            hostname: Some("phone".to_string()),
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_android_canonical_events_with_options(&params, &options).unwrap();
        assert!(
            query.contains(r#"events = flood(query_bucket(find_bucket("test-android", "phone")))"#)
        );
    }

    #[test]
    fn test_explicit_empty_category_specs_use_categorize_v2() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![(
                    vec!["Legacy".to_string()],
                    crate::classes::CategorySpec {
                        spec_type: "regex".to_string(),
                        regex: "legacy".to_string(),
                        ignore_case: false,
                        select_keys: Vec::new(),
                    },
                )],
                filter_classes: vec![],
                filter_afk: true,
                include_audible: true,
            },
            bid_window: "test-window".to_string(),
            bid_afk: "test-afk".to_string(),
            always_active_pattern: None,
        };
        let missing_capability = AdvancedQueryOptions {
            category_specs: Some(vec![]),
            ..AdvancedQueryOptions::default()
        };
        assert_eq!(
            validate_advanced_options(&missing_capability),
            Err(format!(
                "Flexible categorization requires server capability {CATEGORIZE_V2_CAPABILITY}"
            ))
        );

        let options = AdvancedQueryOptions {
            category_specs: Some(vec![]),
            capabilities: vec![CATEGORIZE_V2_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        };

        assert_eq!(AdvancedQueryOptions::default().category_specs, None);
        let query = try_build_desktop_canonical_events_with_options(&params, &options).unwrap();
        assert!(query.contains("events = categorize_v2(events, []);"));
        assert!(!query.contains("events = categorize(events"));
    }

    #[test]
    fn test_context_source_validation() {
        let source =
            |source_id: &str, bucket_ids: Vec<String>, fields: Vec<String>| ContextSource {
                source_id: source_id.to_string(),
                bucket_ids,
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                fields,
                conflict: "base_wins".to_string(),
                host: None,
                interval_policy: IntervalPolicy::Exact,
            };

        let options = |context_source| AdvancedQueryOptions {
            category_specs: None,
            context_sources: vec![context_source],
            capabilities: vec![CONTEXT_ENRICHMENT_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        };

        assert!(validate_advanced_options(&options(source(
            "invalid.source",
            vec!["bucket".to_string()],
            vec!["field".to_string()]
        )))
        .is_err());
        assert!(validate_advanced_options(&options(source(
            "valid-source_1",
            vec![],
            vec!["field".to_string()]
        )))
        .is_err());
        assert!(validate_advanced_options(&options(source(
            "valid-source_1",
            vec!["bucket".to_string()],
            vec![]
        )))
        .is_err());
    }

    #[test]
    fn test_context_source_conflict_deserialization_default() {
        let source: ContextSource = serde_json::from_value(serde_json::json!({
            "source_id": "editor",
            "bucket_ids": ["bucket"],
            "fields": ["project"]
        }))
        .unwrap();

        assert_eq!(source.conflict, "base_wins");
    }

    #[test]
    fn test_context_source_uses_only_current_host_buckets() {
        let source = ContextSource {
            source_id: "browser".to_string(),
            bucket_ids: vec!["browser-laptop".to_string(), "browser-desktop".to_string()],
            scope: None,
            bucket_hosts: BTreeMap::from([
                ("browser-laptop".to_string(), "laptop".to_string()),
                ("browser-desktop".to_string(), "desktop".to_string()),
            ]),
            fields: vec!["url".to_string()],
            conflict: "base_wins".to_string(),
            host: None,
            interval_policy: IntervalPolicy::Exact,
        };

        validate_context_sources(std::slice::from_ref(&source), Some("laptop")).unwrap();
        let query = legacy_v1::build_context_events(&[source], Some("laptop"), false).unwrap();

        assert!(query.contains("browser-laptop"));
        assert!(!query.contains("browser-desktop"));
    }

    #[test]
    fn test_context_source_rejects_incomplete_bucket_host_mapping() {
        let source = ContextSource {
            source_id: "browser".to_string(),
            bucket_ids: vec!["browser-laptop".to_string(), "browser-desktop".to_string()],
            scope: Some(SourceScope::Host),
            bucket_hosts: BTreeMap::from([("browser-laptop".to_string(), "laptop".to_string())]),
            fields: vec!["url".to_string()],
            conflict: "base_wins".to_string(),
            host: None,
            interval_policy: IntervalPolicy::Exact,
        };

        assert_eq!(
            validate_context_sources(&[source], Some("laptop")),
            Err("context source bucket_hosts must map every bucket exactly once".to_string())
        );
    }

    #[test]
    fn test_active_time_requires_capability() {
        let options = AdvancedQueryOptions {
            active_time_rule: Some(serde_json::json!({"type": "none"})),
            active_time_sources: vec![ActiveTimeSource {
                source_id: "afk".to_string(),
                bucket_ids: vec!["afk".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                host: None,
                interval_policy: IntervalPolicy::Exact,
            }],
            ..AdvancedQueryOptions::default()
        };

        assert_eq!(
            validate_advanced_options(&options),
            Err(format!(
                "Active-time rules require server capability {ACTIVE_PERIODS_V2_CAPABILITY}"
            ))
        );
    }

    #[test]
    fn test_android_rejects_active_time_options() {
        let params = AndroidQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![],
                filter_classes: vec![],
                filter_afk: true,
                include_audible: true,
            },
            bid_android: "test-android".to_string(),
        };
        let options = AdvancedQueryOptions {
            active_time_sources: vec![ActiveTimeSource {
                source_id: "afk".to_string(),
                bucket_ids: vec!["afk".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                host: None,
                interval_policy: IntervalPolicy::Exact,
            }],
            ..AdvancedQueryOptions::default()
        };

        assert_eq!(
            try_build_android_canonical_events_with_options(&params, &options),
            Err("Active-time options are not supported for Android queries".to_string())
        );
    }

    #[test]
    fn test_source_scope_serde_and_fail_closed_ownership() {
        let global: ContextSource = serde_json::from_value(serde_json::json!({
            "source_id": "editor",
            "bucket_ids": ["editor"],
            "scope": "global",
            "fields": ["project"]
        }))
        .unwrap();
        assert_eq!(global.scope, Some(SourceScope::Global));
        validate_context_sources(&[global], None).unwrap();

        let missing_scope: ContextSource = serde_json::from_value(serde_json::json!({
            "source_id": "editor",
            "bucket_ids": ["editor"],
            "fields": ["project"]
        }))
        .unwrap();
        assert!(validate_context_sources(&[missing_scope], None)
            .unwrap_err()
            .contains("scope is required"));

        let normalized_host: ContextSource = serde_json::from_value(serde_json::json!({
            "source_id": "editor",
            "bucket_ids": ["editor"],
            "host": "laptop",
            "fields": ["project"]
        }))
        .unwrap();
        validate_context_sources(&[normalized_host], Some("laptop")).unwrap();
    }

    #[test]
    fn test_host_scope_partition_and_validation_are_strict() {
        let bucket_ids = vec!["laptop".to_string(), "desktop".to_string()];
        let bucket_hosts = BTreeMap::from([
            ("laptop".to_string(), "host-a".to_string()),
            ("desktop".to_string(), "host-b".to_string()),
        ]);
        assert_eq!(
            resolve_source_buckets(
                Some(SourceScope::Host),
                &bucket_ids,
                &bucket_hosts,
                None,
                Some("host-a"),
                "activity",
            )
            .unwrap(),
            vec!["laptop"]
        );
        assert!(resolve_source_buckets(
            Some(SourceScope::Host),
            &bucket_ids,
            &bucket_hosts,
            None,
            None,
            "activity",
        )
        .unwrap_err()
        .contains("requires query hostname"));

        let duplicate_ids = vec!["same".to_string(), "same".to_string()];
        assert!(resolve_source_buckets(
            Some(SourceScope::Global),
            &duplicate_ids,
            &BTreeMap::new(),
            None,
            None,
            "activity",
        )
        .unwrap_err()
        .contains("duplicate bucket_id"));
        assert!(resolve_source_buckets(
            Some(SourceScope::Global),
            &["one".to_string()],
            &BTreeMap::from([("extra".to_string(), "host-a".to_string())]),
            None,
            Some("host-a"),
            "activity",
        )
        .unwrap_err()
        .contains("map every bucket exactly once"));
        assert!(resolve_source_buckets(
            Some(SourceScope::Host),
            &["one".to_string()],
            &BTreeMap::from([("one".to_string(), String::new())]),
            None,
            Some("host-a"),
            "activity",
        )
        .unwrap_err()
        .contains("map every bucket exactly once"));
        assert!(resolve_source_buckets(
            Some(SourceScope::Host),
            &["one".to_string()],
            &BTreeMap::new(),
            None,
            Some("host-a"),
            "activity",
        )
        .unwrap_err()
        .contains("requires host or complete bucket_hosts"));
        assert!(resolve_source_buckets(
            Some(SourceScope::Host),
            &["one".to_string()],
            &BTreeMap::from([("one".to_string(), "host-a".to_string())]),
            Some("host-a"),
            Some("host-a"),
            "activity",
        )
        .unwrap_err()
        .contains("either host or bucket_hosts, not both"));
        assert!(resolve_source_buckets(
            Some(SourceScope::Global),
            &["one".to_string()],
            &BTreeMap::new(),
            Some("host-a"),
            Some("host-a"),
            "activity",
        )
        .unwrap_err()
        .contains("may not contain host ownership metadata"));
    }

    #[test]
    fn test_active_and_legacy_afk_only_queries_need_no_activity_stream() {
        let legacy_query = try_build_legacy_afk_query("legacy-afk", Some("desktop")).unwrap();
        assert!(legacy_query.contains(r#"find_bucket("legacy-afk", "desktop")"#));
        assert!(legacy_query.ends_with("RETURN = not_afk;"));
        assert!(!legacy_query.contains("window"));
        assert!(!legacy_query.contains("events ="));
    }

    fn insert_v2_test_event(
        datastore: &aw_datastore::Datastore,
        bucket_id: &str,
        data: serde_json::Map<String, serde_json::Value>,
    ) {
        let timestamp = chrono::DateTime::parse_from_rfc3339("2024-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        datastore
            .create_bucket(&aw_models::Bucket {
                bid: None,
                id: bucket_id.to_string(),
                _type: "test".to_string(),
                client: "test".to_string(),
                hostname: "test".to_string(),
                created: Some(timestamp),
                data: serde_json::Map::new(),
                metadata: aw_models::BucketMetadata::default(),
                events: None,
                last_updated: None,
            })
            .unwrap();
        datastore
            .insert_events(
                bucket_id,
                &[aw_models::Event::new(
                    timestamp,
                    chrono::Duration::seconds(10),
                    data,
                )],
            )
            .unwrap();
    }

    fn run_v2_query(
        datastore: &aw_datastore::Datastore,
        options: &CanonicalQueryV2Options,
    ) -> Vec<aw_models::Event> {
        let query = try_build_canonical_events_v2(options).unwrap();
        let interval =
            aw_models::TimeInterval::new_from_string("2024-06-01T12:00:00Z/2024-06-01T12:01:00Z")
                .unwrap();
        let result =
            aw_query::query(&format!("{query}; return events;"), &interval, datastore).unwrap();
        Vec::<aw_models::Event>::try_from(&result).unwrap()
    }

    #[test]
    fn notifier_projection_queries_execute_category_totals_and_active_status() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        let timestamp = chrono::DateTime::parse_from_rfc3339("2024-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        datastore
            .create_bucket(&aw_models::Bucket {
                bid: None,
                id: "meeting".to_string(),
                _type: "meeting".to_string(),
                client: "test".to_string(),
                hostname: "test".to_string(),
                created: Some(timestamp),
                data: serde_json::Map::new(),
                metadata: aw_models::BucketMetadata::default(),
                events: None,
                last_updated: None,
            })
            .unwrap();
        datastore
            .insert_events(
                "meeting",
                &[aw_models::Event::new(
                    timestamp,
                    chrono::Duration::seconds(30),
                    serde_json::Map::from_iter([(
                        "subject".to_string(),
                        serde_json::json!("Planning"),
                    )]),
                )],
            )
            .unwrap();
        let source = global_coverage_source("meeting", "meeting", &["subject"]);
        let options = CanonicalQueryV2Options {
            activity_coverage_sources: vec![source],
            active_time_sources: vec![ActiveTimeSource {
                source_id: "meeting".to_string(),
                bucket_ids: vec!["meeting".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                host: None,
                interval_policy: IntervalPolicy::Exact,
            }],
            active_time_rule: Some(serde_json::json!({
                "type":"regex", "source":"meeting", "field":"subject", "regex":"Planning"
            })),
            category_specs: Some(vec![serde_json::json!({
                "id":"meeting", "name":["Meeting"],
                "rule":{"type":"regex", "source":"meeting", "field":"subject", "regex":"Planning"}
            })]),
            capabilities: vec![
                OPTIONAL_BUCKET_RAW_CAPABILITY.to_string(),
                QUERY_PERIOD_CAPABILITY.to_string(),
                FLOOD_V2_CAPABILITY.to_string(),
                CONTEXT_ENRICHMENT_CAPABILITY.to_string(),
                ACTIVE_PERIODS_V2_CAPABILITY.to_string(),
                CATEGORIZE_V2_CAPABILITY.to_string(),
            ],
            ..CanonicalQueryV2Options::default()
        };
        let canonical = try_build_canonical_events_v2(&options).unwrap();
        let interval =
            aw_models::TimeInterval::new_from_string("2024-06-01T12:00:00Z/2024-06-01T12:01:00Z")
                .unwrap();

        let totals =
            aw_query::query(&category_totals_query(&canonical), &interval, &datastore).unwrap();
        let totals = serde_json::to_value(totals).unwrap();
        assert_eq!(totals["duration"], 30.0);
        assert_eq!(totals["cat_events"][0]["duration"], 30.0);
        assert_eq!(
            totals["cat_events"][0]["data"]["$category"],
            serde_json::json!(["Meeting"])
        );

        let status =
            aw_query::query(&active_status_query(&canonical), &interval, &datastore).unwrap();
        let status = serde_json::to_value(status).unwrap();
        assert_eq!(status["duration"], 30.0);
    }

    fn global_coverage_source(
        source_id: &str,
        bucket_id: &str,
        fields: &[&str],
    ) -> ActivityCoverageSource {
        ActivityCoverageSource {
            source_id: source_id.to_string(),
            bucket_ids: vec![bucket_id.to_string()],
            fields: fields.iter().map(|field| (*field).to_string()).collect(),
            keeps_active: false,
            scope: Some(SourceScope::Global),
            bucket_hosts: BTreeMap::new(),
            host: None,
            interval_policy: IntervalPolicy::Exact,
        }
    }

    #[test]
    fn test_combining_browser_family_buckets_before_projection_preserves_latest_event() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        let timestamp = chrono::DateTime::parse_from_rfc3339("2024-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for bucket_id in ["coverage", "browser-single", "browser-old", "browser-new"] {
            datastore
                .create_bucket(&aw_models::Bucket {
                    bid: None,
                    id: bucket_id.to_string(),
                    _type: "test".to_string(),
                    client: "test".to_string(),
                    hostname: "test".to_string(),
                    created: Some(timestamp),
                    data: serde_json::Map::new(),
                    metadata: aw_models::BucketMetadata::default(),
                    events: None,
                    last_updated: None,
                })
                .unwrap();
        }
        let event = |offset, duration, url: Option<&str>| {
            aw_models::Event::new(
                timestamp + chrono::Duration::seconds(offset),
                chrono::Duration::seconds(duration),
                serde_json::Map::from_iter([(
                    if url.is_some() { "url" } else { "app" }.to_string(),
                    serde_json::json!(url.unwrap_or("Chrome")),
                )]),
            )
        };
        datastore
            .insert_events("coverage", &[event(30, 10, None)])
            .unwrap();
        datastore
            .insert_events(
                "browser-single",
                &[
                    event(0, 100, Some("https://old.example")),
                    event(20, 40, Some("https://new.example")),
                ],
            )
            .unwrap();
        datastore
            .insert_events("browser-old", &[event(0, 100, Some("https://old.example"))])
            .unwrap();
        datastore
            .insert_events("browser-new", &[event(20, 40, Some("https://new.example"))])
            .unwrap();
        let interval =
            aw_models::TimeInterval::new_from_string("2024-06-01T12:00:00Z/2024-06-01T12:02:00Z")
                .unwrap();

        for bucket_ids in [
            vec!["browser-single"],
            vec!["browser-old", "browser-new"],
            vec!["browser-new", "browser-old"],
        ] {
            let loads = bucket_ids
                .iter()
                .map(|bucket_id| {
                    format!("browser = concat(browser, flood(query_bucket(\"{bucket_id}\")));")
                })
                .collect::<Vec<_>>()
                .join("\n");
            let generated = format!(
                "events = query_bucket(\"coverage\");\nbrowser = [];\n{loads}\nbrowser = sort_by_timestamp(browser);\nevents = merge_subwatcher_fields(events, browser, [\"url\"]);\nRETURN = events;"
            );
            let result = aw_query::query(&generated, &interval, &datastore).unwrap();
            let events = Vec::<aw_models::Event>::try_from(&result).unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(
                events[0].timestamp,
                timestamp + chrono::Duration::seconds(30)
            );
            assert_eq!(events[0].duration, chrono::Duration::seconds(10));
            assert_eq!(
                events[0].data["url"],
                serde_json::json!("https://new.example")
            );
        }
    }

    #[test]
    fn test_context_enrichment_preserves_latest_overlapping_source_event() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        let timestamp = chrono::DateTime::parse_from_rfc3339("2024-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for bucket_id in ["overlap-coverage", "overlap-context"] {
            datastore
                .create_bucket(&aw_models::Bucket {
                    bid: None,
                    id: bucket_id.to_string(),
                    _type: "test".to_string(),
                    client: "test".to_string(),
                    hostname: "test".to_string(),
                    created: Some(timestamp),
                    data: serde_json::Map::new(),
                    metadata: aw_models::BucketMetadata::default(),
                    events: None,
                    last_updated: None,
                })
                .unwrap();
        }
        datastore
            .insert_events(
                "overlap-coverage",
                &[aw_models::Event::new(
                    timestamp + chrono::Duration::seconds(30),
                    chrono::Duration::seconds(10),
                    serde_json::Map::from_iter([("label".to_string(), serde_json::json!("base"))]),
                )],
            )
            .unwrap();
        datastore
            .insert_events(
                "overlap-context",
                &[
                    aw_models::Event::new(
                        timestamp,
                        chrono::Duration::seconds(100),
                        serde_json::Map::from_iter([(
                            "name".to_string(),
                            serde_json::json!("older-long"),
                        )]),
                    ),
                    aw_models::Event::new(
                        timestamp + chrono::Duration::seconds(20),
                        chrono::Duration::seconds(40),
                        serde_json::Map::from_iter([(
                            "name".to_string(),
                            serde_json::json!("newer-short"),
                        )]),
                    ),
                ],
            )
            .unwrap();

        let coverage = global_coverage_source("coverage", "overlap-coverage", &["label"]);
        let context = ContextSource {
            source_id: "context".to_string(),
            bucket_ids: vec!["overlap-context".to_string()],
            scope: Some(SourceScope::Global),
            bucket_hosts: BTreeMap::new(),
            fields: vec!["name".to_string()],
            conflict: "base_wins".to_string(),
            host: None,
            interval_policy: IntervalPolicy::Exact,
        };
        let capabilities = vec![CONTEXT_ENRICHMENT_CAPABILITY.to_string()];
        let v2_query = try_build_canonical_events_v2(&CanonicalQueryV2Options {
            activity_coverage_sources: vec![coverage.clone()],
            context_sources: vec![context.clone()],
            capabilities: capabilities.clone(),
            filter_afk: false,
            ..CanonicalQueryV2Options::default()
        })
        .unwrap();
        let legacy_query = try_build_desktop_canonical_events_with_options(
            &DesktopQueryParams {
                base: QueryParamsBase {
                    bid_browsers: vec![],
                    classes: vec![],
                    filter_classes: vec![],
                    filter_afk: false,
                    include_audible: false,
                },
                bid_window: String::new(),
                bid_afk: String::new(),
                always_active_pattern: None,
            },
            &AdvancedQueryOptions {
                activity_coverage_sources: vec![coverage],
                context_sources: vec![context],
                capabilities,
                ..AdvancedQueryOptions::default()
            },
        )
        .unwrap();
        let interval =
            aw_models::TimeInterval::new_from_string("2024-06-01T12:00:00Z/2024-06-01T12:02:00Z")
                .unwrap();

        for generated in [v2_query, legacy_query] {
            assert!(!generated.contains("context_0 = filter_period_intersect(context_0, events)"));
            let result = aw_query::query(
                &format!("{generated}; return events;"),
                &interval,
                &datastore,
            )
            .unwrap();
            let events = Vec::<aw_models::Event>::try_from(&result).unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(
                events[0].timestamp,
                timestamp + chrono::Duration::seconds(30)
            );
            assert_eq!(events[0].duration, chrono::Duration::seconds(10));
            assert_eq!(
                events[0].data["$source.coverage.label"],
                serde_json::json!("base")
            );
            assert_eq!(
                events[0].data["$source.context.name"],
                serde_json::json!("newer-short")
            );
        }
    }

    #[test]
    fn test_v2_meeting_only_coverage_needs_no_window_or_afk() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        insert_v2_test_event(
            &datastore,
            "meeting",
            serde_json::Map::from_iter([("subject".to_string(), serde_json::json!("Planning"))]),
        );
        let options = CanonicalQueryV2Options {
            activity_coverage_sources: vec![global_coverage_source(
                "meeting",
                "meeting",
                &["subject"],
            )],
            capabilities: vec![CONTEXT_ENRICHMENT_CAPABILITY.to_string()],
            filter_afk: false,
            ..CanonicalQueryV2Options::default()
        };

        let query = try_build_canonical_events_v2(&options).unwrap();
        assert!(!query.contains("find_bucket"));
        assert!(query.contains("not_afk = filter_period_intersect(not_afk, coverage)"));
        let events = run_v2_query(&datastore, &options);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].data["$source.meeting.subject"],
            serde_json::json!("Planning")
        );
        assert_eq!(events[0].data.len(), 1);
    }

    #[test]
    fn test_v2_stopwatch_like_coverage_keeps_only_namespaced_facts() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        insert_v2_test_event(
            &datastore,
            "stopwatch",
            serde_json::Map::from_iter([("label".to_string(), serde_json::json!("Focused work"))]),
        );
        let options = CanonicalQueryV2Options {
            activity_coverage_sources: vec![global_coverage_source(
                "stopwatch",
                "stopwatch",
                &["label"],
            )],
            capabilities: vec![CONTEXT_ENRICHMENT_CAPABILITY.to_string()],
            filter_afk: false,
            ..CanonicalQueryV2Options::default()
        };

        let events = run_v2_query(&datastore, &options);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data.len(), 1);
        assert_eq!(
            events[0].data["$source.stopwatch.label"],
            serde_json::json!("Focused work")
        );
    }

    #[test]
    fn test_v2_unreferenced_currentwindow_is_inert() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        insert_v2_test_event(
            &datastore,
            "meeting",
            serde_json::Map::from_iter([("subject".to_string(), serde_json::json!("Planning"))]),
        );
        insert_v2_test_event(
            &datastore,
            "currentwindow",
            serde_json::Map::from_iter([
                ("app".to_string(), serde_json::json!("editor")),
                ("title".to_string(), serde_json::json!("secret.rs")),
            ]),
        );
        let options = CanonicalQueryV2Options {
            activity_coverage_sources: vec![global_coverage_source(
                "meeting",
                "meeting",
                &["subject"],
            )],
            capabilities: vec![CONTEXT_ENRICHMENT_CAPABILITY.to_string()],
            filter_afk: false,
            ..CanonicalQueryV2Options::default()
        };

        let query = try_build_canonical_events_v2(&options).unwrap();
        assert!(!query.contains("currentwindow"));
        let events = run_v2_query(&datastore, &options);
        assert_eq!(events.len(), 1);
        assert!(!events[0].data.contains_key("app"));
        assert!(!events[0].data.contains_key("title"));
        assert!(!events[0]
            .data
            .keys()
            .any(|key| key.contains("currentwindow")));
    }

    #[test]
    fn test_v2_explicit_window_source_is_namespaced_only() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        insert_v2_test_event(
            &datastore,
            "currentwindow",
            serde_json::Map::from_iter([
                ("app".to_string(), serde_json::json!("editor")),
                ("title".to_string(), serde_json::json!("project.rs")),
            ]),
        );
        let options = CanonicalQueryV2Options {
            activity_coverage_sources: vec![global_coverage_source(
                "window",
                "currentwindow",
                &["app", "title"],
            )],
            capabilities: vec![CONTEXT_ENRICHMENT_CAPABILITY.to_string()],
            filter_afk: false,
            ..CanonicalQueryV2Options::default()
        };

        let events = run_v2_query(&datastore, &options);
        assert_eq!(events.len(), 1);
        assert!(!events[0].data.contains_key("app"));
        assert!(!events[0].data.contains_key("title"));
        assert_eq!(
            events[0].data["$source.window.app"],
            serde_json::json!("editor")
        );
        assert_eq!(
            events[0].data["$source.window.title"],
            serde_json::json!("project.rs")
        );
    }

    #[test]
    fn test_v2_keeps_configured_coverage_active() {
        let mut manual = global_coverage_source("manual", "manual", &["label"]);
        manual.keeps_active = true;
        let options = CanonicalQueryV2Options {
            activity_coverage_sources: vec![manual],
            active_time_rule: Some(serde_json::json!({
                "type": "regex",
                "source": "afk",
                "field": "status",
                "regex": "not-afk"
            })),
            active_time_sources: vec![ActiveTimeSource {
                source_id: "afk".to_string(),
                bucket_ids: vec!["afk".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                host: None,
                interval_policy: IntervalPolicy::Exact,
            }],
            capabilities: vec![
                CONTEXT_ENRICHMENT_CAPABILITY.to_string(),
                ACTIVE_PERIODS_V2_CAPABILITY.to_string(),
            ],
            ..CanonicalQueryV2Options::default()
        };

        let query = try_build_canonical_events_v2(&options).unwrap();
        let override_index = query
            .find("not_afk = period_union(not_afk, coverage_period_0)")
            .unwrap();
        let normalize_index = query.find("not_afk = period_union(not_afk, [])").unwrap();
        let mask_index = query
            .find("events = filter_period_intersect(events, not_afk)")
            .unwrap();
        assert!(override_index < normalize_index);
        assert!(normalize_index < mask_index);
    }

    #[test]
    fn test_v2_context_and_active_time_sources_cannot_create_coverage() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        insert_v2_test_event(
            &datastore,
            "context",
            serde_json::Map::from_iter([(
                "project".to_string(),
                serde_json::json!("activitywatch"),
            )]),
        );
        insert_v2_test_event(
            &datastore,
            "presence",
            serde_json::Map::from_iter([("state".to_string(), serde_json::json!("active"))]),
        );

        let context_only = CanonicalQueryV2Options {
            context_sources: vec![ContextSource {
                source_id: "context".to_string(),
                bucket_ids: vec!["context".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                fields: vec!["project".to_string()],
                conflict: "base_wins".to_string(),
                host: None,
                interval_policy: IntervalPolicy::Exact,
            }],
            capabilities: vec![CONTEXT_ENRICHMENT_CAPABILITY.to_string()],
            filter_afk: false,
            ..CanonicalQueryV2Options::default()
        };
        assert!(run_v2_query(&datastore, &context_only).is_empty());

        let active_only = CanonicalQueryV2Options {
            active_time_rule: Some(serde_json::json!({
                "type": "regex",
                "source": "presence",
                "field": "state",
                "regex": "^active$"
            })),
            active_time_sources: vec![ActiveTimeSource {
                source_id: "presence".to_string(),
                bucket_ids: vec!["presence".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                host: None,
                interval_policy: IntervalPolicy::Exact,
            }],
            capabilities: vec![ACTIVE_PERIODS_V2_CAPABILITY.to_string()],
            ..CanonicalQueryV2Options::default()
        };
        assert!(run_v2_query(&datastore, &active_only).is_empty());
    }

    #[test]
    fn test_v2_options_reject_every_legacy_source_path() {
        for field in [
            "bid_window",
            "bid_afk",
            "bid_browsers",
            "bid_stopwatch",
            "always_active_pattern",
            "legacy_window_mode",
            "legacy_window_fields",
            "activity_sources",
            "background_sources",
        ] {
            let mut value = serde_json::json!({});
            value
                .as_object_mut()
                .unwrap()
                .insert(field.to_string(), serde_json::json!([]));
            assert!(
                serde_json::from_value::<CanonicalQueryV2Options>(value).is_err(),
                "v2 options unexpectedly accepted {field}"
            );
        }

        let query = try_build_canonical_events_v2(&CanonicalQueryV2Options {
            filter_afk: false,
            ..CanonicalQueryV2Options::default()
        })
        .unwrap();
        assert!(query.contains("events = coverage"));
        assert!(!query.contains("find_bucket"));
        assert!(!query.contains("map_event_fields"));
    }

    #[test]
    fn test_current_legacy_adapter_reuses_focused_browser_for_audible_activity() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        let timestamp = chrono::DateTime::parse_from_rfc3339("2024-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for (bucket_id, bucket_type) in [
            ("aw-watcher-window_imported", "currentwindow"),
            ("aw-watcher-afk_imported", "afkstatus"),
            ("aw-watcher-web-chrome_imported", "web.tab.current"),
        ] {
            datastore
                .create_bucket(&aw_models::Bucket {
                    bid: None,
                    id: bucket_id.to_string(),
                    _type: bucket_type.to_string(),
                    client: "test".to_string(),
                    hostname: "host-a".to_string(),
                    created: Some(timestamp),
                    data: serde_json::Map::new(),
                    metadata: aw_models::BucketMetadata::default(),
                    events: None,
                    last_updated: None,
                })
                .unwrap();
        }
        let event = |data| aw_models::Event::new(timestamp, chrono::Duration::seconds(20), data);
        datastore
            .insert_events(
                "aw-watcher-window_imported",
                &[event(serde_json::Map::from_iter([
                    ("app".to_string(), serde_json::json!("Google Chrome")),
                    ("title".to_string(), serde_json::json!("Focused")),
                ]))],
            )
            .unwrap();
        datastore
            .insert_events(
                "aw-watcher-afk_imported",
                &[event(serde_json::Map::from_iter([(
                    "status".to_string(),
                    serde_json::json!("afk"),
                )]))],
            )
            .unwrap();
        datastore
            .insert_events(
                "aw-watcher-web-chrome_imported",
                &[event(serde_json::Map::from_iter([
                    ("url".to_string(), serde_json::json!("https://example.test")),
                    ("title".to_string(), serde_json::json!("Page")),
                    ("audible".to_string(), serde_json::json!(true)),
                ]))],
            )
            .unwrap();

        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec!["aw-watcher-web-chrome_imported".to_string()],
                classes: vec![],
                filter_classes: vec![],
                filter_afk: true,
                include_audible: true,
            },
            bid_window: "aw-watcher-window_".to_string(),
            bid_afk: "aw-watcher-afk_".to_string(),
            always_active_pattern: None,
        };
        let options = AdvancedQueryOptions {
            hostname: Some("host-a".to_string()),
            capabilities: vec![
                OPTIONAL_BUCKET_RAW_CAPABILITY.to_string(),
                QUERY_PERIOD_CAPABILITY.to_string(),
                FLOOD_V2_CAPABILITY.to_string(),
                CONTEXT_ENRICHMENT_CAPABILITY.to_string(),
                ACTIVE_PERIODS_V2_CAPABILITY.to_string(),
                CATEGORIZE_V2_CAPABILITY.to_string(),
            ],
            ..AdvancedQueryOptions::default()
        };
        let generated = adapt_legacy_desktop_to_current_v2(&params, &options).unwrap();
        assert!(generated.contains(
            "query_bucket_optional_raw(find_bucket(\"aw-watcher-window_\", \"host-a\"), \"host-a\", 5)"
        ));
        assert!(generated.contains(
            "query_bucket_optional_raw(find_bucket(\"aw-watcher-afk_\", \"host-a\"), \"host-a\", 5)"
        ));
        assert_eq!(
            generated
                .matches("query_bucket_optional_raw(\"aw-watcher-web-chrome_imported\"")
                .count(),
            1
        );
        let interval =
            aw_models::TimeInterval::new_from_string("2024-06-01T12:00:00Z/2024-06-01T12:00:20Z")
                .unwrap();
        for variable in ["events", "browser_events"] {
            let result = aw_query::query(
                &format!("{generated}; return {variable};"),
                &interval,
                &datastore,
            )
            .unwrap();
            let events = Vec::<aw_models::Event>::try_from(&result).unwrap();
            assert_eq!(events.len(), 1, "{variable} should retain audible activity");
        }

        let mut without_audible = params.clone();
        without_audible.base.include_audible = false;
        let generated = adapt_legacy_desktop_to_current_v2(&without_audible, &options).unwrap();
        let result = aw_query::query(
            &format!("{generated}; return events;"),
            &interval,
            &datastore,
        )
        .unwrap();
        assert!(Vec::<aw_models::Event>::try_from(&result)
            .unwrap()
            .is_empty());
        let result = aw_query::query(
            &format!("{generated}; return browser_events;"),
            &interval,
            &datastore,
        )
        .unwrap();
        assert!(Vec::<aw_models::Event>::try_from(&result)
            .unwrap()
            .is_empty());

        let mut custom_options = options.clone();
        custom_options.active_time_rule = Some(serde_json::json!({"type": "none"}));
        let generated = adapt_legacy_desktop_to_current_v2(&params, &custom_options).unwrap();
        assert!(!generated.contains("\"field\":\"audible\""));
        assert!(generated.contains("browser_chrome = split_url_events(browser_resolved_chrome)"));
        assert!(!generated.contains("active_source_0 = filter_period_intersect"));

        for bucket_id in ["aw-watcher-web-chrome-a", "aw-watcher-web-chrome-z"] {
            datastore
                .create_bucket(&aw_models::Bucket {
                    bid: None,
                    id: bucket_id.to_string(),
                    _type: "web.tab.current".to_string(),
                    client: "test".to_string(),
                    hostname: "host-a".to_string(),
                    created: Some(timestamp),
                    data: serde_json::Map::new(),
                    metadata: aw_models::BucketMetadata::default(),
                    events: None,
                    last_updated: None,
                })
                .unwrap();
        }
        datastore
            .insert_events(
                "aw-watcher-web-chrome-a",
                &[event(serde_json::Map::from_iter([(
                    "audible".to_string(),
                    serde_json::json!(true),
                )]))],
            )
            .unwrap();
        datastore
            .insert_events(
                "aw-watcher-web-chrome-z",
                &[event(serde_json::Map::from_iter([(
                    "audible".to_string(),
                    serde_json::json!(false),
                )]))],
            )
            .unwrap();
        let mut family_params = params.clone();
        family_params.base.bid_browsers = vec![
            "aw-watcher-web-chrome-a".to_string(),
            "aw-watcher-web-chrome-z".to_string(),
        ];
        let generated = adapt_legacy_desktop_to_current_v2(&family_params, &options).unwrap();
        assert_eq!(generated.matches("active_source_1_raw = concat").count(), 2);
        let result = aw_query::query(
            &format!("{generated}; return events;"),
            &interval,
            &datastore,
        )
        .unwrap();
        assert!(Vec::<aw_models::Event>::try_from(&result)
            .unwrap()
            .is_empty());

        let mut missing_params = params.clone();
        missing_params.base.include_audible = false;
        missing_params.base.bid_browsers = vec!["aw-watcher-web-chrome-missing".to_string()];
        let generated = adapt_legacy_desktop_to_current_v2(&missing_params, &options).unwrap();
        let result = aw_query::query(
            &format!("{generated}; return browser_events;"),
            &interval,
            &datastore,
        )
        .unwrap();
        assert!(Vec::<aw_models::Event>::try_from(&result)
            .unwrap()
            .is_empty());

        datastore
            .create_bucket(&aw_models::Bucket {
                bid: None,
                id: "meeting".to_string(),
                _type: "meeting".to_string(),
                client: "test".to_string(),
                hostname: "host-a".to_string(),
                created: Some(timestamp),
                data: serde_json::Map::new(),
                metadata: aw_models::BucketMetadata::default(),
                events: None,
                last_updated: None,
            })
            .unwrap();
        datastore
            .insert_events(
                "meeting",
                &[aw_models::Event::new(
                    timestamp + chrono::Duration::seconds(5),
                    chrono::Duration::seconds(5),
                    serde_json::Map::from_iter([(
                        "subject".to_string(),
                        serde_json::json!("Planning"),
                    )]),
                )],
            )
            .unwrap();
        let mut context_options = options.clone();
        context_options.legacy_window_mode = LegacyWindowMode::Context;
        context_options.activity_coverage_sources = vec![ActivityCoverageSource {
            source_id: "meeting".to_string(),
            bucket_ids: vec!["meeting".to_string()],
            fields: vec!["subject".to_string()],
            keeps_active: true,
            scope: Some(SourceScope::Global),
            bucket_hosts: BTreeMap::new(),
            host: None,
            interval_policy: IntervalPolicy::Exact,
        }];
        let generated = adapt_legacy_desktop_to_current_v2(&params, &context_options).unwrap();
        for variable in ["events", "browser_events"] {
            let result = aw_query::query(
                &format!("{generated}; return {variable};"),
                &interval,
                &datastore,
            )
            .unwrap();
            let events = Vec::<aw_models::Event>::try_from(&result).unwrap();
            assert_eq!(events.len(), 1, "{variable}");
            assert_eq!(events[0].duration, chrono::Duration::seconds(5));
        }
    }

    #[test]
    fn test_current_legacy_adapter_classifies_windowless_coverage_and_restores_namespaces() {
        let capabilities = vec![
            OPTIONAL_BUCKET_RAW_CAPABILITY.to_string(),
            QUERY_PERIOD_CAPABILITY.to_string(),
            FLOOD_V2_CAPABILITY.to_string(),
            CONTEXT_ENRICHMENT_CAPABILITY.to_string(),
            ACTIVE_PERIODS_V2_CAPABILITY.to_string(),
            CATEGORIZE_V2_CAPABILITY.to_string(),
        ];
        let meeting = global_coverage_source("meeting", "meeting-imported", &["project"]);
        let options = AdvancedQueryOptions {
            hostname: Some("host-a".to_string()),
            category_specs: Some(vec![serde_json::json!({
                "id": "work",
                "name": ["Work"],
                "rule": {
                    "type": "regex",
                    "source": "meeting",
                    "field": "project",
                    "regex": "^Alpha$"
                }
            })]),
            activity_coverage_sources: vec![meeting.clone()],
            capabilities: capabilities.clone(),
            ..AdvancedQueryOptions::default()
        };
        let windowless = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![],
                filter_classes: vec![vec!["Work".to_string()]],
                filter_afk: false,
                include_audible: false,
            },
            bid_window: String::new(),
            bid_afk: String::new(),
            always_active_pattern: None,
        };
        let generated = adapt_legacy_desktop_to_current_v2(&windowless, &options).unwrap();
        assert!(generated.contains("events = categorize_v2(events"));
        assert!(generated.contains("events = filter_keyvals(events, \"$category\""));
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        let timestamp = chrono::DateTime::parse_from_rfc3339("2024-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        datastore
            .create_bucket(&aw_models::Bucket {
                bid: None,
                id: "meeting-imported".to_string(),
                _type: "meeting".to_string(),
                client: "test".to_string(),
                hostname: "host-a".to_string(),
                created: Some(timestamp),
                data: serde_json::Map::new(),
                metadata: aw_models::BucketMetadata::default(),
                events: None,
                last_updated: None,
            })
            .unwrap();
        datastore
            .insert_events(
                "meeting-imported",
                &[aw_models::Event::new(
                    timestamp,
                    chrono::Duration::seconds(20),
                    serde_json::Map::from_iter([(
                        "project".to_string(),
                        serde_json::json!("Alpha"),
                    )]),
                )],
            )
            .unwrap();
        let interval =
            aw_models::TimeInterval::new_from_string("2024-06-01T12:00:00Z/2024-06-01T12:00:20Z")
                .unwrap();
        let result = aw_query::query(
            &format!("{generated}; return events;"),
            &interval,
            &datastore,
        )
        .unwrap();
        let events = Vec::<aw_models::Event>::try_from(&result).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data["$category"], serde_json::json!(["Work"]));
        assert_eq!(
            events[0].data["$source.meeting.project"],
            serde_json::json!("Alpha")
        );

        let with_window = DesktopQueryParams {
            bid_window: "aw-watcher-window_".to_string(),
            bid_afk: "aw-watcher-afk_".to_string(),
            ..windowless
        };
        let projected = adapt_legacy_desktop_to_current_v2(&with_window, &options).unwrap();
        let reset = projected.find("events = period_union([], events)").unwrap();
        let restored = projected[reset..]
            .find("merge_subwatcher_fields(events, coverage_source_1, [\"project\"], {\"conflict\":\"base_wins\",\"source_id\":\"meeting\"})")
            .unwrap();
        assert!(restored > 0);

        let mut always_active = with_window.clone();
        always_active.always_active_pattern = Some("meeting".to_string());
        let generated = adapt_legacy_desktop_to_current_v2(&always_active, &options).unwrap();
        assert_eq!(
            generated
                .matches("find_bucket(\"aw-watcher-window_\", \"host-a\")")
                .count(),
            1,
            "always-active must alias the loaded window stream"
        );
    }

    #[test]
    fn test_empty_bucket_host_maps_are_omitted_from_serialized_sources() {
        let source = ContextSource {
            source_id: "global".to_string(),
            bucket_ids: vec!["global-bucket".to_string()],
            scope: Some(SourceScope::Global),
            bucket_hosts: BTreeMap::new(),
            fields: vec!["title".to_string()],
            conflict: "base_wins".to_string(),
            host: None,
            interval_policy: IntervalPolicy::Exact,
        };

        let serialized = serde_json::to_value(source).unwrap();
        assert!(serialized.get("bucket_hosts").is_none());
    }
    #[test]
    fn public_desktop_wrappers_use_the_current_pipeline_by_default() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: Vec::new(),
                classes: Vec::new(),
                filter_classes: Vec::new(),
                filter_afk: false,
                include_audible: true,
            },
            bid_window: "window".to_string(),
            bid_afk: "afk".to_string(),
            always_active_pattern: None,
        };
        let direct = build_desktop_canonical_events(&params);
        let enum_query = QueryParams::Desktop(params.clone()).canonical_events();
        let options_query = try_build_desktop_canonical_events_with_options(
            &params,
            &AdvancedQueryOptions::default(),
        )
        .unwrap();
        let full_query = full_desktop_query(&params);
        for query in [&direct, &enum_query, &options_query, &full_query] {
            assert!(query.contains("query_bucket_optional_raw"));
            assert!(query.contains("query_period()"));
            assert!(!query.contains("legacy_activity = flood"));
            assert!(query.contains("Uncategorized"));
        }
    }

    #[test]
    fn explicit_legacy_module_owns_the_old_query_grammar() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: Vec::new(),
                classes: crate::classes::default_classes(),
                filter_classes: Vec::new(),
                filter_afk: false,
                include_audible: true,
            },
            bid_window: "window".to_string(),
            bid_afk: "afk".to_string(),
            always_active_pattern: None,
        };
        let query = legacy_v1::desktop(&params).unwrap();
        assert!(query.contains("legacy_activity = flood"));
        assert!(!query.contains("query_bucket_optional_raw"));
    }
}
