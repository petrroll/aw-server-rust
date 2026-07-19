//! Query building utilities for ActivityWatch
//!
//! This module provides functionality to build canonical queries that are compatible
//! with the ActivityWatch query language. It includes support for:
//!
//! - Desktop and Android query parameters
//! - Server-side categorization classes fetching
//! - Browser events integration
//! - AFK filtering
//!
//! ## Server-side Classes
//!
//! The queries can automatically fetch categorization classes from the ActivityWatch server:
//!
//! ```rust
//! use aw_client_rust::queries::{DesktopQueryParams, QueryParams, QueryParamsBase};
//!
//! let params = DesktopQueryParams {
//!     base: QueryParamsBase {
//!         bid_browsers: vec![],
//!         classes: vec![], // Empty - will fetch from server
//!         filter_classes: vec![],
//!         filter_afk: true,
//!         include_audible: true,
//!     },
//!     bid_window: "aw-watcher-window_example".to_string(),
//!     bid_afk: "aw-watcher-afk_example".to_string(),
//!     always_active_pattern: None,
//! };
//!
//! // Automatically fetches classes from localhost:5600
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

pub const DEFAULT_LIMIT: u32 = 100;
pub const CATEGORIZE_V2_CAPABILITY: &str = "query.categorize_v2.v1";
pub const CONTEXT_ENRICHMENT_CAPABILITY: &str = "query.merge_subwatcher_fields.source_namespace.v1";
pub const ACTIVE_PERIODS_V2_CAPABILITY: &str = "query.active_periods_v2.v1";
pub const MAP_EVENT_FIELDS_CAPABILITY: &str = "query.map_event_fields.v1";
pub const OPTIONAL_BUCKET_HOSTNAME_CAPABILITY: &str =
    "query.query_bucket_optional.expected_hostname.v1";

/// Type alias for categorization classes
pub type ClassRule = (CategoryId, CategorySpec);

/// Ownership scope for a configured bucket source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceScope {
    Host,
    Global,
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
}

/// A source whose event periods contribute to abstract activity coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityCoverageSource {
    pub source_id: String,
    pub bucket_ids: Vec<String>,
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<SourceScope>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bucket_hosts: BTreeMap<String, String>,
    #[serde(default)]
    pub host: Option<String>,
}

/// Optional advanced query features and the server capabilities required by them.
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
    /// Build canonical events query string
    pub fn canonical_events(&self) -> String {
        match self {
            QueryParams::Desktop(params) => build_desktop_canonical_events(params),
            QueryParams::Android(params) => build_android_canonical_events(params),
        }
    }

    /// Build canonical events with validated advanced query options.
    pub fn try_canonical_events_with_options(
        &self,
        options: &AdvancedQueryOptions,
    ) -> Result<String, String> {
        match self {
            QueryParams::Desktop(params) => {
                try_build_desktop_canonical_events_with_options(params, options)
            }
            QueryParams::Android(params) => {
                try_build_android_canonical_events_with_options(params, options)
            }
        }
    }
}

/// Serialize legacy classes using Query2's raw-backslash string grammar.
fn serialize_classes(classes: &[ClassRule]) -> String {
    serialize_query_json(classes)
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
    validate_query_strings(options)?;
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
        if options.active_time_sources.is_empty() {
            return Err("active-time rules require at least one source".to_string());
        }
        validate_active_time_sources(&options.active_time_sources, options.hostname.as_deref())?;
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

fn build_context_events(
    sources: &[ContextSource],
    hostname: Option<&str>,
    enforce_hostname: bool,
) -> Result<String, String> {
    let mut query = Vec::new();

    for (index, source) in sources.iter().enumerate() {
        let variable = format!("context_{index}");
        query.push(format!("{variable} = []"));
        for bucket_id in resolve_source_buckets(
            source.scope,
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            hostname,
            "context",
        )? {
            query.push(format!(
                "{variable} = concat({variable}, flood(query_bucket_optional({}{})))",
                serialize_bucket_id(bucket_id)?,
                expected_source_hostname(source.scope, hostname, enforce_hostname)
            ));
        }
        query.push(format!(
            "{variable} = filter_period_intersect({variable}, events)"
        ));
        let options = serde_json::json!({
            "source_id": source.source_id,
            "conflict": source.conflict,
        });
        query.push(format!(
            "context_fields_{index} = {}",
            serialize_query_json(&source.fields)
        ));
        query.push(format!(
            "context_options_{index} = {}",
            serialize_query_json(&options)
        ));
        query.push(format!(
            "events = merge_subwatcher_fields(events, {variable}, context_fields_{index}, context_options_{index})"
        ));
    }

    Ok(query.join(";\n"))
}

fn build_activity_coverage_events(
    sources: &[ActivityCoverageSource],
    hostname: Option<&str>,
    enforce_hostname: bool,
) -> Result<String, String> {
    let mut query = Vec::new();

    for (index, source) in sources.iter().enumerate() {
        let variable = format!("activity_coverage_source_{index}");
        query.push(format!("{variable} = []"));
        for (bucket_index, bucket_id) in resolve_source_buckets(
            source.scope,
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            hostname,
            "activity coverage",
        )?
        .into_iter()
        .enumerate()
        {
            let bucket_variable = format!("activity_coverage_bucket_{index}_{bucket_index}");
            query.push(format!(
                "{bucket_variable} = flood(query_bucket_optional({}{}))",
                serialize_bucket_id(bucket_id)?,
                expected_source_hostname(source.scope, hostname, enforce_hostname)
            ));
            query.push(format!(
                "{variable} = union_no_overlap({variable}, {bucket_variable})"
            ));
        }
        query.push(format!(
            "activity_coverage_period_{index} = filter_period_intersect({variable}, {variable})"
        ));
        query.push(format!(
            "events = period_union(events, activity_coverage_period_{index})"
        ));
    }

    for (index, source) in sources.iter().enumerate() {
        let variable = format!("activity_coverage_source_{index}");
        query.push(format!(
            "{variable} = filter_period_intersect({variable}, events)"
        ));
        query.push(format!(
            "activity_coverage_fields_{index} = {}",
            serialize_query_json(&source.fields)
        ));
        let options = serde_json::json!({
            "source_id": source.source_id,
            "conflict": "base_wins",
        });
        query.push(format!(
            "activity_coverage_options_{index} = {}",
            serialize_query_json(&options)
        ));
        query.push(format!(
            "events = merge_subwatcher_fields(events, {variable}, activity_coverage_fields_{index}, activity_coverage_options_{index})"
        ));
    }

    Ok(query.join(";\n"))
}

fn build_activity_events(
    sources: &[ActivitySource],
    filter_afk: bool,
    hostname: Option<&str>,
    enforce_hostname: bool,
) -> Result<String, String> {
    let mut query = Vec::new();

    for (index, source) in sources.iter().enumerate() {
        let variable = format!("activity_source_{index}");
        query.push(format!("{variable} = []"));
        for (bucket_index, bucket_id) in resolve_source_buckets(
            source.scope,
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            hostname,
            "activity",
        )?
        .into_iter()
        .enumerate()
        {
            let bucket_variable = format!("activity_bucket_{index}_{bucket_index}");
            query.push(format!(
                "{bucket_variable} = flood(query_bucket_optional({}{}))",
                serialize_bucket_id(bucket_id)?,
                expected_source_hostname(source.scope, hostname, enforce_hostname)
            ));
            query.push(format!(
                "{variable} = union_no_overlap({variable}, {bucket_variable})"
            ));
        }
        if filter_afk {
            query.push(format!(
                "{variable} = filter_period_intersect({variable}, not_afk)"
            ));
        }
        if !source.field_mappings.is_empty() {
            query.push(format!(
                "{variable} = map_event_fields({variable}, {})",
                serialize_query_json(&source.field_mappings)
            ));
        }
        query.push(format!("{variable} = sort_by_timestamp({variable})"));
        query.push(format!("events = union_no_overlap({variable}, events)"));
    }

    Ok(query.join(";\n"))
}

fn build_background_events(
    sources: &[ActivitySource],
    hostname: Option<&str>,
    enforce_hostname: bool,
) -> Result<String, String> {
    let mut query = Vec::new();

    for (index, source) in sources.iter().enumerate() {
        let variable = format!("background_source_{index}");
        query.push(format!("{variable} = []"));
        for (bucket_index, bucket_id) in resolve_source_buckets(
            source.scope,
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            hostname,
            "background activity",
        )?
        .into_iter()
        .enumerate()
        {
            let bucket_variable = format!("background_bucket_{index}_{bucket_index}");
            query.push(format!(
                "{bucket_variable} = flood(query_bucket_optional({}{}))",
                serialize_bucket_id(bucket_id)?,
                expected_source_hostname(source.scope, hostname, enforce_hostname)
            ));
            query.push(format!(
                "{variable} = union_no_overlap({variable}, {bucket_variable})"
            ));
        }
        query.push(format!(
            "{variable} = filter_period_intersect({variable}, not_afk)"
        ));
        if !source.field_mappings.is_empty() {
            query.push(format!(
                "{variable} = map_event_fields({variable}, {})",
                serialize_query_json(&source.field_mappings)
            ));
        }
        query.push(format!("{variable} = sort_by_timestamp({variable})"));
        query.push(format!("events = union_no_overlap(events, {variable})"));
    }

    Ok(query.join(";\n"))
}

fn build_active_time_events(
    sources: &[ActiveTimeSource],
    active_time_rule: &serde_json::Value,
    hostname: Option<&str>,
    enforce_hostname: bool,
) -> Result<String, String> {
    let mut query = Vec::new();
    let mut named_sources = Vec::with_capacity(sources.len());

    for (index, source) in sources.iter().enumerate() {
        let variable = format!("active_source_{index}");
        query.push(format!("{variable} = []"));
        for bucket_id in resolve_source_buckets(
            source.scope,
            &source.bucket_ids,
            &source.bucket_hosts,
            source.host.as_deref(),
            hostname,
            "active-time",
        )? {
            query.push(format!(
                "{variable} = concat({variable}, flood(query_bucket_optional({}{})))",
                serialize_bucket_id(bucket_id)?,
                expected_source_hostname(source.scope, hostname, enforce_hostname)
            ));
        }
        named_sources.push(format!(
            "[{}, {variable}]",
            serialize_query_json(&source.source_id)
        ));
    }

    query.push(format!(
        "active_time_rule = {}",
        serialize_query_json(active_time_rule)
    ));
    query.push(format!(
        "active_time_sources = [{}]",
        named_sources.join(", ")
    ));
    query.push(format!(
        "not_afk = active_periods_v2(active_time_sources, active_time_rule{})",
        hostname
            .map(|host| format!(", {}", serialize_query_json(host)))
            .unwrap_or_default()
    ));
    query.push("not_afk = period_union(not_afk, [])".to_string());
    Ok(query.join(";\n"))
}

fn append_enrichment_and_categorization(
    query: &mut Vec<String>,
    options: &AdvancedQueryOptions,
) -> Result<bool, String> {
    let enforce_hostname = options
        .capabilities
        .iter()
        .any(|capability| capability == OPTIONAL_BUCKET_HOSTNAME_CAPABILITY);
    let context_events = build_context_events(
        &options.context_sources,
        options.hostname.as_deref(),
        enforce_hostname,
    )?;
    if !context_events.is_empty() {
        query.push(context_events);
    }
    if let Some(category_specs) = &options.category_specs {
        let host = options
            .hostname
            .as_ref()
            .map(|host| format!(", {}", serialize_query_json(host)))
            .unwrap_or_default();
        query.push(format!(
            "events = categorize_v2(events, {}{host});",
            serialize_query_json(category_specs)
        ));
        return Ok(true);
    }
    Ok(false)
}

/// Build canonical events from explicit sources without assuming a window or legacy AFK bucket.
pub fn try_build_canonical_events(options: &AdvancedQueryOptions) -> Result<String, String> {
    validate_advanced_options(options)?;
    if !options.background_sources.is_empty() && options.active_time_rule.is_none() {
        return Err("Background activity sources require an active-time rule".to_string());
    }

    let mut query = vec!["events = []".to_string()];
    let enforce_hostname = options
        .capabilities
        .iter()
        .any(|capability| capability == OPTIONAL_BUCKET_HOSTNAME_CAPABILITY);
    let coverage_events = build_activity_coverage_events(
        &options.activity_coverage_sources,
        options.hostname.as_deref(),
        enforce_hostname,
    )?;
    if !coverage_events.is_empty() {
        query.push(coverage_events);
    }
    let activity_events = build_activity_events(
        &options.activity_sources,
        false,
        options.hostname.as_deref(),
        enforce_hostname,
    )?;
    if !activity_events.is_empty() {
        query.push(activity_events);
    }
    if let Some(active_time_rule) = &options.active_time_rule {
        query.push(build_active_time_events(
            &options.active_time_sources,
            active_time_rule,
            options.hostname.as_deref(),
            enforce_hostname,
        )?);
        query.push("events = filter_period_intersect(events, not_afk)".to_string());
    }
    let background_events = build_background_events(
        &options.background_sources,
        options.hostname.as_deref(),
        enforce_hostname,
    )?;
    if !background_events.is_empty() {
        query.push(background_events);
    }
    append_enrichment_and_categorization(&mut query, options)?;

    Ok(query.join(";\n"))
}

/// Build a standalone query returning active periods from named sources and a rule.
pub fn try_build_active_time_query(
    sources: &[ActiveTimeSource],
    active_time_rule: &serde_json::Value,
    hostname: Option<&str>,
) -> Result<String, String> {
    try_build_active_time_query_with_capabilities(sources, active_time_rule, hostname, &[])
}

/// Build an active-time query with capability-gated server-side bucket ownership checks.
pub fn try_build_active_time_query_with_capabilities(
    sources: &[ActiveTimeSource],
    active_time_rule: &serde_json::Value,
    hostname: Option<&str>,
    capabilities: &[String],
) -> Result<String, String> {
    if hostname.is_some_and(str::is_empty) {
        return Err("hostname must be non-empty".to_string());
    }
    if sources.is_empty() {
        return Err("active-time rules require at least one source".to_string());
    }
    validate_query_strings(sources)?;
    validate_query_strings(active_time_rule)?;
    validate_active_time_sources(sources, hostname)?;
    let enforce_hostname = capabilities
        .iter()
        .any(|capability| capability == OPTIONAL_BUCKET_HOSTNAME_CAPABILITY);
    Ok(format!(
        "{};\nRETURN = not_afk;",
        build_active_time_events(sources, active_time_rule, hostname, enforce_hostname)?
    ))
}

fn build_legacy_afk_events(bid_afk: &str, hostname: Option<&str>) -> Result<String, String> {
    if bid_afk.is_empty() {
        return Err("legacy AFK bucket id must be non-empty".to_string());
    }
    if hostname.is_some_and(str::is_empty) {
        return Err("hostname must be non-empty".to_string());
    }
    let host = hostname
        .map(|host| format!(", {}", serialize_query_json(host)))
        .unwrap_or_default();
    Ok(format!(
        "not_afk = flood(query_bucket(find_bucket({}{host})));\nnot_afk = filter_keyvals(not_afk, \"status\", [\"not-afk\"])",
        serialize_bucket_id(bid_afk)?
    ))
}

/// Build a standalone legacy AFK query without requiring a window bucket.
pub fn try_build_legacy_afk_query(bid_afk: &str, hostname: Option<&str>) -> Result<String, String> {
    Ok(format!(
        "{};\nRETURN = not_afk;",
        build_legacy_afk_events(bid_afk, hostname)?
    ))
}

pub fn build_desktop_canonical_events(params: &DesktopQueryParams) -> String {
    build_desktop_canonical_events_with_options(params, &AdvancedQueryOptions::default())
        .expect("legacy desktop query parameters are valid")
}

pub fn try_build_desktop_canonical_events_with_options(
    params: &DesktopQueryParams,
    options: &AdvancedQueryOptions,
) -> Result<String, String> {
    validate_query_strings(params)?;
    validate_advanced_options(options)?;
    build_desktop_canonical_events_with_options(params, options)
}

fn build_desktop_canonical_events_with_options(
    params: &DesktopQueryParams,
    options: &AdvancedQueryOptions,
) -> Result<String, String> {
    let mut query = Vec::new();
    let host = options
        .hostname
        .as_ref()
        .map(|host| format!(", {}", serialize_query_json(host)))
        .unwrap_or_default();

    query.push("events = []".to_string());
    let supports_source_namespace = options
        .capabilities
        .iter()
        .any(|capability| capability == CONTEXT_ENRICHMENT_CAPABILITY);
    let enforce_hostname = options
        .capabilities
        .iter()
        .any(|capability| capability == OPTIONAL_BUCKET_HOSTNAME_CAPABILITY);
    if !params.bid_window.is_empty() && options.legacy_window_mode != LegacyWindowMode::None {
        query.push(format!(
            "legacy_activity = flood(query_bucket(find_bucket({}{host})))",
            serialize_bucket_id(&params.bid_window)?,
        ));
        if options.legacy_window_mode == LegacyWindowMode::Activity {
            if supports_source_namespace {
                query.push(
                    "legacy_activity_period = filter_period_intersect(legacy_activity, legacy_activity)"
                        .to_string(),
                );
                query.push("events = period_union(events, legacy_activity_period)".to_string());
            } else {
                query.push("events = legacy_activity".to_string());
            }
        }
    }

    let has_active_time_rule = options.active_time_rule.is_some();
    let coverage_events = build_activity_coverage_events(
        &options.activity_coverage_sources,
        options.hostname.as_deref(),
        enforce_hostname,
    )?;
    if !coverage_events.is_empty() {
        query.push(coverage_events);
    }
    if !params.bid_window.is_empty()
        && options.legacy_window_mode != LegacyWindowMode::None
        && supports_source_namespace
    {
        let legacy_window_fields = if options.legacy_window_fields.is_empty() {
            default_legacy_window_fields()
        } else {
            options.legacy_window_fields.clone()
        };
        query.push(format!(
            "events = merge_subwatcher_fields(events, legacy_activity, {})",
            serde_json::to_string(&legacy_window_fields).unwrap()
        ));
    }
    let activity_events = build_activity_events(
        &options.activity_sources,
        false,
        options.hostname.as_deref(),
        enforce_hostname,
    )?;
    if !activity_events.is_empty() {
        query.push(activity_events);
    }

    let needs_not_afk = params.base.filter_afk
        || !options.background_sources.is_empty()
        || options.active_time_rule.is_some();

    // Fetch or compile not-afk events
    if needs_not_afk {
        if let Some(active_time_rule) = &options.active_time_rule {
            query.push(build_active_time_events(
                &options.active_time_sources,
                active_time_rule,
                options.hostname.as_deref(),
                enforce_hostname,
            )?);
        } else {
            let mut not_afk_query =
                build_legacy_afk_events(&params.bid_afk, options.hostname.as_deref())?;

            // Add treat_as_active functionality if pattern is provided
            if let Some(ref pattern) = params.always_active_pattern {
                let pattern = serialize_query_json(pattern);
                not_afk_query.push_str(&format!(
                    ";
not_treat_as_afk = filter_keyvals_regex(events, \"app\", {});
not_afk = period_union(not_afk, not_treat_as_afk);
not_treat_as_afk = filter_keyvals_regex(events, \"title\", {});
not_afk = period_union(not_afk, not_treat_as_afk)",
                    pattern, pattern
                ));
            }

            query.push(not_afk_query);
        }
    } else {
        query.push("not_afk = []".to_string());
    }

    // Add browser events if any browser buckets specified
    if !params.base.bid_browsers.is_empty() {
        query.push(try_build_browser_events(params)?);

        if params.base.include_audible && !has_active_time_rule && needs_not_afk {
            query.push(
                "audible_events = filter_keyvals(browser_events, \"audible\", [true]);
not_afk = period_union(not_afk, audible_events)"
                    .to_string(),
            );
        }
    }

    // Filter out window events when user was AFK
    if params.base.filter_afk {
        query.push("events = filter_period_intersect(events, not_afk)".to_string());
    }

    let background_events = build_background_events(
        &options.background_sources,
        options.hostname.as_deref(),
        enforce_hostname,
    )?;
    if !background_events.is_empty() {
        query.push(background_events);
    }

    // Enrich and categorize after AFK filtering.
    let used_v2_categories = append_enrichment_and_categorization(&mut query, options)?;
    if !used_v2_categories && !params.base.classes.is_empty() {
        query.push(format!(
            "events = categorize(events, {});",
            serialize_classes(&params.base.classes)
        ));
    }

    // Filter categories if specified
    if !params.base.filter_classes.is_empty() {
        query.push(format!(
            "events = filter_keyvals(events, \"$category\", {})",
            serialize_query_json(&params.base.filter_classes)
        ));
    }

    Ok(query.join(";\n"))
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
    let mut query = Vec::new();
    let host = options
        .hostname
        .as_ref()
        .map(|host| format!(", {}", serialize_query_json(host)))
        .unwrap_or_default();

    // Fetch app events
    query.push(format!(
        "events = flood(query_bucket(find_bucket({}{host})))",
        serialize_bucket_id(&params.bid_android)?,
    ));

    // Preserve source intervals until report-level aggregation.
    let used_v2_categories = append_enrichment_and_categorization(&mut query, options)?;
    if !used_v2_categories && !params.base.classes.is_empty() {
        query.push(format!(
            "events = categorize(events, {});",
            serialize_classes(&params.base.classes)
        ));
    }

    // Filter categories if specified
    if !params.base.filter_classes.is_empty() {
        query.push(format!(
            "events = filter_keyvals(events, \"$category\", {})",
            serialize_query_json(&params.base.filter_classes)
        ));
    }

    Ok(query.join(";\n"))
}

pub fn try_build_browser_events(params: &DesktopQueryParams) -> Result<String, String> {
    let mut query = String::from("browser_events = [];");

    for browser_bucket in &params.base.bid_browsers {
        for (browser_name, app_names) in BROWSER_APPNAMES.entries() {
            if browser_bucket.contains(browser_name) {
                query.push_str(&format!(
                    "
events_{0} = flood(query_bucket({1}));
window_{0} = filter_keyvals(events, \"app\", {2});
events_{0} = filter_period_intersect(events_{0}, window_{0});
events_{0} = split_url_events(events_{0});
browser_events = concat(browser_events, events_{0});
browser_events = sort_by_timestamp(browser_events)",
                    browser_name,
                    serialize_bucket_id(browser_bucket)?,
                    serialize_query_json(app_names)
                ));
            }
        }
    }
    Ok(query)
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
            browser_events = split_url_events(browser_events);
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
mod tests {
    use super::*;

    #[test]
    fn test_desktop_query_generation() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![],
                filter_classes: vec![],
                filter_afk: true,
                include_audible: true,
            },
            bid_window: "aw-watcher-window_".to_string(),
            bid_afk: "aw-watcher-afk_".to_string(),
            always_active_pattern: None,
        };

        let query = full_desktop_query(&params);
        assert!(!query.is_empty());
        assert!(query.contains("legacy_activity = flood"));
    }

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
                },
            ),
            (
                vec!["Work".to_string(), "Programming".to_string()],
                crate::classes::CategorySpec {
                    spec_type: "regex".to_string(),
                    regex: "GitHub|vim".to_string(),
                    ignore_case: true,
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
    fn test_canonical_events_with_empty_classes() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![],
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

        // Should contain basic query structure
        assert!(query.contains("legacy_activity = flood"));
        assert!(query.contains("test-window"));
    }

    #[test]
    fn test_canonical_events_with_existing_classes() {
        let classes = vec![(
            vec!["Test".to_string()],
            crate::classes::CategorySpec {
                spec_type: "regex".to_string(),
                regex: "test".to_string(),
                ignore_case: false,
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
    fn test_context_enrichment_before_categorization() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![(
                    vec!["Legacy".to_string()],
                    crate::classes::CategorySpec {
                        spec_type: "regex".to_string(),
                        regex: "legacy".to_string(),
                        ignore_case: false,
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
        let options = AdvancedQueryOptions {
            hostname: Some("workstation".to_string()),
            category_specs: Some(vec![serde_json::json!({
                "name": ["Work"],
                "rule": {
                    "type": "regex",
                    "field": "context.editor.project",
                    "regex": "\\w+"
                }
            })]),
            context_sources: vec![ContextSource {
                source_id: "editor".to_string(),
                bucket_ids: vec!["context-one".to_string(), "context-\"two".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                fields: vec!["project".to_string()],
                conflict: "base_wins".to_string(),
                host: None,
            }],
            capabilities: vec![
                CATEGORIZE_V2_CAPABILITY.to_string(),
                CONTEXT_ENRICHMENT_CAPABILITY.to_string(),
            ],
            ..AdvancedQueryOptions::default()
        };

        let query = QueryParams::Desktop(params)
            .try_canonical_events_with_options(&options)
            .unwrap();
        assert!(query.contains(
            r#"legacy_activity = flood(query_bucket(find_bucket("test-window", "workstation")))"#
        ));
        assert!(query
            .contains(r#"not_afk = flood(query_bucket(find_bucket("test-afk", "workstation")))"#));
        assert!(query.contains(r#", "workstation");"#));
        let afk_position = query
            .find("events = filter_period_intersect(events, not_afk)")
            .unwrap();
        let context_position = query.find("context_0 = []").unwrap();
        let categorize_position = query.find("events = categorize_v2").unwrap();

        assert!(afk_position < context_position);
        assert!(context_position < categorize_position);
        assert!(query.contains(
            "context_0 = concat(context_0, flood(query_bucket_optional(\"context-one\")))"
        ));
        assert!(query.contains("query_bucket_optional(\"context-\\\"two\")"));
        assert!(query.contains("context_fields_0 = [\"project\"]"));
        assert!(query
            .contains("context_options_0 = {\"conflict\":\"base_wins\",\"source_id\":\"editor\"}"));
        assert!(query.contains(
            "events = merge_subwatcher_fields(events, context_0, context_fields_0, context_options_0)"
        ));
        assert!(query.contains("\"regex\":\"\\w+\""));
        assert!(!query.contains("events = categorize(events"));
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
        };

        validate_context_sources(std::slice::from_ref(&source), Some("laptop")).unwrap();
        let query = build_context_events(&[source], Some("laptop"), false).unwrap();

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
        };

        assert_eq!(
            validate_context_sources(&[source], Some("laptop")),
            Err("context source bucket_hosts must map every bucket exactly once".to_string())
        );
    }

    #[test]
    fn test_categorize_v2_requires_capability() {
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
            category_specs: Some(vec![serde_json::json!({"name": ["Work"]})]),
            context_sources: vec![],
            capabilities: vec![],
            ..AdvancedQueryOptions::default()
        };

        assert_eq!(
            QueryParams::Android(params).try_canonical_events_with_options(&options),
            Err(format!(
                "Flexible categorization requires server capability {CATEGORIZE_V2_CAPABILITY}"
            ))
        );
    }

    #[test]
    fn test_context_enrichment_requires_capability() {
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
            category_specs: None,
            context_sources: vec![ContextSource {
                source_id: "editor".to_string(),
                bucket_ids: vec!["context".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                fields: vec!["project".to_string()],
                conflict: "base_wins".to_string(),
                host: None,
            }],
            capabilities: vec![],
            ..AdvancedQueryOptions::default()
        };

        assert_eq!(
            QueryParams::Android(params).try_canonical_events_with_options(&options),
            Err(format!(
                "Context enrichment requires server capability {CONTEXT_ENRICHMENT_CAPABILITY}"
            ))
        );
    }

    #[test]
    fn test_active_time_compilation_order_and_legacy_overrides() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec!["aw-watcher-web-chrome".to_string()],
                classes: vec![],
                filter_classes: vec![],
                filter_afk: true,
                include_audible: true,
            },
            bid_window: "test-window".to_string(),
            bid_afk: "legacy-afk".to_string(),
            always_active_pattern: Some("always-active".to_string()),
        };
        let options = AdvancedQueryOptions {
            hostname: Some("workstation".to_string()),
            active_time_rule: Some(serde_json::json!({
                "type": "regex",
                "source": "afk",
                "host": "workstation",
                "field": "status",
                "regex": "^not-afk$"
            })),
            active_time_sources: vec![
                ActiveTimeSource {
                    source_id: "afk".to_string(),
                    bucket_ids: vec!["afk-one".to_string(), "afk-\"two".to_string()],
                    scope: Some(SourceScope::Global),
                    bucket_hosts: BTreeMap::new(),
                    host: None,
                },
                ActiveTimeSource {
                    source_id: "presence".to_string(),
                    bucket_ids: vec!["presence".to_string()],
                    scope: Some(SourceScope::Global),
                    bucket_hosts: BTreeMap::new(),
                    host: None,
                },
            ],
            capabilities: vec![ACTIVE_PERIODS_V2_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_desktop_canonical_events_with_options(&params, &options).unwrap();
        let source_position = query.find("active_source_0 = []").unwrap();
        let rule_position = query.find("active_time_rule = {").unwrap();
        let active_position = query.find("not_afk = active_periods_v2").unwrap();
        let filter_position = query
            .find("events = filter_period_intersect(events, not_afk)")
            .unwrap();

        assert!(source_position < rule_position);
        assert!(rule_position < active_position);
        assert!(active_position < filter_position);
        assert!(query.contains(
            "active_source_0 = concat(active_source_0, flood(query_bucket_optional(\"afk-one\")))"
        ));
        assert!(query.contains("query_bucket_optional(\"afk-\\\"two\")"));
        assert!(query.contains(
            "active_time_sources = [[\"afk\", active_source_0], [\"presence\", active_source_1]]"
        ));
        assert!(query.contains(
            "not_afk = active_periods_v2(active_time_sources, active_time_rule, \"workstation\")"
        ));
        assert!(!query.contains("legacy-afk"));
        assert!(!query.contains("always-active"));
        assert!(!query.contains("audible_events"));
    }

    #[test]
    fn test_active_time_default_leaves_legacy_query_unchanged() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec!["aw-watcher-web-chrome".to_string()],
                classes: vec![],
                filter_classes: vec![],
                filter_afk: true,
                include_audible: true,
            },
            bid_window: "test-window".to_string(),
            bid_afk: "legacy-afk".to_string(),
            always_active_pattern: Some("always-active".to_string()),
        };

        let legacy = build_desktop_canonical_events(&params);
        let advanced =
            try_build_desktop_canonical_events_with_options(&params, &Default::default()).unwrap();

        assert_eq!(advanced, legacy);
        assert!(legacy.contains("legacy-afk"));
        assert!(legacy.contains("always-active"));
        assert!(legacy.contains("audible_events"));
        assert!(!legacy.contains("active_periods_v2"));
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
    fn test_active_time_source_validation() {
        let options = |source_id: &str, bucket_ids: Vec<String>| AdvancedQueryOptions {
            active_time_rule: Some(serde_json::json!({"type": "none"})),
            active_time_sources: vec![ActiveTimeSource {
                source_id: source_id.to_string(),
                bucket_ids,
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                host: None,
            }],
            capabilities: vec![ACTIVE_PERIODS_V2_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        };

        assert!(
            validate_advanced_options(&options("invalid.source", vec!["afk".to_string()])).is_err()
        );
        assert!(validate_advanced_options(&options("afk", vec![])).is_err());
        assert!(validate_advanced_options(&AdvancedQueryOptions {
            active_time_rule: Some(serde_json::json!({"type": "none"})),
            capabilities: vec![ACTIVE_PERIODS_V2_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        })
        .is_err());
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
            }],
            ..AdvancedQueryOptions::default()
        };

        assert_eq!(
            try_build_android_canonical_events_with_options(&params, &options),
            Err("Active-time options are not supported for Android queries".to_string())
        );
    }

    #[test]
    fn test_activity_coverage_sources_build_abstract_stream() {
        let options = AdvancedQueryOptions {
            activity_coverage_sources: vec![
                ActivityCoverageSource {
                    source_id: "meeting".to_string(),
                    bucket_ids: vec!["meeting".to_string()],
                    fields: vec!["subject".to_string()],
                    scope: Some(SourceScope::Global),
                    bucket_hosts: BTreeMap::new(),
                    host: None,
                },
                ActivityCoverageSource {
                    source_id: "desktop".to_string(),
                    bucket_ids: vec!["desktop".to_string()],
                    fields: vec!["vdesktop".to_string()],
                    scope: Some(SourceScope::Global),
                    bucket_hosts: BTreeMap::new(),
                    host: None,
                },
            ],
            capabilities: vec![CONTEXT_ENRICHMENT_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_canonical_events(&options).unwrap();
        assert!(query.contains("events = period_union(events, activity_coverage_period_0)"));
        assert!(query.contains("events = period_union(events, activity_coverage_period_1)"));
        assert!(query.contains(r#""source_id":"meeting""#));
        assert!(query.contains(r#""source_id":"desktop""#));
        assert!(!query.contains("events = union_no_overlap(activity_coverage_source_"));
    }

    #[test]
    fn test_replacement_activity_sources_are_applied_in_order() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![],
                filter_classes: vec![],
                filter_afk: true,
                include_audible: true,
            },
            bid_window: "test-window".to_string(),
            bid_afk: "test-afk".to_string(),
            always_active_pattern: None,
        };
        let options = AdvancedQueryOptions {
            activity_sources: vec![
                ActivitySource {
                    source_id: "low".to_string(),
                    bucket_ids: vec!["meeting-low".to_string()],
                    scope: Some(SourceScope::Global),
                    bucket_hosts: BTreeMap::new(),
                    field_mappings: BTreeMap::new(),
                    host: None,
                },
                ActivitySource {
                    source_id: "high".to_string(),
                    bucket_ids: vec!["meeting-high".to_string()],
                    scope: Some(SourceScope::Global),
                    bucket_hosts: BTreeMap::new(),
                    field_mappings: BTreeMap::from([
                        ("app".to_string(), "provider".to_string()),
                        ("title".to_string(), "subject".to_string()),
                    ]),
                    host: None,
                },
            ],
            capabilities: vec![MAP_EVENT_FIELDS_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_desktop_canonical_events_with_options(&params, &options).unwrap();
        assert!(query.contains(
            r#"map_event_fields(activity_source_1, {"app":"provider","title":"subject"})"#
        ));
        assert!(query.contains("activity_source_0 = sort_by_timestamp(activity_source_0)"));
        assert!(query.contains("activity_source_1 = sort_by_timestamp(activity_source_1)"));
        assert!(
            query.find("union_no_overlap(activity_source_0").unwrap()
                < query.find("union_no_overlap(activity_source_1").unwrap()
        );
    }

    #[test]
    fn test_replacement_activity_sources_are_sorted_without_afk_filtering() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![],
                filter_classes: vec![],
                filter_afk: false,
                include_audible: false,
            },
            bid_window: "test-window".to_string(),
            bid_afk: "test-afk".to_string(),
            always_active_pattern: None,
        };
        let options = AdvancedQueryOptions {
            activity_sources: vec![ActivitySource {
                source_id: "replacement".to_string(),
                bucket_ids: vec!["replacement".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                field_mappings: BTreeMap::new(),
                host: None,
            }],
            capabilities: vec![MAP_EVENT_FIELDS_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_desktop_canonical_events_with_options(&params, &options).unwrap();
        let sort = query
            .find("activity_source_0 = sort_by_timestamp(activity_source_0)")
            .unwrap();
        let union = query
            .find("events = union_no_overlap(activity_source_0, events)")
            .unwrap();
        assert!(sort < union);
        assert!(!query.contains("filter_period_intersect(activity_source_0, not_afk)"));
    }

    #[test]
    fn test_background_query_generation_and_generic_active_rule_requirement() {
        let options = AdvancedQueryOptions {
            hostname: Some("workstation".to_string()),
            category_specs: Some(vec![]),
            context_sources: vec![ContextSource {
                source_id: "editor".to_string(),
                bucket_ids: vec!["editor".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                fields: vec!["project".to_string()],
                conflict: "base_wins".to_string(),
                host: None,
            }],
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
            }],
            activity_sources: vec![ActivitySource {
                source_id: "replacement".to_string(),
                bucket_ids: vec!["replacement".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                field_mappings: BTreeMap::new(),
                host: None,
            }],
            background_sources: vec![ActivitySource {
                source_id: "calendar".to_string(),
                bucket_ids: vec!["calendar-one".to_string(), "calendar-two".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                field_mappings: BTreeMap::from([
                    ("app".to_string(), "provider".to_string()),
                    ("title".to_string(), "subject".to_string()),
                ]),
                host: None,
            }],
            capabilities: vec![
                CATEGORIZE_V2_CAPABILITY.to_string(),
                CONTEXT_ENRICHMENT_CAPABILITY.to_string(),
                ACTIVE_PERIODS_V2_CAPABILITY.to_string(),
                MAP_EVENT_FIELDS_CAPABILITY.to_string(),
            ],
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_canonical_events(&options).unwrap();
        let replacement = query.find("activity_source_0 = []").unwrap();
        let active = query.find("not_afk = active_periods_v2").unwrap();
        let mask = query
            .find("events = filter_period_intersect(events, not_afk)")
            .unwrap();
        let background = query.find("background_source_0 = []").unwrap();
        let context = query.find("context_0 = []").unwrap();
        let categorize = query.find("events = categorize_v2").unwrap();
        assert!(replacement < active);
        assert!(active < mask);
        assert!(mask < background);
        assert!(background < context);
        assert!(context < categorize);
        assert!(query
            .contains(r#"background_bucket_0_0 = flood(query_bucket_optional("calendar-one"))"#));
        assert!(query.contains(
            "background_source_0 = union_no_overlap(background_source_0, background_bucket_0_1)"
        ));
        assert!(query.contains(
            "background_source_0 = filter_period_intersect(background_source_0, not_afk)"
        ));
        assert!(query.contains(
            r#"map_event_fields(background_source_0, {"app":"provider","title":"subject"})"#
        ));
        assert!(query.contains("events = union_no_overlap(events, background_source_0)"));
        assert!(!query.contains("find_bucket"));

        let mut missing_rule = options;
        missing_rule.active_time_rule = None;
        missing_rule.active_time_sources.clear();
        missing_rule
            .capabilities
            .retain(|capability| capability != ACTIVE_PERIODS_V2_CAPABILITY);
        assert_eq!(
            try_build_canonical_events(&missing_rule),
            Err("Background activity sources require an active-time rule".to_string())
        );
    }

    #[test]
    fn test_desktop_background_uses_legacy_afk_even_without_activity_masking() {
        let params = DesktopQueryParams {
            base: QueryParamsBase {
                bid_browsers: vec![],
                classes: vec![],
                filter_classes: vec![],
                filter_afk: false,
                include_audible: false,
            },
            bid_window: String::new(),
            bid_afk: "legacy-afk".to_string(),
            always_active_pattern: None,
        };
        let options = AdvancedQueryOptions {
            background_sources: vec![ActivitySource {
                source_id: "calendar".to_string(),
                bucket_ids: vec!["calendar".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                field_mappings: BTreeMap::new(),
                host: None,
            }],
            capabilities: vec![MAP_EVENT_FIELDS_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_desktop_canonical_events_with_options(&params, &options).unwrap();
        let afk = query.find(r#"find_bucket("legacy-afk")"#).unwrap();
        let background = query.find("background_source_0 = []").unwrap();
        assert!(afk < background);
        assert!(!query.contains("legacy_activity"));
        assert!(!query.contains("events = filter_period_intersect(events, not_afk)"));
        assert!(query.contains(
            "background_source_0 = filter_period_intersect(background_source_0, not_afk)"
        ));
    }

    #[test]
    fn test_background_execution_preserves_activity_merges_buckets_and_clips_to_active_time() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        let timestamp = chrono::DateTime::parse_from_rfc3339("2024-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for bucket_id in [
            "replacement",
            "presence",
            "background-one",
            "background-two",
        ] {
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
                "replacement",
                &[aw_models::Event::new(
                    timestamp,
                    chrono::Duration::seconds(10),
                    serde_json::Map::from_iter([(
                        "app".to_string(),
                        serde_json::json!("foreground"),
                    )]),
                )],
            )
            .unwrap();
        datastore
            .insert_events(
                "presence",
                &[aw_models::Event::new(
                    timestamp,
                    chrono::Duration::seconds(15),
                    serde_json::Map::from_iter([(
                        "state".to_string(),
                        serde_json::json!("active"),
                    )]),
                )],
            )
            .unwrap();
        for (bucket_id, app) in [
            ("background-one", "background-first"),
            ("background-two", "background-second"),
        ] {
            datastore
                .insert_events(
                    bucket_id,
                    &[aw_models::Event::new(
                        timestamp,
                        chrono::Duration::seconds(20),
                        serde_json::Map::from_iter([(
                            "provider".to_string(),
                            serde_json::json!(app),
                        )]),
                    )],
                )
                .unwrap();
        }

        let options = AdvancedQueryOptions {
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
            }],
            activity_sources: vec![ActivitySource {
                source_id: "replacement".to_string(),
                bucket_ids: vec!["replacement".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                field_mappings: BTreeMap::new(),
                host: None,
            }],
            background_sources: vec![ActivitySource {
                source_id: "background".to_string(),
                bucket_ids: vec![
                    "background-one".to_string(),
                    "background-two".to_string(),
                    "missing-background".to_string(),
                ],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                field_mappings: BTreeMap::from([("app".to_string(), "provider".to_string())]),
                host: None,
            }],
            capabilities: vec![
                ACTIVE_PERIODS_V2_CAPABILITY.to_string(),
                MAP_EVENT_FIELDS_CAPABILITY.to_string(),
            ],
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_canonical_events(&options).unwrap();
        assert!(query.contains(r#"query_bucket_optional("missing-background")"#));
        let interval =
            aw_models::TimeInterval::new_from_string("2024-06-01T12:00:00Z/2024-06-01T12:01:00Z")
                .unwrap();
        let result =
            aw_query::query(&format!("{query}; return events;"), &interval, &datastore).unwrap();
        let events = Vec::<aw_models::Event>::try_from(&result).unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data["app"], serde_json::json!("foreground"));
        assert_eq!(events[0].duration, chrono::Duration::seconds(10));
        assert_eq!(events[1].data["app"], serde_json::json!("background-first"));
        assert_eq!(
            events[1].timestamp,
            timestamp + chrono::Duration::seconds(10)
        );
        assert_eq!(events[1].duration, chrono::Duration::seconds(5));
    }

    #[test]
    fn test_background_host_mismatch_is_ignored_at_execution() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        let timestamp = chrono::DateTime::parse_from_rfc3339("2024-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        datastore
            .create_bucket(&aw_models::Bucket {
                bid: None,
                id: "presence".to_string(),
                _type: "test".to_string(),
                client: "test".to_string(),
                hostname: "desktop".to_string(),
                created: Some(timestamp),
                data: serde_json::Map::new(),
                metadata: aw_models::BucketMetadata::default(),
                events: None,
                last_updated: None,
            })
            .unwrap();
        datastore
            .insert_events(
                "presence",
                &[aw_models::Event::new(
                    timestamp,
                    chrono::Duration::seconds(10),
                    serde_json::Map::from_iter([(
                        "state".to_string(),
                        serde_json::json!("active"),
                    )]),
                )],
            )
            .unwrap();
        let options = AdvancedQueryOptions {
            hostname: Some("desktop".to_string()),
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
            }],
            background_sources: vec![ActivitySource {
                source_id: "laptop-calendar".to_string(),
                bucket_ids: vec!["background-laptop".to_string()],
                scope: Some(SourceScope::Host),
                bucket_hosts: BTreeMap::new(),
                field_mappings: BTreeMap::new(),
                host: Some("laptop".to_string()),
            }],
            capabilities: vec![
                ACTIVE_PERIODS_V2_CAPABILITY.to_string(),
                MAP_EVENT_FIELDS_CAPABILITY.to_string(),
            ],
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_canonical_events(&options).unwrap();
        assert!(!query.contains("background-laptop"));
        let interval =
            aw_models::TimeInterval::new_from_string("2024-06-01T12:00:00Z/2024-06-01T12:01:00Z")
                .unwrap();
        let result =
            aw_query::query(&format!("{query}; return events;"), &interval, &datastore).unwrap();
        assert!(Vec::<aw_models::Event>::try_from(&result)
            .unwrap()
            .is_empty());
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
    fn test_shared_scope_resolver_isolates_roles_and_keeps_global_sources() {
        let host_context = ContextSource {
            source_id: "context_host".to_string(),
            bucket_ids: vec!["context-laptop".to_string()],
            scope: Some(SourceScope::Host),
            bucket_hosts: BTreeMap::new(),
            fields: vec!["project".to_string()],
            conflict: "base_wins".to_string(),
            host: Some("laptop".to_string()),
        };
        let global_context = ContextSource {
            source_id: "context_global".to_string(),
            bucket_ids: vec!["context-global".to_string()],
            scope: Some(SourceScope::Global),
            bucket_hosts: BTreeMap::new(),
            fields: vec!["project".to_string()],
            conflict: "base_wins".to_string(),
            host: None,
        };
        let context_query =
            build_context_events(&[host_context, global_context], Some("desktop"), false).unwrap();
        assert!(!context_query.contains("context-laptop"));
        assert!(context_query.contains("context-global"));

        let active_query = try_build_active_time_query(
            &[
                ActiveTimeSource {
                    source_id: "host".to_string(),
                    bucket_ids: vec!["active-laptop".to_string()],
                    scope: Some(SourceScope::Host),
                    bucket_hosts: BTreeMap::new(),
                    host: Some("laptop".to_string()),
                },
                ActiveTimeSource {
                    source_id: "global".to_string(),
                    bucket_ids: vec!["active-global".to_string()],
                    scope: Some(SourceScope::Global),
                    bucket_hosts: BTreeMap::new(),
                    host: None,
                },
            ],
            &serde_json::json!({"type": "none"}),
            Some("desktop"),
        )
        .unwrap();
        assert!(!active_query.contains("active-laptop"));
        assert!(active_query.contains("active-global"));
        assert!(active_query.contains(
            r#"active_time_sources = [["host", active_source_0], ["global", active_source_1]]"#
        ));
    }

    #[test]
    fn test_host_scoped_sources_emit_server_hostname_check_when_supported() {
        let options = AdvancedQueryOptions {
            hostname: Some("laptop".to_string()),
            capabilities: vec![
                CONTEXT_ENRICHMENT_CAPABILITY.to_string(),
                OPTIONAL_BUCKET_HOSTNAME_CAPABILITY.to_string(),
            ],
            context_sources: vec![
                ContextSource {
                    source_id: "host-context".to_string(),
                    bucket_ids: vec!["context-laptop".to_string()],
                    scope: Some(SourceScope::Host),
                    bucket_hosts: BTreeMap::new(),
                    fields: vec!["project".to_string()],
                    conflict: "base_wins".to_string(),
                    host: Some("laptop".to_string()),
                },
                ContextSource {
                    source_id: "global-context".to_string(),
                    bucket_ids: vec!["context-global".to_string()],
                    scope: Some(SourceScope::Global),
                    bucket_hosts: BTreeMap::new(),
                    fields: vec!["project".to_string()],
                    conflict: "base_wins".to_string(),
                    host: None,
                },
            ],
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_canonical_events(&options).unwrap();
        assert!(query.contains(r#"query_bucket_optional("context-laptop", "laptop")"#));
        assert!(query.contains(r#"query_bucket_optional("context-global")"#));
        let active_query = try_build_active_time_query_with_capabilities(
            &[ActiveTimeSource {
                source_id: "presence".to_string(),
                bucket_ids: vec!["presence-laptop".to_string()],
                scope: Some(SourceScope::Host),
                bucket_hosts: BTreeMap::new(),
                host: Some("laptop".to_string()),
            }],
            &serde_json::json!({"type": "none"}),
            Some("laptop"),
            &[OPTIONAL_BUCKET_HOSTNAME_CAPABILITY.to_string()],
        )
        .unwrap();
        assert!(active_query.contains(r#"query_bucket_optional("presence-laptop", "laptop")"#));

        let activity_query = try_build_canonical_events(&AdvancedQueryOptions {
            hostname: Some("desktop".to_string()),
            activity_sources: vec![
                ActivitySource {
                    source_id: "host".to_string(),
                    bucket_ids: vec!["activity-laptop".to_string()],
                    scope: Some(SourceScope::Host),
                    bucket_hosts: BTreeMap::new(),
                    field_mappings: BTreeMap::new(),
                    host: Some("laptop".to_string()),
                },
                ActivitySource {
                    source_id: "global".to_string(),
                    bucket_ids: vec!["activity-global".to_string()],
                    scope: Some(SourceScope::Global),
                    bucket_hosts: BTreeMap::new(),
                    field_mappings: BTreeMap::new(),
                    host: None,
                },
            ],
            capabilities: vec![MAP_EVENT_FIELDS_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        })
        .unwrap();
        assert!(!activity_query.contains("activity-laptop"));
        assert!(activity_query.contains("activity-global"));
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
    fn test_duplicate_source_ids_rejected_for_every_role() {
        let context = ContextSource {
            source_id: "duplicate".to_string(),
            bucket_ids: vec!["context".to_string()],
            scope: Some(SourceScope::Global),
            bucket_hosts: BTreeMap::new(),
            fields: vec!["field".to_string()],
            conflict: "base_wins".to_string(),
            host: None,
        };
        assert!(validate_context_sources(&[context.clone(), context], None)
            .unwrap_err()
            .contains("duplicate context source id"));

        let active = ActiveTimeSource {
            source_id: "duplicate".to_string(),
            bucket_ids: vec!["active".to_string()],
            scope: Some(SourceScope::Global),
            bucket_hosts: BTreeMap::new(),
            host: None,
        };
        assert!(
            validate_active_time_sources(&[active.clone(), active], None)
                .unwrap_err()
                .contains("duplicate active-time source id")
        );

        let activity = ActivitySource {
            source_id: "duplicate".to_string(),
            bucket_ids: vec!["activity".to_string()],
            scope: Some(SourceScope::Global),
            bucket_hosts: BTreeMap::new(),
            field_mappings: BTreeMap::new(),
            host: None,
        };
        assert!(
            validate_activity_sources(&[activity.clone(), activity], None)
                .unwrap_err()
                .contains("duplicate activity source id")
        );
    }

    #[test]
    fn test_generic_expression_and_alternative_activity_need_no_window_or_afk() {
        let expression_query = try_build_canonical_events(&AdvancedQueryOptions {
            category_specs: Some(vec![serde_json::json!({
                "name": ["Editor"],
                "rule": {"type": "regex", "field": "title", "regex": "code"}
            })]),
            capabilities: vec![CATEGORIZE_V2_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        })
        .unwrap();
        assert!(expression_query.starts_with("events = []"));
        assert!(expression_query.contains("categorize_v2"));
        assert!(!expression_query.contains("find_bucket"));
        assert!(!expression_query.contains("not_afk"));

        let activity_query = try_build_canonical_events(&AdvancedQueryOptions {
            activity_sources: vec![ActivitySource {
                source_id: "calendar".to_string(),
                bucket_ids: vec!["calendar".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                field_mappings: BTreeMap::new(),
                host: None,
            }],
            capabilities: vec![MAP_EVENT_FIELDS_CAPABILITY.to_string()],
            ..AdvancedQueryOptions::default()
        })
        .unwrap();
        assert!(activity_query.starts_with("events = []"));
        assert!(activity_query.contains("query_bucket_optional(\"calendar\")"));
        assert!(!activity_query.contains("window"));
        assert!(!activity_query.contains("not_afk"));
    }

    #[test]
    fn test_generic_pipeline_uses_optional_buckets_and_executes_when_all_are_missing() {
        let options = AdvancedQueryOptions {
            category_specs: Some(vec![]),
            context_sources: vec![ContextSource {
                source_id: "editor".to_string(),
                bucket_ids: vec!["missing-context".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                fields: vec!["project".to_string()],
                conflict: "base_wins".to_string(),
                host: None,
            }],
            active_time_rule: Some(serde_json::json!({"type": "none"})),
            active_time_sources: vec![ActiveTimeSource {
                source_id: "presence".to_string(),
                bucket_ids: vec!["missing-active".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                host: None,
            }],
            activity_sources: vec![ActivitySource {
                source_id: "activity".to_string(),
                bucket_ids: vec!["missing-activity".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                field_mappings: BTreeMap::new(),
                host: None,
            }],
            capabilities: vec![
                CATEGORIZE_V2_CAPABILITY.to_string(),
                CONTEXT_ENRICHMENT_CAPABILITY.to_string(),
                ACTIVE_PERIODS_V2_CAPABILITY.to_string(),
                MAP_EVENT_FIELDS_CAPABILITY.to_string(),
            ],
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_canonical_events(&options).unwrap();
        assert_eq!(query.matches("query_bucket_optional").count(), 3);
        assert!(!query.contains("query_bucket(\"missing"));

        let datastore = aw_datastore::Datastore::new_in_memory(false);
        let interval =
            aw_models::TimeInterval::new_from_string("2024-01-01T00:00:00Z/2025-01-01T00:00:00Z")
                .unwrap();
        let result =
            aw_query::query(&format!("{query}; return events;"), &interval, &datastore).unwrap();
        assert!(Vec::<aw_models::Event>::try_from(&result)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_generic_pipeline_orders_and_executes_all_stages() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        let timestamp = chrono::DateTime::parse_from_rfc3339("2024-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for bucket_id in ["activity", "presence", "editor"] {
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
                "activity",
                &[aw_models::Event::new(
                    timestamp,
                    chrono::Duration::seconds(10),
                    serde_json::Map::from_iter([
                        ("app".to_string(), serde_json::json!("terminal")),
                        ("title".to_string(), serde_json::json!("shell")),
                    ]),
                )],
            )
            .unwrap();
        datastore
            .insert_events(
                "presence",
                &[aw_models::Event::new(
                    timestamp,
                    chrono::Duration::seconds(10),
                    serde_json::Map::from_iter([(
                        "state".to_string(),
                        serde_json::json!("active"),
                    )]),
                )],
            )
            .unwrap();
        datastore
            .insert_events(
                "editor",
                &[aw_models::Event::new(
                    timestamp,
                    chrono::Duration::seconds(10),
                    serde_json::Map::from_iter([(
                        "project".to_string(),
                        serde_json::json!("activitywatch"),
                    )]),
                )],
            )
            .unwrap();

        let options = AdvancedQueryOptions {
            category_specs: Some(vec![serde_json::json!({
                "name": ["Project"],
                "rule": {
                    "type": "regex",
                    "source": "editor",
                    "field": "project",
                    "regex": "^activitywatch$"
                }
            })]),
            context_sources: vec![ContextSource {
                source_id: "editor".to_string(),
                bucket_ids: vec!["editor".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                fields: vec!["project".to_string()],
                conflict: "base_wins".to_string(),
                host: None,
            }],
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
            }],
            activity_sources: vec![ActivitySource {
                source_id: "activity".to_string(),
                bucket_ids: vec!["activity".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                field_mappings: BTreeMap::new(),
                host: None,
            }],
            capabilities: vec![
                CATEGORIZE_V2_CAPABILITY.to_string(),
                CONTEXT_ENRICHMENT_CAPABILITY.to_string(),
                ACTIVE_PERIODS_V2_CAPABILITY.to_string(),
                MAP_EVENT_FIELDS_CAPABILITY.to_string(),
            ],
            ..AdvancedQueryOptions::default()
        };

        let query = try_build_canonical_events(&options).unwrap();
        let activity_position = query.find("activity_source_0 = []").unwrap();
        let active_position = query.find("active_source_0 = []").unwrap();
        let mask_position = query
            .find("events = filter_period_intersect(events, not_afk)")
            .unwrap();
        let context_position = query.find("context_0 = []").unwrap();
        let category_position = query.find("events = categorize_v2").unwrap();
        assert!(activity_position < active_position);
        assert!(active_position < mask_position);
        assert!(mask_position < context_position);
        assert!(context_position < category_position);

        let interval =
            aw_models::TimeInterval::new_from_string("2024-01-01T00:00:00Z/2025-01-01T00:00:00Z")
                .unwrap();
        let result =
            aw_query::query(&format!("{query}; return events;"), &interval, &datastore).unwrap();
        let events = Vec::<aw_models::Event>::try_from(&result).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data["app"], serde_json::json!("terminal"));
        assert_eq!(
            events[0].data["$source.editor.project"],
            serde_json::json!("activitywatch")
        );
        assert_eq!(events[0].data["$category"], serde_json::json!(["Project"]));
    }

    #[test]
    fn test_context_app_and_title_are_ordinary_namespaced_fields() {
        let query = try_build_canonical_events(&AdvancedQueryOptions {
            category_specs: Some(vec![serde_json::json!({
                "name": ["Context app"],
                "rule": {
                    "type": "regex",
                    "source": "editor",
                    "field": "app",
                    "regex": "code"
                }
            })]),
            context_sources: vec![ContextSource {
                source_id: "editor".to_string(),
                bucket_ids: vec!["editor".to_string()],
                scope: Some(SourceScope::Global),
                bucket_hosts: BTreeMap::new(),
                fields: vec!["app".to_string(), "title".to_string()],
                conflict: "base_wins".to_string(),
                host: None,
            }],
            capabilities: vec![
                CATEGORIZE_V2_CAPABILITY.to_string(),
                CONTEXT_ENRICHMENT_CAPABILITY.to_string(),
            ],
            ..AdvancedQueryOptions::default()
        })
        .unwrap();

        assert!(query.contains(r#"context_fields_0 = ["app","title"]"#));
        assert!(query.contains(r#""source":"editor""#));
        assert!(query.contains(r#""field":"app""#));
        assert!(!query.contains("map_event_fields"));
    }

    #[test]
    fn test_active_and_legacy_afk_only_queries_need_no_activity_stream() {
        let active_query = try_build_active_time_query(
            &[ActiveTimeSource {
                source_id: "afk".to_string(),
                bucket_ids: vec!["afk-laptop".to_string()],
                scope: Some(SourceScope::Host),
                bucket_hosts: BTreeMap::new(),
                host: Some("laptop".to_string()),
            }],
            &serde_json::json!({"type": "none"}),
            Some("desktop"),
        )
        .unwrap();
        assert!(active_query.contains("active_source_0 = []"));
        assert!(active_query.ends_with("RETURN = not_afk;"));
        assert!(active_query.contains(r#"active_time_sources = [["afk", active_source_0]]"#));
        assert!(!active_query.contains("afk-laptop"));
        assert!(!active_query.contains("events ="));

        let legacy_query = try_build_legacy_afk_query("legacy-afk", Some("desktop")).unwrap();
        assert!(legacy_query.contains(r#"find_bucket("legacy-afk", "desktop")"#));
        assert!(legacy_query.ends_with("RETURN = not_afk;"));
        assert!(!legacy_query.contains("window"));
        assert!(!legacy_query.contains("events ="));
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
        };

        let serialized = serde_json::to_value(source).unwrap();
        assert!(serialized.get("bucket_hosts").is_none());
    }
}
