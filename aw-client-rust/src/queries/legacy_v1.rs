//! Frozen Query2 grammar for explicitly selected old-server and Android targets.

use super::*;

pub fn desktop(params: &DesktopQueryParams) -> Result<String, String> {
    desktop_with_options(params, &AdvancedQueryOptions::default())
}

pub fn android(params: &AndroidQueryParams) -> Result<String, String> {
    android_with_options(params, &AdvancedQueryOptions::default())
}

pub(super) fn desktop_with_options(
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

    // Coverage configured to keep activity active contributes to the same effective
    // active-time mask, regardless of whether that mask came from legacy AFK events
    // or an active-time expression.
    if params.base.filter_afk {
        let active_overrides =
            build_activity_coverage_active_overrides(&options.activity_coverage_sources);
        if !active_overrides.is_empty() {
            query.push(active_overrides);
        }
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

pub(super) fn android_with_options(
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

// Frozen source loaders for the explicit old-target grammar.

pub(super) fn build_context_events(
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

fn build_activity_coverage_active_overrides(sources: &[ActivityCoverageSource]) -> String {
    sources
        .iter()
        .enumerate()
        .filter(|(_, source)| source.keeps_active)
        .map(|(index, _)| {
            format!("not_afk = period_union(not_afk, activity_coverage_period_{index})")
        })
        .collect::<Vec<_>>()
        .join(";\n")
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
    append_source_enrichment_and_categorization(
        query,
        options.hostname.as_deref(),
        &options.context_sources,
        options.category_specs.as_deref(),
        &options.capabilities,
    )
}

fn append_source_enrichment_and_categorization(
    query: &mut Vec<String>,
    hostname: Option<&str>,
    context_sources: &[ContextSource],
    category_specs: Option<&[serde_json::Value]>,
    capabilities: &[String],
) -> Result<bool, String> {
    let enforce_hostname = capabilities
        .iter()
        .any(|capability| capability == OPTIONAL_BUCKET_HOSTNAME_CAPABILITY);
    let context_events = build_context_events(context_sources, hostname, enforce_hostname)?;
    if !context_events.is_empty() {
        query.push(context_events);
    }
    if let Some(category_specs) = category_specs {
        let host = hostname
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

pub(super) fn legacy_afk_query(bid_afk: &str, hostname: Option<&str>) -> Result<String, String> {
    Ok(format!(
        "{};\nRETURN = not_afk;",
        build_legacy_afk_events(bid_afk, hostname)?
    ))
}

pub(super) fn browser_events(params: &DesktopQueryParams) -> Result<String, String> {
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
