use crate::DataType;
use crate::QueryError;
use crate::VarEnv;
use aw_datastore::Datastore;

pub type QueryFn =
    fn(args: Vec<DataType>, env: &VarEnv, ds: &Datastore) -> Result<DataType, QueryError>;

pub fn fill_env(env: &mut VarEnv) {
    env.insert(
        "print".to_string(),
        DataType::Function("print".to_string(), qfunctions::print),
    );
    env.insert(
        "query_bucket".to_string(),
        DataType::Function("query_bucket".to_string(), qfunctions::query_bucket),
    );
    env.insert(
        "query_bucket_optional".to_string(),
        DataType::Function(
            "query_bucket_optional".to_string(),
            qfunctions::query_bucket_optional,
        ),
    );
    env.insert(
        "query_bucket_names".to_string(),
        DataType::Function(
            "query_bucket_names".to_string(),
            qfunctions::query_bucket_names,
        ),
    );
    env.insert(
        "sort_by_duration".to_string(),
        DataType::Function("sort_by_duration".to_string(), qfunctions::sort_by_duration),
    );
    env.insert(
        "sort_by_timestamp".to_string(),
        DataType::Function(
            "sort_by_timestamp".to_string(),
            qfunctions::sort_by_timestamp,
        ),
    );
    env.insert(
        "sum_durations".to_string(),
        DataType::Function("sum_durations".to_string(), qfunctions::sum_durations),
    );
    env.insert(
        "limit_events".to_string(),
        DataType::Function("limit_events".to_string(), qfunctions::limit_events),
    );
    env.insert(
        "contains".to_string(),
        DataType::Function("contains".to_string(), qfunctions::contains),
    );
    env.insert(
        "flood".to_string(),
        DataType::Function("flood".to_string(), qfunctions::flood),
    );
    env.insert(
        "find_bucket".to_string(),
        DataType::Function("find_bucket".to_string(), qfunctions::find_bucket),
    );
    env.insert(
        "merge_events_by_keys".to_string(),
        DataType::Function(
            "merge_events_by_keys".to_string(),
            qfunctions::merge_events_by_keys,
        ),
    );
    env.insert(
        "merge_subwatcher_fields".to_string(),
        DataType::Function(
            "merge_subwatcher_fields".to_string(),
            qfunctions::merge_subwatcher_fields,
        ),
    );
    env.insert(
        "map_event_fields".to_string(),
        DataType::Function("map_event_fields".into(), qfunctions::map_event_fields),
    );
    env.insert(
        "chunk_events_by_key".to_string(),
        DataType::Function(
            "chunk_events_by_key".to_string(),
            qfunctions::chunk_events_by_key,
        ),
    );
    env.insert(
        "exclude_keyvals".to_string(),
        DataType::Function("exclude_keyvals".to_string(), qfunctions::exclude_keyvals),
    );
    env.insert(
        "filter_keyvals".to_string(),
        DataType::Function("filter_keyvals".to_string(), qfunctions::filter_keyvals),
    );
    env.insert(
        "filter_keyvals_regex".to_string(),
        DataType::Function(
            "filter_keyvals_regex".to_string(),
            qfunctions::filter_keyvals_regex,
        ),
    );
    env.insert(
        "filter_period_intersect".to_string(),
        DataType::Function(
            "filter_period_intersect".to_string(),
            qfunctions::filter_period_intersect,
        ),
    );
    env.insert(
        "split_url_events".to_string(),
        DataType::Function("split_url_events".to_string(), qfunctions::split_url_events),
    );
    env.insert(
        "concat".to_string(),
        DataType::Function("concat".to_string(), qfunctions::concat),
    );
    env.insert(
        "categorize".to_string(),
        DataType::Function("categorize".into(), qfunctions::categorize),
    );
    env.insert(
        "categorize_v2".to_string(),
        DataType::Function("categorize_v2".into(), qfunctions::categorize_v2),
    );
    env.insert(
        "categorize_v2_explain".to_string(),
        DataType::Function(
            "categorize_v2_explain".into(),
            qfunctions::categorize_v2_explain,
        ),
    );
    env.insert(
        "active_periods_v2".to_string(),
        DataType::Function("active_periods_v2".into(), qfunctions::active_periods_v2),
    );
    env.insert(
        "tag".to_string(),
        DataType::Function("tag".into(), qfunctions::tag),
    );
    env.insert(
        "period_union".to_string(),
        DataType::Function("period_union".into(), qfunctions::period_union),
    );
    env.insert(
        "union_no_overlap".to_string(),
        DataType::Function("union_no_overlap".into(), qfunctions::union_no_overlap),
    );
}

mod qfunctions {
    use aw_datastore::{Datastore, DatastoreError};
    use aw_models::Event;
    use aw_transform::classify::Rule;

    use super::validate;
    use crate::DataType;
    use crate::QueryError;
    use crate::VarEnv;

    pub fn print(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        for arg in args {
            info!("{:?}", arg);
        }
        Ok(DataType::None())
    }

    pub fn query_bucket(
        args: Vec<DataType>,
        env: &VarEnv,
        ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // Typecheck
        validate::args_length(&args, 1)?;

        let bucket_id: String = args.into_iter().next().unwrap().try_into()?;
        let interval = validate::get_timeinterval(env)?;

        let events = match ds.get_events(
            bucket_id.as_str(),
            Some(*interval.start()),
            Some(*interval.end()),
            None,
        ) {
            Ok(events) => events,
            Err(DatastoreError::NoSuchBucket(error)) => {
                return Err(QueryError::BucketQueryError(format!(
                    "Failed to query bucket: {error}"
                )))
            }
            Err(error) => {
                return Err(QueryError::DatastoreQueryError(format!(
                    "Failed to query bucket: {error:?}"
                )))
            }
        };
        let mut ret = Vec::new();
        for event in events {
            ret.push(DataType::Event(event));
        }
        Ok(DataType::List(ret))
    }

    pub fn query_bucket_optional(
        mut args: Vec<DataType>,
        env: &VarEnv,
        ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        validate::args_length(&args, if args.len() == 2 { 2 } else { 1 })?;
        let expected_hostname = if args.len() == 2 {
            Some(String::try_from(args.pop().unwrap())?)
        } else {
            None
        };
        let bucket_id: String = args.pop().unwrap().try_into()?;
        if let Some(expected_hostname) = expected_hostname {
            match ds.get_bucket(bucket_id.as_str()) {
                Ok(bucket) if bucket.hostname == expected_hostname => {}
                Ok(_) | Err(DatastoreError::NoSuchBucket(_)) => {
                    return Ok(DataType::List(Vec::new()))
                }
                Err(error) => {
                    return Err(QueryError::DatastoreQueryError(format!(
                        "Failed to inspect bucket: {error:?}"
                    )))
                }
            }
        }
        let interval = validate::get_timeinterval(env)?;
        let events = match ds.get_events(
            bucket_id.as_str(),
            Some(*interval.start()),
            Some(*interval.end()),
            None,
        ) {
            Ok(events) => events,
            Err(DatastoreError::NoSuchBucket(_)) => Vec::new(),
            Err(error) => {
                return Err(QueryError::DatastoreQueryError(format!(
                    "Failed to query bucket: {error:?}"
                )))
            }
        };
        Ok(DataType::List(
            events.into_iter().map(DataType::Event).collect(),
        ))
    }

    pub fn query_bucket_names(
        args: Vec<DataType>,
        _env: &VarEnv,
        ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        validate::args_length(&args, 0)?;
        let mut bucketnames: Vec<DataType> = Vec::new();
        let buckets = match ds.get_buckets() {
            Ok(buckets) => buckets,
            Err(e) => {
                return Err(QueryError::DatastoreQueryError(format!(
                    "Failed to query bucket names: {e:?}"
                )))
            }
        };
        for bucketname in buckets.keys() {
            bucketnames.push(DataType::String(bucketname.to_string()));
        }
        Ok(DataType::List(bucketnames))
    }

    pub fn find_bucket(
        args: Vec<DataType>,
        _env: &VarEnv,
        ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        validate::args_length(&args, 1).or_else(|_| validate::args_length(&args, 2))?;

        let mut args = args.into_iter();
        let bucket_filter: String = args.next().unwrap().try_into()?;
        let hostname_filter: Option<String> = match args.next() {
            Some(arg) => Some(arg.try_into()?),
            None => None,
        };

        let buckets = match ds.get_buckets() {
            Ok(buckets) => buckets,
            Err(e) => {
                return Err(QueryError::DatastoreQueryError(format!(
                    "Failed to query bucket names: {e:?}"
                )))
            }
        };
        let bucketname = match aw_transform::find_bucket(
            &bucket_filter,
            &hostname_filter,
            buckets.values(),
        ) {
            Some(bucketname) => bucketname,
            None => {
                return Err(QueryError::BucketQueryError(match hostname_filter {
                        None => {
                            format!("Failed to find bucket matching filter '{bucket_filter}'")
                        }
                        Some(hostname_filter) => format!(
                            "Failed to find bucket matching filter '{bucket_filter}' and hostname '{hostname_filter}'"
                        ),
                    }));
            }
        };
        Ok(DataType::String(bucketname))
    }

    pub fn contains(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        match args.first().unwrap() {
            DataType::List(ref list) => Ok(DataType::Bool(list.contains(&args[1]))),
            DataType::Dict(ref dict) => {
                let s = match &args[1] {
                    DataType::String(s) => s.to_string(),
                    _ => {
                        return Err(QueryError::InvalidFunctionParameters(format!(
                            "function contains got second argument {:?}, expected type String",
                            args[0]
                        )))
                    }
                };
                Ok(DataType::Bool(dict.contains_key(&s)))
            }
            _ => Err(QueryError::InvalidFunctionParameters(format!(
                "function contains got first argument {:?}, expected type List or Dict",
                args[0]
            ))),
        }
    }

    pub fn flood(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 1)?;
        let events: Vec<Event> = args.into_iter().next().unwrap().try_into()?;
        // Run flood
        let mut flooded_events = aw_transform::flood(events, chrono::Duration::seconds(5));
        // Put events back into DataType::Event container
        let mut tagged_flooded_events = Vec::new();
        for event in flooded_events.drain(..) {
            tagged_flooded_events.push(DataType::Event(event));
        }
        Ok(DataType::List(tagged_flooded_events))
    }

    pub fn categorize(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let rules: Vec<(Vec<String>, Rule)> = args.next().unwrap().try_into()?;
        // Run categorize
        let mut flooded_events = aw_transform::classify::categorize(events, &rules);
        // Put events back into DataType::Event container
        let mut tagged_flooded_events = Vec::new();
        for event in flooded_events.drain(..) {
            tagged_flooded_events.push(DataType::Event(event));
        }
        Ok(DataType::List(tagged_flooded_events))
    }

    pub fn categorize_v2(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        validate::args_length(&args, 2).or_else(|_| validate::args_length(&args, 3))?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let category_specs: serde_json::Value = args.next().unwrap().try_into()?;
        let host: Option<String> = match args.next() {
            Some(DataType::None()) | None => None,
            Some(host) => Some(host.try_into()?),
        };
        let events = aw_transform::categorize_v2_for_host(events, &category_specs, host.as_deref())
            .map_err(QueryError::InvalidFunctionParameters)?;
        Ok(DataType::List(
            events.into_iter().map(DataType::Event).collect(),
        ))
    }

    pub fn categorize_v2_explain(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        validate::args_length(&args, 2).or_else(|_| validate::args_length(&args, 3))?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let category_specs: serde_json::Value = args.next().unwrap().try_into()?;
        let host: Option<String> = match args.next() {
            Some(DataType::None()) | None => None,
            Some(host) => Some(host.try_into()?),
        };
        let events =
            aw_transform::categorize_v2_explain_for_host(events, &category_specs, host.as_deref())
                .map_err(QueryError::InvalidFunctionParameters)?;
        Ok(DataType::List(
            events.into_iter().map(DataType::Event).collect(),
        ))
    }

    pub fn tag(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let rules: Vec<(String, Rule)> = args.next().unwrap().try_into()?;
        // Run categorize
        let mut flooded_events = aw_transform::classify::tag(events, &rules);
        // Put events back into DataType::Event container
        let mut tagged_flooded_events = Vec::new();
        for event in flooded_events.drain(..) {
            tagged_flooded_events.push(DataType::Event(event));
        }
        Ok(DataType::List(tagged_flooded_events))
    }

    pub fn sort_by_duration(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 1)?;
        let events: Vec<Event> = args.into_iter().next().unwrap().try_into()?;

        // Sort by duration
        let mut sorted_events = aw_transform::sort_by_duration(events);
        // Put events back into DataType::Event container
        let mut tagged_sorted_events = Vec::new();
        for event in sorted_events.drain(..) {
            tagged_sorted_events.push(DataType::Event(event));
        }

        Ok(DataType::List(tagged_sorted_events))
    }

    pub fn limit_events(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let mut events: Vec<Event> = args.next().unwrap().try_into()?;
        let mut limit: usize = args.next().unwrap().try_into()?;

        if events.len() < limit {
            limit = events.len()
        }
        let mut limited_tagged_events = Vec::new();
        for event in events.drain(0..limit) {
            limited_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(limited_tagged_events))
    }

    pub fn sort_by_timestamp(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 1)?;
        let events: Vec<Event> = args.into_iter().next().unwrap().try_into()?;

        // Sort by duration
        let mut sorted_events = aw_transform::sort_by_timestamp(events);
        // Put events back into DataType::Event container
        let mut tagged_sorted_events = Vec::new();
        for event in sorted_events.drain(..) {
            tagged_sorted_events.push(DataType::Event(event));
        }
        Ok(DataType::List(tagged_sorted_events))
    }

    pub fn sum_durations(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 1)?;
        let mut events: Vec<Event> = args.into_iter().next().unwrap().try_into()?;

        // Sort by duration
        let mut sum_durations = chrono::Duration::zero();
        for event in events.drain(..) {
            sum_durations += event.duration;
        }
        Ok(DataType::Number(
            (sum_durations.num_milliseconds() as f64) / 1000.0,
        ))
    }

    pub fn merge_events_by_keys(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let keys: Vec<String> = args.next().unwrap().try_into()?;

        let mut merged_events = aw_transform::merge_events_by_keys(events, keys);
        let mut merged_tagged_events = Vec::new();
        for event in merged_events.drain(..) {
            merged_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(merged_tagged_events))
    }

    pub fn merge_subwatcher_fields(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        if !(3..=5).contains(&args.len()) {
            return Err(QueryError::InvalidFunctionParameters(format!(
                "Expected 3 to 5 parameters in function, got {}",
                args.len()
            )));
        }
        let mut args = args.into_iter();
        let base_events: Vec<Event> = args.next().unwrap().try_into()?;
        let subwatcher_events: Vec<Event> = args.next().unwrap().try_into()?;
        let keys: Vec<String> = args.next().unwrap().try_into()?;
        let mut conflict = "base_wins".to_string();
        let mut source_id = None;
        let mut source_id_from_options = false;

        if let Some(options) = args.next() {
            match options {
                DataType::String(value) => conflict = value,
                DataType::Dict(options) => {
                    if let Some(value) = options.get("conflict") {
                        conflict = match value {
                            DataType::String(value) => value.clone(),
                            invalid => {
                                return Err(QueryError::InvalidFunctionParameters(format!(
                                    "conflict must be 'base_wins' or 'sub_wins', got {invalid:?}"
                                )))
                            }
                        };
                    }
                    if let Some(value) = options.get("source_id") {
                        source_id_from_options = true;
                        source_id = match value {
                            DataType::String(value) => Some(value.clone()),
                            DataType::None() => None,
                            invalid => {
                                return Err(QueryError::InvalidFunctionParameters(format!(
                                    "source_id must be a string, got {invalid:?}"
                                )))
                            }
                        };
                    }
                }
                invalid => {
                    return Err(QueryError::InvalidFunctionParameters(format!(
                        "merge_subwatcher_fields fourth argument must be a conflict string or options dict, got {invalid:?}"
                    )))
                }
            }
        }
        if let Some(value) = args.next() {
            if source_id_from_options {
                return Err(QueryError::InvalidFunctionParameters(
                    "source_id must be provided either in options or as the fifth argument, not both"
                        .to_string(),
                ));
            }
            source_id = match value {
                DataType::String(value) => Some(value),
                DataType::None() => None,
                invalid => {
                    return Err(QueryError::InvalidFunctionParameters(format!(
                        "source_id must be a string, got {invalid:?}"
                    )))
                }
            };
        }

        let events = aw_transform::merge_subwatcher_fields(
            base_events,
            subwatcher_events,
            &keys,
            &conflict,
            source_id.as_deref(),
        )
        .map_err(QueryError::InvalidFunctionParameters)?;
        Ok(DataType::List(
            events.into_iter().map(DataType::Event).collect(),
        ))
    }

    pub fn map_event_fields(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let mappings: serde_json::Value = args.next().unwrap().try_into()?;
        let events = aw_transform::map_event_fields(events, &mappings)
            .map_err(QueryError::InvalidFunctionParameters)?;
        Ok(DataType::List(
            events.into_iter().map(DataType::Event).collect(),
        ))
    }

    pub fn chunk_events_by_key(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let key: String = args.next().unwrap().try_into()?;

        let mut merged_events = aw_transform::chunk_events_by_key(events, &key);
        let mut merged_tagged_events = Vec::new();
        for event in merged_events.drain(..) {
            merged_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(merged_tagged_events))
    }

    pub fn filter_keyvals(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 3)?;
        let mut args = args.into_iter();
        let events = args.next().unwrap().try_into()?;
        let key: String = args.next().unwrap().try_into()?;
        let vals: Vec<_> = args.next().unwrap().try_into()?;

        let mut filtered_events = aw_transform::filter_keyvals(events, &key, &vals);
        let mut filtered_tagged_events = Vec::new();
        for event in filtered_events.drain(..) {
            filtered_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(filtered_tagged_events))
    }

    use fancy_regex::RegexBuilder;

    pub fn filter_keyvals_regex(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 3)?;
        let mut args = args.into_iter();
        let events = args.next().unwrap().try_into()?;
        let key: String = args.next().unwrap().try_into()?;
        let regex_str: String = args.next().unwrap().try_into()?;
        let regex = match RegexBuilder::new(&regex_str).build() {
            Ok(regex) => regex,
            Err(e) => {
                return Err(QueryError::RegexCompileError(format!(
                    "Failed to compile regex string '{regex_str}': {e}"
                )))
            }
        };

        let mut filtered_events = aw_transform::filter_keyvals_regex(events, &key, &regex);
        let mut filtered_tagged_events = Vec::new();
        for event in filtered_events.drain(..) {
            filtered_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(filtered_tagged_events))
    }

    pub fn exclude_keyvals(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 3)?;
        let mut args = args.into_iter();
        let events = args.next().unwrap().try_into()?;
        let key: String = args.next().unwrap().try_into()?;
        let vals: Vec<_> = args.next().unwrap().try_into()?;

        let mut filtered_events = aw_transform::exclude_keyvals(events, &key, &vals);
        let mut filtered_tagged_events = Vec::new();
        for event in filtered_events.drain(..) {
            filtered_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(filtered_tagged_events))
    }

    pub fn filter_period_intersect(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let filter_events: Vec<Event> = args.next().unwrap().try_into()?;

        let mut filtered_events = aw_transform::filter_period_intersect(events, filter_events);
        let mut filtered_tagged_events = Vec::new();
        for event in filtered_events.drain(..) {
            filtered_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(filtered_tagged_events))
    }

    pub fn active_periods_v2(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        validate::args_length(&args, 2).or_else(|_| validate::args_length(&args, 3))?;
        let mut args = args.into_iter();
        let named_sources: Vec<DataType> = args.next().unwrap().try_into()?;
        let mut sources = Vec::with_capacity(named_sources.len());
        for source in named_sources {
            let pair: Vec<DataType> = source.try_into()?;
            if pair.len() != 2 {
                return Err(QueryError::InvalidFunctionParameters(
                    "active_periods_v2 named sources must be [source_id, event_list] pairs"
                        .to_string(),
                ));
            }
            let mut pair = pair.into_iter();
            let source_id: String = pair.next().unwrap().try_into()?;
            let events: Vec<Event> = pair.next().unwrap().try_into()?;
            sources.push((source_id, events));
        }
        let expression: serde_json::Value = args.next().unwrap().try_into()?;
        let host: Option<String> = match args.next() {
            Some(DataType::None()) | None => None,
            Some(host) => Some(host.try_into()?),
        };
        let result =
            aw_transform::active_periods_v2_for_host(sources, &expression, host.as_deref())
                .map_err(QueryError::InvalidFunctionParameters)?;
        Ok(DataType::List(
            result.into_iter().map(DataType::Event).collect(),
        ))
    }

    pub fn split_url_events(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 1)?;
        let mut events: Vec<Event> = args.into_iter().next().unwrap().try_into()?;

        let mut tagged_split_url_events = Vec::new();
        for mut event in events.drain(..) {
            aw_transform::split_url_event(&mut event);
            tagged_split_url_events.push(DataType::Event(event));
        }
        Ok(DataType::List(tagged_split_url_events))
    }

    pub fn concat(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        let mut event_list = Vec::new();
        for arg in args {
            let mut events: Vec<Event> = arg.try_into()?;
            for event in events.drain(..) {
                event_list.push(DataType::Event(event));
            }
        }
        Ok(DataType::List(event_list))
    }

    pub fn period_union(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events1: Vec<Event> = args.next().unwrap().try_into()?;
        let events2: Vec<Event> = args.next().unwrap().try_into()?;

        let mut result = aw_transform::period_union(&events1, &events2);
        let mut result_tagged = Vec::new();
        for event in result.drain(..) {
            result_tagged.push(DataType::Event(event));
        }
        Ok(DataType::List(result_tagged))
    }

    pub fn union_no_overlap(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events1: Vec<Event> = args.next().unwrap().try_into()?;
        let events2: Vec<Event> = args.next().unwrap().try_into()?;

        let mut result = aw_transform::union_no_overlap(events1, events2);
        let mut result_tagged = Vec::new();
        for event in result.drain(..) {
            result_tagged.push(DataType::Event(event));
        }
        Ok(DataType::List(result_tagged))
    }
}

mod validate {
    use crate::{DataType, QueryError, VarEnv};
    use aw_models::TimeInterval;

    pub fn args_length(args: &[DataType], len: usize) -> Result<(), QueryError> {
        if args.len() != len {
            return Err(QueryError::InvalidFunctionParameters(format!(
                "Expected {} parameters in function, got {}",
                len,
                args.len()
            )));
        }
        Ok(())
    }

    pub fn get_timeinterval(env: &VarEnv) -> Result<TimeInterval, QueryError> {
        let interval_str = match env.get("TIMEINTERVAL") {
            Some(data_ti) => match data_ti {
                DataType::String(ti_str) => ti_str,
                _ => {
                    return Err(QueryError::TimeIntervalError(
                        "TIMEINTERVAL is not of type string!".to_string(),
                    ))
                }
            },
            None => {
                return Err(QueryError::TimeIntervalError(
                    "TIMEINTERVAL not defined!".to_string(),
                ))
            }
        };
        match TimeInterval::new_from_string(interval_str) {
            Ok(ti) => Ok(ti),
            Err(_e) => Err(QueryError::TimeIntervalError(format!(
                "Failed to parse TIMEINTERVAL: {interval_str}"
            ))),
        }
    }
}
