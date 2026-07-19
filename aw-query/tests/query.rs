extern crate chrono;
extern crate serde_json;

extern crate aw_query;

// TODO: Move me to an appropriate place
#[macro_export]
macro_rules! json_map {
    { $( $key:literal : $value:expr),* } => {{
        use serde_json::Value;
        use serde_json::map::Map;
        #[allow(unused_mut)]
        let mut map : Map<String, Value> = Map::new();
        $(
          map.insert( $key.to_string(), json!($value) );
        )*
        map
    }};
}

#[cfg(test)]
mod query_tests {

    use chrono::Duration;
    use serde_json::json;
    use std::convert::TryFrom;

    use aw_query::DataType;
    use aw_query::QueryError;

    use aw_datastore::Datastore;

    use aw_models::Bucket;
    use aw_models::BucketMetadata;
    use aw_models::Event;
    use aw_models::TimeInterval;

    static TIME_INTERVAL: &str = "1980-01-01T00:00:00Z/2080-01-02T00:00:00Z";
    static BUCKET_ID: &str = "testid";

    fn setup_datastore_empty() -> Datastore {
        Datastore::new_in_memory(false)
    }

    fn setup_datastore_with_bucket() -> Datastore {
        let ds = setup_datastore_empty();
        // Create bucket
        let bucket = Bucket {
            bid: None,
            id: BUCKET_ID.to_string(),
            _type: "testtype".to_string(),
            client: "testclient".to_string(),
            hostname: "testhost".to_string(),
            created: Some(chrono::Utc::now()),
            data: json_map! {},
            metadata: BucketMetadata::default(),
            events: None,
            last_updated: None,
        };
        ds.create_bucket(&bucket).unwrap();
        ds
    }

    fn setup_datastore_populated() -> Datastore {
        let ds = setup_datastore_with_bucket();
        // Insert events
        let e1 = Event {
            id: None,
            timestamp: chrono::Utc::now(),
            duration: Duration::seconds(0),
            data: json_map! {"key": json!("value")},
        };
        let mut e2 = e1.clone();
        e2.timestamp = chrono::Utc::now();
        let mut e_replace = e2.clone();
        e_replace.data = json_map! {"key": json!("value2")};
        e_replace.duration = Duration::seconds(2);

        let event_list = vec![e1, e2];

        ds.insert_events(BUCKET_ID, &event_list).unwrap();

        ds
    }

    macro_rules! assert_err_type {
        ($v:expr, $p:pat) => {
            match $v {
                Ok(_) => panic!("Expected an error, got {:?}", $v),
                Err(e) => match e {
                    $p => (),
                    _ => panic!("Expected an error of another type, got {:?}", e),
                },
            }
        };
    }

    #[test]
    fn test_bool() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = String::from("True;False;a=True;return True;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Bool(b) => assert!(b),
            ref data => panic!("Wrong datatype, {data:?}"),
        };
    }

    #[test]
    fn test_number() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = String::from("1;1.0;return -1.5e2;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, -150.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };
    }

    #[test]
    fn test_equals() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        // number comparison true
        let code = String::from("return 1==1;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Bool(b) => assert!(b),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // number comparison false
        let code = String::from("return  2==1;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Bool(b) => assert!(!b),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // string comparison true
        let code = String::from(r#"return  "a"=="a";"#);
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Bool(b) => assert!(b),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // string comparison false
        let code = String::from(r#"return  "a"=="b";"#);
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Bool(b) => assert!(!b),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // bool comparison true
        let code = String::from("return  True==True;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Bool(b) => assert!(b),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // bool comparison false
        let code = String::from("return  False==True;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Bool(b) => assert!(!b),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // different types comparison (should raise an error)
        let code = String::from("return  True==1;");
        let res = aw_query::query(&code, &interval, &ds);
        assert_err_type!(res, QueryError::InvalidType(_));
    }

    #[test]
    fn test_return() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = String::from("return 1;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, 1.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // Test with old RETURN method
        let code = String::from("RETURN=1;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, 1.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        let code = String::from("return 1+1;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, 2.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };
    }

    #[test]
    fn test_if() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        // Test hardcoded True
        let code = String::from(
            "
            n=1;
            if True { n=2; }
            return n;",
        );
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, 2.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // Test hardcoded False
        let code = String::from(
            "
            n=1;
            if False { n=2; }
            return n;",
        );
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, 1.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // Test expression True
        let code = String::from(
            "
            a=True; n=1;
            if a { n=2; }
            return n;",
        );
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, 2.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // Test expression False
        let code = String::from(
            "
            a=False; n=1;
            if a { n=2; }
            return n;",
        );
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, 1.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // Test if else
        let code = String::from(
            "
            a=False; n=1;
            if a { }
            else { n=3; }
            return n;",
        );
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, 3.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // Test if else if
        let code = String::from(
            "
            a=False; b=True; n=1;
            if a { n=2; }
            elif b { n=3; }
            return n;",
        );
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, 3.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // Test if else if else
        let code = String::from(
            "
            a=False; b=True; n=1;
            if a { n=2; }
            elif a { n=3; }
            else { n=4; }
            return n;",
        );
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, 4.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };

        // Test if inside if
        let code = String::from(
            "
            a=True; n=1;
            if a { if a { n = 2; } }
            return n;",
        );
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::Number(n) => assert_eq!(n, 2.0),
            ref data => panic!("Wrong datatype, {data:?}"),
        };
    }

    #[test]
    fn test_function() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = String::from("return print(1);");
        aw_query::query(&code, &interval, &ds).unwrap();

        let code = String::from("return print(1, 2);");
        aw_query::query(&code, &interval, &ds).unwrap();

        let code = String::from("return no_such_function(1);");
        match aw_query::query(&code, &interval, &ds) {
            Ok(ok) => panic!("Expected QueryError, got {ok:?}"),
            Err(e) => match e {
                QueryError::VariableNotDefined(qe) => assert_eq!(qe, "no_such_function"),
                qe => panic!("Expected QueryError::VariableNotDefined, got {qe:?}"),
            },
        }

        let code = String::from("invalid_type=1; return invalid_type(1);");
        match aw_query::query(&code, &interval, &ds) {
            Ok(ok) => panic!("Expected QueryError, got {ok:?}"),
            Err(e) => match e {
                QueryError::InvalidType(qe) => assert_eq!(qe, "invalid_type"),
                qe => panic!("Expected QueryError::VariableNotDefined, got {qe:?}"),
            },
        }
    }

    #[test]
    fn test_all_functions() {
        let ds = setup_datastore_populated();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = String::from("return query_bucket(\"testid\");");
        aw_query::query(&code, &interval, &ds).unwrap();

        let code = format!(
            r#"
            events = query_bucket(find_bucket("{}", "testhost"));
            events = flood(events);
            events = sort_by_duration(events);
            events = limit_events(events, 10000);
            events = sort_by_timestamp(events);
            events = concat(events, query_bucket("{}"));
            events = concat(events, query_bucket_optional("missing"));
            events = merge_subwatcher_fields(events, events, ["key"], {{ "source_id": "self" }});
            events = map_event_fields(events, {{ "title": "key" }});
            events = categorize(events, [[["test"], {{ "type": "regex", "regex": "value$" }}], [["test", "testing"], {{ "type": "regex", "regex": "value$" }}]]);
            events = categorize_v2(events, [{{ "name": ["test"], "rule": {{ "type": "regex", "host": "testhost", "field": "key", "regex": "value$" }} }}], "testhost");
            events = categorize_v2_explain(events, [{{ "name": ["test"], "data": {{ "color": null }}, "rule": {{ "type": "regex", "host": "testhost", "field": "key", "regex": "value$" }} }}], "testhost");
            events = tag(events, [["testtag", {{ "type": "regex", "regex": "test$" }}], ["another testtag", {{ "type": "regex", "regex": "test-pat$" }}]]);
            total_duration = sum_durations(events);
            bucketnames = query_bucket_names();
            print("test", "test2");
            url_events = split_url_events (events);
            filtered_events = filter_period_intersect(events, events);
            filtered_events = filter_keyvals(events, "$category", [["Uncategorized"]]);
            filtered_events = filter_keyvals_regex(events, "key", "regex");
            chunked_events = chunk_events_by_key(events, "key");
            merged_events = merge_events_by_keys(events, ["key"]);
            return  merged_events;"#,
            "testid", "testid"
        );
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::List(l) => l,
            ref data => panic!("Wrong datatype, {data:?}"),
        };
        // TODO: assert_eq result
    }

    #[test]
    fn test_query_bucket_optional_only_suppresses_missing_buckets() {
        let ds = setup_datastore_populated();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let optional = aw_query::query(
            r#"return query_bucket_optional("missing");"#,
            &interval,
            &ds,
        )
        .unwrap();
        assert!(Vec::<Event>::try_from(&optional).unwrap().is_empty());
        let existing =
            aw_query::query(r#"return query_bucket_optional("testid");"#, &interval, &ds).unwrap();
        assert!(!Vec::<Event>::try_from(&existing).unwrap().is_empty());
        let correct_host = aw_query::query(
            r#"return query_bucket_optional("testid", "testhost");"#,
            &interval,
            &ds,
        )
        .unwrap();
        assert!(!Vec::<Event>::try_from(&correct_host).unwrap().is_empty());
        let wrong_host = aw_query::query(
            r#"return query_bucket_optional("testid", "another-host");"#,
            &interval,
            &ds,
        )
        .unwrap();
        assert!(Vec::<Event>::try_from(&wrong_host).unwrap().is_empty());

        let strict = aw_query::query(r#"return query_bucket("missing");"#, &interval, &ds);
        assert!(matches!(strict, Err(QueryError::BucketQueryError(_))));
    }

    #[test]
    fn test_categorize() {
        let ds = setup_datastore_populated();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = format!(
            r#"
            events = query_bucket("{}");
            events = categorize(events, [[["Test", "Subtest"], {{ "type": "regex", "regex": "^value$" }}]]);
            return  events;"#,
            "testid"
        );
        let result: DataType = aw_query::query(&code, &interval, &ds).unwrap();
        let events: Vec<Event> = Vec::try_from(&result).unwrap();

        let event = events.first().unwrap();
        let cats = event.data.get("$category").unwrap();
        assert_eq!(cats, &serde_json::json!(vec!["Test", "Subtest"]));
    }

    #[test]
    fn test_merge_subwatcher_fields_and_categorize_v2() {
        let ds = setup_datastore_with_bucket();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();
        let event = Event {
            id: None,
            timestamp: chrono::Utc::now(),
            duration: Duration::seconds(10),
            data: json_map! {"key": json!("value")},
        };
        ds.insert_events(BUCKET_ID, &[event]).unwrap();
        let code = format!(
            r#"
            events = query_bucket("{}");
            context = query_bucket("{}");
            events = merge_subwatcher_fields(events, context, ["key"], {{ "source_id": "context" }});
            events = categorize_v2(events, [
                {{
                    "id": "base",
                    "name": ["Base"],
                    "rule": {{ "type": "regex", "field": "key", "regex": "^value$" }}
                }},
                {{
                    "id": "context",
                    "name": ["Context"],
                    "rule": {{
                        "type": "all",
                        "rules": [
                            {{ "type": "regex", "field": "key", "regex": "^value$" }},
                            {{ "type": "regex", "source": "context", "field": "key", "regex": "^value$", "weight": 10 }}
                        ]
                    }}
                }}
            ]);
            return events;"#,
            BUCKET_ID, BUCKET_ID
        );

        let result = aw_query::query(&code, &interval, &ds).unwrap();
        let events: Vec<Event> = Vec::try_from(&result).unwrap();
        assert!(!events.is_empty());
        assert_eq!(events[0].data["$source.context.key"], json!("value"));
        assert_eq!(events[0].data["$category"], json!(["Context"]));
        assert_eq!(events[0].data["$category_score"], json!(10));
        assert_eq!(events[0].data["$category_rule"], json!("context"));
    }

    #[test]
    fn test_context_app_and_title_do_not_replace_canonical_fields() {
        let ds = setup_datastore_empty();
        let now = chrono::Utc::now();
        for bucket_id in ["base", "editor"] {
            ds.create_bucket(&Bucket {
                bid: None,
                id: bucket_id.to_string(),
                _type: "testtype".to_string(),
                client: "testclient".to_string(),
                hostname: "testhost".to_string(),
                created: Some(now),
                data: json_map! {},
                metadata: BucketMetadata::default(),
                events: None,
                last_updated: None,
            })
            .unwrap();
        }
        ds.insert_events(
            "base",
            &[Event {
                id: None,
                timestamp: now,
                duration: Duration::seconds(10),
                data: json_map! {"app": json!("terminal"), "title": json!("shell")},
            }],
        )
        .unwrap();
        ds.insert_events(
            "editor",
            &[Event {
                id: None,
                timestamp: now,
                duration: Duration::seconds(10),
                data: json_map! {"app": json!("code"), "title": json!("project")},
            }],
        )
        .unwrap();

        let code = r#"
            events = query_bucket("base");
            context = query_bucket("editor");
            events = merge_subwatcher_fields(
                events,
                context,
                ["app", "title"],
                {"source_id": "editor"}
            );
            return categorize_v2(events, [
                {
                    "id": "canonical",
                    "name": ["Canonical"],
                    "rule": {"type": "regex", "field": "app", "regex": "^code$"}
                },
                {
                    "id": "context",
                    "name": ["Context"],
                    "rule": {
                        "type": "regex",
                        "source": "editor",
                        "field": "app",
                        "regex": "^code$"
                    }
                }
            ]);"#;

        let result = aw_query::query(
            code,
            &TimeInterval::new_from_string(TIME_INTERVAL).unwrap(),
            &ds,
        )
        .unwrap();
        let events = Vec::<Event>::try_from(&result).unwrap();
        assert_eq!(events[0].data["app"], json!("terminal"));
        assert_eq!(events[0].data["title"], json!("shell"));
        assert_eq!(events[0].data["$source.editor.app"], json!("code"));
        assert_eq!(events[0].data["$source.editor.title"], json!("project"));
        assert_eq!(events[0].data["$category"], json!(["Context"]));
    }

    #[test]
    fn test_active_periods_v2_named_sources_and_negative_predicate() {
        let ds = setup_datastore_with_bucket();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();
        let event = Event {
            id: None,
            timestamp: chrono::Utc::now(),
            duration: Duration::seconds(10),
            data: json_map! {"state": json!("active")},
        };
        ds.insert_events(BUCKET_ID, &[event]).unwrap();
        let code = format!(
            r#"
            afk = query_bucket("{}");
            sources = [["afk", afk]];
            return active_periods_v2(sources, {{
                "source": "afk",
                "host": "testhost",
                "field": "state",
                "regex": "^idle$",
                "negate": true,
                "weight": 1.0
            }}, "testhost");"#,
            BUCKET_ID
        );

        let result = aw_query::query(&code, &interval, &ds).unwrap();
        let events: Vec<Event> = Vec::try_from(&result).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data["state"], json!("active"));
    }

    #[test]
    fn test_active_periods_v2_validation_errors() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let missing_source =
            r#"return active_periods_v2([], {"type": "regex", "regex": "active"});"#;
        let error = aw_query::query(missing_source, &interval, &ds).unwrap_err();
        assert!(format!("{error}").contains("'source'"));

        let unknown_source = r#"
            return active_periods_v2(
                [["afk", []]],
                {"type": "regex", "source": "window", "regex": "active"}
            );"#;
        let error = aw_query::query(unknown_source, &interval, &ds).unwrap_err();
        assert!(format!("{error}").contains("unknown source"));

        let duplicate_source = r#"
            return active_periods_v2(
                [["afk", []], ["afk", []]],
                {"type": "none"}
            );"#;
        let error = aw_query::query(duplicate_source, &interval, &ds).unwrap_err();
        assert!(format!("{error}").contains("duplicate"));
    }

    #[test]
    fn test_v2_function_validation_errors() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let invalid_conflict = r#"return merge_subwatcher_fields([], [], [], "invalid");"#;
        let error = aw_query::query(invalid_conflict, &interval, &ds).unwrap_err();
        assert!(format!("{error}").contains("conflict must be"));

        let invalid_source =
            r#"return merge_subwatcher_fields([], [], [], {"source_id": "invalid.source"});"#;
        let error = aw_query::query(invalid_source, &interval, &ds).unwrap_err();
        assert!(format!("{error}").contains("source_id"));

        let duplicate_source = r#"return merge_subwatcher_fields(
            [], [], [], {"source_id": "options"}, "positional"
        );"#;
        let error = aw_query::query(duplicate_source, &interval, &ds).unwrap_err();
        assert!(format!("{error}").contains("not both"));

        let invalid_priority = r#"return categorize_v2([], [{"name": ["Bad"], "priority": 1.5}]);"#;
        let error = aw_query::query(invalid_priority, &interval, &ds).unwrap_err();
        assert!(format!("{error}").contains("'priority' must be an integer"));

        let cycle = r#"
            return categorize_v2([], [
                {"id": "a", "name": ["A"], "requires": ["b"]},
                {"id": "b", "name": ["B"], "requires": ["a"]}
            ]);"#;
        let error = aw_query::query(cycle, &interval, &ds).unwrap_err();
        assert!(format!("{error}").contains("dependency cycle"));
    }

    #[test]
    fn test_v2_optional_hosts_accept_none() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();
        let code = r#"
            categorized = categorize_v2([], [], None);
            explained = categorize_v2_explain([], [], None);
            active = active_periods_v2([], {"type": "none"}, None);
            return concat(categorized, concat(explained, active));"#;

        let result = aw_query::query(code, &interval, &ds).unwrap();
        assert!(Vec::<Event>::try_from(&result).unwrap().is_empty());
    }

    #[test]
    fn test_tag() {
        let ds = setup_datastore_populated();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = format!(
            r#"
            events = query_bucket("{}");
            events = tag(events, [["testtag", {{ "type": "regex", "regex": "value$" }}], ["another testtag", {{ "type": "regex", "regex": "value$" }}]]);
            return  events;"#,
            "testid"
        );
        let result: DataType = aw_query::query(&code, &interval, &ds).unwrap();
        let events: Vec<Event> = Vec::try_from(&result).unwrap();

        let event = events.first().unwrap();
        let tags = event.data.get("$tags").unwrap().as_array().unwrap();
        assert_eq!(tags.len(), 2);
    }

    #[test]
    fn test_tag_select_keys() {
        let ds = setup_datastore_with_bucket();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let event = Event {
            id: None,
            timestamp: chrono::Utc::now(),
            duration: Duration::seconds(0),
            data: json_map! {
                "app": json!("terminal"),
                "title": json!("just a test"),
                "pid": json!(123)
            },
        };
        ds.insert_events(BUCKET_ID, &[event]).unwrap();

        let code = format!(
            r#"
            events = query_bucket("{}");
            events = tag(events, [["title-match", {{ "type": "regex", "regex": "test$", "select_keys": ["title"] }}], ["app-match", {{ "type": "regex", "regex": "test$", "select_keys": ["app"] }}], ["pid-match", {{ "type": "regex", "regex": "123", "select_keys": ["pid"] }}], ["missing-match", {{ "type": "regex", "regex": "test", "select_keys": ["missing"] }}]]);
            return  events;"#,
            BUCKET_ID
        );
        let result: DataType = aw_query::query(&code, &interval, &ds).unwrap();
        let events: Vec<Event> = Vec::try_from(&result).unwrap();

        let event = events.first().unwrap();
        let tags = event.data.get("$tags").unwrap();
        assert_eq!(tags, &serde_json::json!(vec!["title-match"]));
    }

    #[test]
    fn test_rule_parsing() {
        let ds = setup_datastore_populated();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        // Test rule where rule is not a dict
        let code = r#"
            events = [];
            events = tag(events, ["test", false]);
            return  events;"#;
        let res = aw_query::query(code, &interval, &ds);
        assert_err_type!(res, QueryError::InvalidFunctionParameters(_));

        // Test rule without type
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { }]]);
            return  events;"#;
        let res = aw_query::query(code, &interval, &ds);
        assert_err_type!(res, QueryError::InvalidFunctionParameters(_));

        // Test invalid rule type
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { "type": false }]]);
            return  events;"#;
        let res = aw_query::query(code, &interval, &ds);
        assert_err_type!(res, QueryError::InvalidFunctionParameters(_));

        // Test invalid rule name
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { "type": "rgex" }]]);
            return  events;"#;
        let res = aw_query::query(code, &interval, &ds);
        assert_err_type!(res, QueryError::InvalidFunctionParameters(_));

        // Test "none" rule type
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { "type": "none" }]]);
            return  events;"#;
        aw_query::query(code, &interval, &ds).unwrap();

        // Test regex rule where regex field has wrong type
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { "type": "regex", "regex": true }]]);
            return  events;"#;
        let res = aw_query::query(code, &interval, &ds);
        assert_err_type!(res, QueryError::InvalidFunctionParameters(_));

        // Test regex rule where regex field is not set
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { "type": "regex" }]]);
            return  events;"#;
        let res = aw_query::query(code, &interval, &ds);
        assert_err_type!(res, QueryError::InvalidFunctionParameters(_));

        // Test regex rule with ignore_case field
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { "type": "regex", "regex": "test", "ignore_case": false }]]);
            return  events;"#;
        aw_query::query(code, &interval, &ds).unwrap();

        // Test regex rule with valid select_keys field
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { "type": "regex", "regex": "test", "select_keys": ["key"] }]]);
            return  events;"#;
        aw_query::query(code, &interval, &ds).unwrap();

        // Test regex rule where ignore_case field is of invalid type
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { "type": "regex", "regex": "test", "ignore_case": "" }]]);
            return  events;"#;
        let res = aw_query::query(code, &interval, &ds);
        assert_err_type!(res, QueryError::InvalidFunctionParameters(_));

        // Test regex rule where select_keys field is of invalid type
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { "type": "regex", "regex": "test", "select_keys": "key" }]]);
            return  events;"#;
        let res = aw_query::query(code, &interval, &ds);
        assert_err_type!(res, QueryError::InvalidFunctionParameters(_));

        // Test regex rule where select_keys contains non-string values
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { "type": "regex", "regex": "test", "select_keys": ["key", false] }]]);
            return  events;"#;
        let res = aw_query::query(code, &interval, &ds);
        assert_err_type!(res, QueryError::InvalidFunctionParameters(_));

        // Test regex rule where uncompilable regex is supplied
        let code = r#"
            events = [];
            events = tag(events, [["testtag", { "type": "regex", "regex": "!#¤%&/(=" }]]);
            return  events;"#;
        let res = aw_query::query(code, &interval, &ds);
        assert_err_type!(res, QueryError::RegexCompileError(_));
    }

    #[test]
    fn test_string() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = String::from("return \"test \\\" with escaped quote\";");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::String(s) => assert_eq!(s, "test \" with escaped quote"),
            _ => panic!("Wrong datatype"),
        }

        let code = String::from(r#"return "path\\";"#);
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::String(s) => assert_eq!(s, r"path\\"),
            _ => panic!("Wrong datatype"),
        }

        let code = String::from(r#"return "\w+";"#);
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::String(s) => assert_eq!(s, r"\w+"),
            _ => panic!("Wrong datatype"),
        }

        let code = String::from(r#"return "a\\\"b";"#);
        match aw_query::query(&code, &interval, &ds).unwrap() {
            aw_query::DataType::String(s) => assert_eq!(s, "a\\\"b"),
            _ => panic!("Wrong datatype"),
        }
    }

    #[test]
    fn test_list() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = String::from("return [];");
        aw_query::query(&code, &interval, &ds).unwrap();

        let code = String::from("return [1];");
        aw_query::query(&code, &interval, &ds).unwrap();

        let code = String::from("return [1+1];");
        aw_query::query(&code, &interval, &ds).unwrap();

        let code = String::from("return [1,1];");
        aw_query::query(&code, &interval, &ds).unwrap();

        let code = String::from("return [1,1+2];");
        aw_query::query(&code, &interval, &ds).unwrap();

        let code = String::from("return [1,1+1,1+2+3,4/3,[1+2]];");
        aw_query::query(&code, &interval, &ds).unwrap();
    }

    #[test]
    fn test_comment() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = String::from("return 1;# testing 123");
        aw_query::query(&code, &interval, &ds).unwrap();
    }

    #[test]
    fn test_dict() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = String::from("return {};");
        aw_query::query(&code, &interval, &ds).unwrap();

        let code = String::from("return {\"test\": 2};");
        aw_query::query(&code, &interval, &ds).unwrap();

        let code = String::from("return {\"test\": 2, \"test2\": \"teststr\"};");
        aw_query::query(&code, &interval, &ds).unwrap();

        let code = String::from("return {\"test\": {\"test\": \"test\"}};");
        aw_query::query(&code, &interval, &ds).unwrap();
    }

    #[test]
    fn test_concat() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        // Append lists
        let code = String::from("return [1]+[2];");
        let res = aw_query::query(&code, &interval, &ds).unwrap();
        let v = vec![DataType::Number(1.0), DataType::Number(2.0)];
        assert_eq!(res, DataType::List(v));

        // Append strings
        let code = String::from(r#"return "a"+"b";"#);
        let res = aw_query::query(&code, &interval, &ds).unwrap();
        assert_eq!(res, DataType::String("ab".to_string()));
    }

    #[test]
    fn test_contains() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        // test list true
        let code = String::from(r#"a = ["b", "a"]; return contains(a, "a");"#);
        let res = aw_query::query(&code, &interval, &ds).unwrap();
        assert_eq!(res, DataType::Bool(true));

        // test list false
        let code = String::from(r#"a = ["b", "a"]; return contains(a, "c");"#);
        let res = aw_query::query(&code, &interval, &ds).unwrap();
        assert_eq!(res, DataType::Bool(false));

        // test dict true
        let code = String::from(r#"a = {"a": 1}; return contains(a, "a");"#);
        let res = aw_query::query(&code, &interval, &ds).unwrap();
        assert_eq!(res, DataType::Bool(true));

        // test dict false
        let code = String::from(r#"a = {"b": 1}; return contains(a, "a");"#);
        let res = aw_query::query(&code, &interval, &ds).unwrap();
        assert_eq!(res, DataType::Bool(false));
    }

    #[test]
    fn test_math() {
        let ds = setup_datastore_empty();
        let interval = TimeInterval::new_from_string(TIME_INTERVAL).unwrap();

        let code = String::from("return 1+1;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            DataType::Number(n) => assert_eq!(n, 2.0),
            num => panic!("Expected number, got {num:?}"),
        };

        let code = String::from("return 1-1;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            DataType::Number(n) => assert_eq!(n, 0.0),
            num => panic!("Expected number, got {num:?}"),
        };

        let code = String::from("return 3*5;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            DataType::Number(n) => assert_eq!(n, 15.0),
            num => panic!("Expected number, got {num:?}"),
        };

        let code = String::from("return 4/2;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            DataType::Number(n) => assert_eq!(n, 2.0),
            num => panic!("Expected number, got {num:?}"),
        };

        let code = String::from("return 1/0;");
        let res = aw_query::query(&code, &interval, &ds);
        assert_err_type!(res, QueryError::MathError(_));

        let code = String::from("return 2.5%1;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            DataType::Number(n) => assert_eq!(n, 0.5),
            num => panic!("Expected number, got {num:?}"),
        };

        let code = String::from("return 1+1+0+1;");
        match aw_query::query(&code, &interval, &ds).unwrap() {
            DataType::Number(n) => assert_eq!(n, 3.0),
            num => panic!("Expected number, got {num:?}"),
        };
    }
}
