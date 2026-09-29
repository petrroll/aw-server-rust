extern crate log;

extern crate rocket;

extern crate aw_datastore;
extern crate aw_server;

#[cfg(test)]
mod api_tests {
    use std::collections::HashMap;

    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};

    use aw_server::config;
    use aw_server::endpoints;

    use aw_models::{Bucket, BucketsExport};
    use rocket::local::blocking::Client;

    fn setup_testserver() -> rocket::Rocket<rocket::Build> {
        let state = endpoints::ServerState {
            datastore: aw_datastore::Datastore::new_in_memory(false),
            asset_resolver: endpoints::AssetResolver::new(None),
            device_id: "test_id".to_string(),
        };
        let aw_config = config::AWConfig::default();
        endpoints::build_rocket(state, aw_config)
    }

    #[test]
    fn test_info_advertises_rule_engine_capabilities() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");
        let response = client
            .get("/api/0/info")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let info: Value = serde_json::from_str(&response.into_string().unwrap()).unwrap();
        assert_eq!(
            info["capabilities"],
            json!([
                "settings.rules_v2.v1",
                "query.categorize_v2.v1",
                "query.categorize_v2_explain.v1",
                "query.active_periods_v2.v1",
                "query.merge_subwatcher_fields.source_namespace.v1",
                "query.map_event_fields.v1",
                "query.query_bucket_optional.expected_hostname.v1",
                "query.query_bucket_optional_raw.v1",
                "query.query_period.v1",
                "query.flood_v2.v1"
            ])
        );
    }

    #[test]
    fn test_bucket() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        // Get empty list of buckets
        let mut res = client
            .get("/api/0/buckets/")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let buckets: HashMap<String, Bucket> =
            serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(buckets.len(), 0);

        // Try to fetch non-existing bucket
        res = client
            .get("/api/0/buckets/id")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::NotFound);

        // Create bucket
        res = client
            .post("/api/0/buckets/id")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{
                "id": "id",
                "type": "type",
                "client": "client",
                "hostname": "hostname"
            }"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        // Try to create bucket which already exists
        res = client
            .post("/api/0/buckets/id")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{
                "id": "id",
                "type": "type",
                "client": "client",
                "hostname": "hostname"
            }"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::NotModified);
        assert_eq!(
            res.into_string().unwrap(),
            r#"{"message":"Bucket 'id' already exists"}"#
        );

        // Get list of buckets (1 bucket)
        res = client
            .get("/api/0/buckets/")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let buckets: HashMap<String, Bucket> =
            serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(buckets.len(), 1);
        let bucket = buckets.get("id").unwrap();
        assert_eq!(bucket.id, "id");
        assert_eq!(bucket._type, "type");
        assert_eq!(bucket.client, "client");
        assert_eq!(bucket.hostname, "hostname");
        assert!(bucket.events.is_none());
        assert_eq!(bucket.metadata.start, None);
        assert_eq!(bucket.metadata.end, None);

        // Get newly created bucket
        res = client
            .get("/api/0/buckets/id")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        // Validate output
        let bucket: Bucket = serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(bucket.id, "id");
        assert_eq!(bucket._type, "type");
        assert_eq!(bucket.client, "client");
        assert_eq!(bucket.hostname, "hostname");
        assert!(bucket.events.is_none());
        assert_eq!(bucket.metadata.start, None);
        assert_eq!(bucket.metadata.end, None);

        // Get non-existing bucket
        res = client
            .get("/api/0/buckets/invalid_bucket")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::NotFound);

        // Delete bucket
        res = client
            .delete("/api/0/buckets/id")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        // Try (and fail) to get deleted bucket
        res = client
            .get("/api/0/buckets/id")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::NotFound);

        // Get empty list of buckets
        let res = client
            .get("/api/0/buckets/")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let buckets: HashMap<String, Bucket> =
            serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(buckets.len(), 0);
    }

    #[test]
    fn test_events() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        // Create bucket
        let res = client
            .post("/api/0/buckets/id")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{
                "id": "id",
                "type": "type",
                "client": "client",
                "hostname": "hostname"
            }"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        // Insert a single event
        let res = client
            .post("/api/0/buckets/id/events")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"[{
                "timestamp": "2018-01-01T01:01:01Z",
                "duration": 1.0,
                "data": {}
            }]"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        assert_eq!(
            res.into_string().unwrap(),
            r#"[{"id":1,"timestamp":"2018-01-01T01:01:01Z","duration":1.0,"data":{}}]"#
        );

        // Get inserted event
        let res = client
            .get("/api/0/buckets/id/events")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        assert_eq!(
            res.into_string().unwrap(),
            r#"[{"id":1,"timestamp":"2018-01-01T01:01:01Z","duration":1.0,"data":{}}]"#
        );

        // Heartbeat
        let res = client
            .post("/api/0/buckets/id/heartbeat?pulsetime=2")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{
                "timestamp": "2018-01-01T01:01:02Z",
                "duration": 1.0,
                "data": {}
            }"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        // After the fix for #559, the heartbeat response includes the DB event ID
        assert_eq!(
            res.into_string().unwrap(),
            r#"{"id":1,"timestamp":"2018-01-01T01:01:01Z","duration":2.0,"data":{}}"#
        );

        // Get heartbeat event
        let res = client
            .get("/api/0/buckets/id/events")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        assert_eq!(
            res.into_string().unwrap(),
            r#"[{"id":1,"timestamp":"2018-01-01T01:01:01Z","duration":2.0,"data":{}}]"#
        );

        // Delete event
        client
            .delete("/api/0/buckets/id/events/1")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();

        // Get eventcount
        let res = client
            .get("/api/0/buckets/id/events/count")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        assert_eq!(res.into_string().unwrap(), "0");

        // Delete bucket
        let res = client
            .delete("/api/0/buckets/id")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
    }

    #[test]
    fn test_import_export() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        // Import bucket
        let res = client
            .post("/api/0/import")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{"buckets":
            {"id1": {
                "id": "id1",
                "type": "type",
                "client": "client",
                "hostname": "hostname",
                "events": [{
                    "timestamp":"2000-01-01T00:00:00Z",
                    "duration":1.0,
                    "data": {}
                }]
            }}}"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        // Import already existing bucket with a new event — should merge instead of fail
        let res = client
            .post("/api/0/import")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{"buckets":
            {"id1": {
                "id": "id1",
                "type": "type",
                "client": "client",
                "hostname": "hostname",
                "events": [{
                    "timestamp":"2000-01-02T00:00:00Z",
                    "duration":1.0,
                    "data": {}
                }]
            }}}"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        // Verify events were merged — bucket should now have 2 events
        let res = client
            .get("/api/0/buckets/id1/events")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let events: serde_json::Value = serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(events.as_array().unwrap().len(), 2);

        // Re-import the first event again — should be idempotent (no duplicate created)
        let res = client
            .post("/api/0/import")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{"buckets":
            {"id1": {
                "id": "id1",
                "type": "type",
                "client": "client",
                "hostname": "hostname",
                "events": [{
                    "timestamp":"2000-01-01T00:00:00Z",
                    "duration":1.0,
                    "data": {}
                }]
            }}}"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        // Count should still be 2, not 3 — re-import is idempotent
        let res = client
            .get("/api/0/buckets/id1/events")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let events: serde_json::Value = serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(
            events.as_array().unwrap().len(),
            2,
            "Re-importing the same event should be idempotent"
        );

        // Import a narrower event fully contained within an existing longer event.
        // This should be preserved as a distinct event, not dropped by clipped dedup.
        let res = client
            .post("/api/0/import")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{"buckets":
            {"id1": {
                "id": "id1",
                "type": "type",
                "client": "client",
                "hostname": "hostname",
                "events": [{
                    "timestamp":"2000-01-01T00:00:30Z",
                    "duration":30.0,
                    "data": {}
                }]
            }}}"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        let res = client
            .get("/api/0/buckets/id1/events")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let events: serde_json::Value = serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(
            events.as_array().unwrap().len(),
            3,
            "Contained event should not be dropped by clipped dedup"
        );

        // Export single created bucket
        let res = client
            .get("/api/0/buckets/id1/export")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let export: BucketsExport = serde_json::from_str(&res.into_string().unwrap()).unwrap();

        // Delete bucket so we can import it again
        let res = client
            .delete("/api/0/buckets/id1")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        // Import exported bucket again but with multipart/form-data
        let boundary_start = b"--a\r\n";
        let disposition = b"Content-Disposition: form-data; name=\"buckets.json\"\r\n";
        let content_type = b"Content-Type: application/json\r\n";
        let data_start = b"\r\n";
        let content = serde_json::to_vec(&export).unwrap();
        let boundary_end = b"\r\n--a--";
        let sum = [
            &boundary_start[..],
            &disposition[..],
            &content_type[..],
            &data_start[..],
            &content[..],
            &boundary_end[..],
        ]
        .concat();

        let res = client
            .post("/api/0/import")
            .header(Header::new(
                "Content-Type",
                "multipart/form-data; boundary=a",
            ))
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(&sum[..])
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        // Get created bucket
        let res = client
            .get("/api/0/buckets/id1")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        println!("{:?}", res.into_string());

        // Export all buckets
        let res = client
            .get("/api/0/export")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let export: BucketsExport = serde_json::from_str(&res.into_string().unwrap()).unwrap();
        let mut buckets = export.buckets;
        assert_eq!(buckets.len(), 1);
        let b = buckets.remove("id1").unwrap();
        assert_eq!(
            b.events.unwrap().take_inner().len(),
            3,
            "Export should preserve the contained event added during merge testing"
        );

        assert_eq!(buckets.len(), 0);
    }

    #[test]
    fn test_query() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        // Minimal query
        let res = client
            .post("/api/0/query")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{
                "timeperiods": ["2000-01-01T00:00:00Z/2020-01-01T00:00:00Z"],
                "query": ["return 1;"]
            }"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        assert_eq!(res.into_string().unwrap(), r#"[1.0]"#);

        // Create bucket to query later
        let res = client
            .post("/api/0/buckets/id")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{
                "id": "id",
                "type": "type",
                "client": "client",
                "hostname": "hostname"
            }"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        // Insert a event to query later
        let res = client
            .post("/api/0/buckets/id/events")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"[{
                "timestamp": "2018-01-01T01:01:01Z",
                "duration": 1.0,
                "data": {}
            }]"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        // Query events
        let res = client
            .post("/api/0/query")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{
                "timeperiods": ["2000-01-01T00:00:00Z/2020-01-01T00:00:00Z"],
                "query": ["return query_bucket(\"id\");"]
            }"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        assert_eq!(
            res.into_string().unwrap(),
            r#"[[{"data":{},"duration":1.0,"id":1,"timestamp":"2018-01-01T01:01:01Z"}]]"#
        );

        let res = client
            .post("/api/0/buckets/id/events")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                json!([{
                    "timestamp": "2018-01-01T01:01:02Z",
                    "duration": 1.0,
                    "data": {"value": format!("{}!", "a".repeat(30))}
                }])
                .to_string(),
            )
            .dispatch();
        assert_eq!(res.status(), Status::Ok);
        let res = client
            .post("/api/0/query")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                json!({
                    "timeperiods": ["2000-01-01T00:00:00Z/2020-01-01T00:00:00Z"],
                    "query": [r#"events = query_bucket("id"); return categorize(events, [[["Runtime error"], {"type":"regex","regex":"^(a+)+(?=b)$|^a+!$","select_keys":["value"]}]]);"#]
                })
                .to_string(),
            )
            .dispatch();
        assert_eq!(res.status(), Status::BadRequest);
        let body = res.into_string().unwrap();
        assert!(body.contains("regex execution failed"), "{body}");

        let rules = (0..1001)
            .map(|index| format!(r#"[["Category {index}"], {{"type":"regex","regex":"x"}}]"#))
            .collect::<Vec<_>>()
            .join(",");
        let res = client
            .post("/api/0/query")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                json!({
                    "timeperiods": ["2000-01-01T00:00:00Z/2020-01-01T00:00:00Z"],
                    "query": [format!("return categorize([], [{rules}]);")]
                })
                .to_string(),
            )
            .dispatch();
        assert_eq!(res.status(), Status::Ok);

        // Test error
        let res = client
            .post("/api/0/query")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(
                r#"{
                "timeperiods": ["2000-01-01T00:00:00Z/2020-01-01T00:00:00Z"],
                "query": [""]
            }"#,
            )
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::BadRequest);
        assert_eq!(
            res.into_string().unwrap(),
            r#"{"type":"QueryInterpretException","message":"EmptyQuery"}"#
        );
    }

    fn set_setting_request(client: &Client, key: &str, value: &Value) -> Status {
        let body = serde_json::to_string(value).unwrap();
        let res = client
            .post(format!("/api/0/settings/{}", key))
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(body)
            .dispatch();
        res.status()
    }

    #[test]
    fn test_illegally_long_key() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        // Test getting not found (getting nonexistent key)
        let key = "thisisaverylongkthisisaverylongkthisisaverylongkthisisaverylongkthisisaverylongkthisisaverylongkthisisaverylongkthisisaverylongk";
        let value = json!("test_value");
        let res = set_setting_request(&client, key, &value);
        assert_eq!(res, rocket::http::Status::BadRequest);
    }

    #[test]
    fn test_setting_setting() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        // Test value creation
        let key = "test_key";
        let value = json!("test_value");
        let response_status = set_setting_request(&client, key, &value);
        assert_eq!(response_status, rocket::http::Status::Created);
    }

    #[test]
    fn test_get_unset_setting() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        // Test getting not found (getting nonexistent key)
        let key = "non_existent_key";
        let res = client
            .get(format!("/api/0/settings/{}", key))
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        assert_eq!(res.into_string().unwrap(), "null")
    }

    #[test]
    fn test_get_settings() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        let key1 = "test_key";
        let key2 = "test_key_2";
        let value = json!("test_value");
        let response1_status = set_setting_request(&client, key1, &value);
        assert_eq!(response1_status, rocket::http::Status::Created);
        let response2_status = set_setting_request(&client, key2, &value);
        assert_eq!(response2_status, rocket::http::Status::Created);

        let res = client
            .get("/api/0/settings")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();

        assert_eq!(res.status(), rocket::http::Status::Ok);

        let deserialized: Value = serde_json::from_str(&res.into_string().unwrap()).unwrap();
        let expected: Value =
            serde_json::from_str(r#"{"test_key_2":"test_value","test_key":"test_value"}"#).unwrap();
        assert_eq!(deserialized, expected);
    }

    #[test]
    fn test_get_setting() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        let key = "test_key";
        let value = json!("test_value");
        let response_status = set_setting_request(&client, key, &value);
        assert_eq!(response_status, rocket::http::Status::Created);

        // Test getting
        let res = client
            .get(format!("/api/0/settings/{}", key))
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let deserialized: Value = serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(deserialized, value);
    }

    #[test]
    fn test_get_setting_list() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        // Test array
        let key = "test_key_array";
        let value = json!([1, 2, 3]);
        let response_status = set_setting_request(&client, key, &value);
        assert_eq!(response_status, rocket::http::Status::Created);

        let res = client
            .get(format!("/api/0/settings/{}", key))
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let deserialized: Value = serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(deserialized, value);
    }

    #[test]
    fn test_get_setting_dict() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        // Test dict
        let key = "test_key_dict";
        let value = json!({"key": "value", "another_key": "another value"});
        let response_status = set_setting_request(&client, key, &value);
        assert_eq!(response_status, rocket::http::Status::Created);

        let res = client
            .get("/api/0/settings/test_key_dict")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let deserialized: Value = serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(deserialized, value);
    }

    #[test]
    fn test_set_setting() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        let key = "test_key";
        let value1 = json!("test_value");
        let value2 = json!("changed_test_value");
        let post_1_status = set_setting_request(&client, key, &value1);
        assert_eq!(post_1_status, rocket::http::Status::Created);

        let res = client
            .get(format!("/api/0/settings/{}", key))
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        let deserialized: Value = serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(deserialized, value1);

        let post_2_status = set_setting_request(&client, key, &value2);
        assert_eq!(post_2_status, rocket::http::Status::Created);

        let res = client
            .get("/api/0/settings/test_key")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        let new_deserialized: Value = serde_json::from_str(&res.into_string().unwrap()).unwrap();
        assert_eq!(new_deserialized, value2);
    }

    #[test]
    fn test_delete_setting() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        let value = json!("test_value");
        let response_status = set_setting_request(&client, "test_key", &value);
        assert_eq!(response_status, rocket::http::Status::Created);

        // Test deleting
        let res = client
            .delete("/api/0/settings/test_key")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);

        let res = client
            .get("/api/0/settings/test_key")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
        assert_eq!(res.into_string().unwrap(), "null");
    }

    fn rules_document(revision: u64, advanced: bool) -> Value {
        let rule = if advanced {
            json!({
                "type": "all",
                "rules": [{
                    "type": "regex",
                    "regex": "Editor",
                    "source": "builtin_window",
                    "field": "app"
                }]
            })
        } else {
            json!({"type": "regex", "regex": "Editor", "weight": 0})
        };
        json!({
            "revision": revision,
            "activity_profiles_v2": [{
                "schema_version": 2,
                "id": "default",
                "category_set_ids": ["work", "private"],
                "sources": [{
                    "id": "builtin_window",
                    "label": "App & window",
                    "bucket_ids": [],
                    "builtin": "window",
                    "fields": ["app", "title"],
                    "creates_activity": true,
                    "interval_policy": "heartbeat"
                }],
                "app_title_source_id": "builtin_window",
                "browser_focus_source_id": "builtin_window",
                "active_time": {
                    "type": "legacy",
                    "use_afk": true,
                    "include_audible": true,
                    "always_active_pattern": "meeting"
                }
            }],
            "category_sets_v2": [{
                "schema_version": 2,
                "id": "work",
                "categories": [{
                    "id": "work:Work",
                    "name": ["Work"],
                    "rule": rule,
                    "simple_ui": !advanced
                }]
            }, {
                "schema_version": 2,
                "id": "private",
                "categories": [{
                    "id": "private:Media",
                    "name": ["Media"],
                    "rule": {"type": "none"},
                    "simple_ui": true
                }, {
                    "id": "private:Work",
                    "name": ["Work"],
                    "rule": {"type": "none"},
                    "simple_ui": true
                }]
            }]
        })
    }

    fn compile_native_rules(document: &Value) -> Result<(), String> {
        let capabilities = [
            "query.query_bucket_optional_raw.v1",
            "query.query_period.v1",
            "query.flood_v2.v1",
            "query.merge_subwatcher_fields.source_namespace.v1",
            "query.active_periods_v2.v1",
            "query.categorize_v2.v1",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let mut request = aw_client_rust::rules_v2::ProfileQueryRequest::for_hostname("host");
        request.filter_afk = false;
        aw_client_rust::rules_v2::compile_profile_v2(
            document,
            &HashMap::new(),
            capabilities,
            &request,
        )
        .map(|_| ())
    }

    fn post_rules(client: &Client, document: &Value) -> (Status, Value) {
        let response = client
            .post("/api/0/settings/rules_v2")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(serde_json::to_string(document).unwrap())
            .dispatch();
        let status = response.status();
        let body = response
            .into_string()
            .map(|body| serde_json::from_str(&body).unwrap())
            .unwrap_or(Value::Null);
        (status, body)
    }

    #[test]
    fn test_rules_v2_cas_and_derived_gets() {
        let client = Client::untracked(setup_testserver()).expect("valid instance");
        let missing = client
            .get("/api/0/settings/rules_v2")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(missing.status(), Status::NotFound);

        assert_eq!(
            set_setting_request(&client, "theme", &json!("dark")),
            Status::Created
        );
        let (status, stored) = post_rules(&client, &rules_document(0, false));
        assert_eq!(status, Status::Ok);
        assert_eq!(stored["revision"], 1);

        let response = client
            .get("/api/0/settings")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let settings: Value = serde_json::from_str(&response.into_string().unwrap()).unwrap();
        assert_eq!(settings["theme"], "dark");
        assert_eq!(settings["rules_v2"], stored);
        assert_eq!(settings["active_set_ids"], json!(["work", "private"]));
        assert_eq!(
            settings["classes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|category| category["name"].clone())
                .collect::<Vec<_>>(),
            vec![json!(["Work"]), json!(["Media"])]
        );
        assert_eq!(settings["always_active_pattern"], "meeting");

        let stale = rules_document(0, false);
        let (status, message) = post_rules(&client, &stale);
        assert_eq!(status, Status::Conflict);
        assert!(message["message"]
            .as_str()
            .unwrap()
            .contains("current revision is 1"));
    }

    #[test]
    fn test_rules_v2_rejects_partial_and_lossy_legacy_writes() {
        let client = Client::untracked(setup_testserver()).expect("valid instance");
        assert_eq!(
            set_setting_request(&client, "activity_profiles_v2", &json!([{"old": true}])),
            Status::Created
        );
        let (status, _) = post_rules(&client, &rules_document(0, true));
        assert_eq!(status, Status::Ok);

        assert_eq!(
            set_setting_request(&client, "activity_profiles_v2", &json!([])),
            Status::Conflict
        );
        assert_eq!(
            set_setting_request(&client, "classes", &json!([])),
            Status::Conflict
        );

        // Compatibility reads shadow, but do not delete, the persisted predecessor value.
        let response = client
            .get("/api/0/settings/activity_profiles_v2")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let projected: Value = serde_json::from_str(&response.into_string().unwrap()).unwrap();
        assert_eq!(projected[0]["id"], "default");
    }

    #[test]
    fn test_rules_v2_safe_legacy_write_and_if_match() {
        let client = Client::untracked(setup_testserver()).expect("valid instance");
        let mut initial = rules_document(0, false);
        initial["activity_profiles_v2"][0]["category_set_ids"] = json!(["work"]);
        assert_eq!(post_rules(&client, &initial).0, Status::Ok);

        assert_eq!(
            set_setting_request(&client, "classes", &json!({"broken": true})),
            Status::BadRequest
        );

        let response = client
            .post("/api/0/settings/classes")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .header(Header::new("If-Match", "W/\"1\""))
            .body(
                json!([{
                    "name": ["Changed"],
                    "rule": {"type": "regex", "regex": "Terminal", "select_keys": ["app"]}
                }])
                .to_string(),
            )
            .dispatch();
        assert_eq!(response.status(), Status::Created);

        let response = client
            .get("/api/0/settings/rules_v2")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        let stored: Value = serde_json::from_str(&response.into_string().unwrap()).unwrap();
        assert_eq!(stored["revision"], 2);
        assert_eq!(
            stored["category_sets_v2"][0]["categories"][0]["name"],
            json!(["Changed"])
        );
        assert_eq!(stored["category_sets_v2"][1]["id"], "private");

        let stale = client
            .post("/api/0/settings/always_active_pattern?revision=1")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .body(json!("call").to_string())
            .dispatch();
        assert_eq!(stale.status(), Status::Conflict);
    }

    #[test]
    fn test_rules_v2_rejects_wrong_optional_types_without_changing_document() {
        let client = Client::untracked(setup_testserver()).expect("valid instance");
        let (status, stored) = post_rules(&client, &rules_document(0, false));
        assert_eq!(status, Status::Ok);
        compile_native_rules(&stored).unwrap();

        let paths = [
            "/category_sets_v2/0/categories/0/rule/value_mode",
            "/activity_profiles_v2/0/sources/0/interval_policy",
            "/activity_profiles_v2/0/sources/0/builtin",
            "/activity_profiles_v2/0/sources/0/scope",
        ];
        let wrong_types = [
            Value::Null,
            json!(42),
            json!([]),
            json!({}),
            json!(true),
            json!("bogus"),
        ];
        for path in paths {
            for wrong_type in &wrong_types {
                let mut invalid = stored.clone();
                let (parent, key) = path.rsplit_once('/').unwrap();
                invalid
                    .pointer_mut(parent)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(key.to_string(), wrong_type.clone());
                assert_eq!(post_rules(&client, &invalid).0, Status::BadRequest);

                let response = client
                    .get("/api/0/settings/rules_v2")
                    .header(Header::new("Host", "127.0.0.1:5600"))
                    .dispatch();
                let unchanged: Value =
                    serde_json::from_str(&response.into_string().unwrap()).unwrap();
                assert_eq!(unchanged, stored);
                compile_native_rules(&unchanged).unwrap();
            }
        }

        for wrong_type in [
            Value::Null,
            json!(42),
            json!([]),
            json!(true),
            json!("bogus"),
        ] {
            let mut invalid = stored.clone();
            invalid["activity_profiles_v2"][0]["sources"][0]["bucket_hosts"] = wrong_type;
            assert_eq!(post_rules(&client, &invalid).0, Status::BadRequest);
        }

        let mut deferred_ownership = stored.clone();
        deferred_ownership["activity_profiles_v2"][0]["sources"][0]["scope"] = json!("host");
        deferred_ownership["activity_profiles_v2"][0]["sources"][0]["bucket_hosts"] = json!({});
        let (status, deferred_ownership) = post_rules(&client, &deferred_ownership);
        assert_eq!(status, Status::Ok);
        compile_native_rules(&deferred_ownership).unwrap();
    }

    #[test]
    fn test_irrelevant_expression_metadata_is_not_walked() {
        for metadata in [
            Value::Null,
            json!(42),
            json!(true),
            json!({"not": "children"}),
            json!([{
                "type": "regex", "regex": ".", "source": "unavailable"
            }]),
        ] {
            let client = Client::untracked(setup_testserver()).expect("valid instance");
            let mut document = rules_document(0, false);
            document["category_sets_v2"][0]["categories"][0]["rule"]["rules"] = metadata;
            let (status, stored) = post_rules(&client, &document);
            assert_eq!(status, Status::Ok);
            compile_native_rules(&stored).unwrap();
        }
    }

    #[test]
    fn test_legacy_writes_use_typed_validation_errors() {
        let client = Client::untracked(setup_testserver()).expect("valid instance");
        let mut initial = rules_document(0, false);
        initial["activity_profiles_v2"][0]["category_set_ids"] = json!(["work"]);
        let (status, stored) = post_rules(&client, &initial);
        assert_eq!(status, Status::Ok);

        for unknown in ["missing", "would discard", "cannot represent"] {
            assert_eq!(
                set_setting_request(&client, "active_set_ids", &json!([unknown])),
                Status::BadRequest
            );
        }
        assert_eq!(
            set_setting_request(
                &client,
                "classes",
                &json!([{"name": ["Changed"], "rule": 42}]),
            ),
            Status::BadRequest
        );

        let response = client
            .get("/api/0/settings/rules_v2")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        let unchanged: Value = serde_json::from_str(&response.into_string().unwrap()).unwrap();
        assert_eq!(unchanged, stored);
    }

    #[test]
    fn test_rules_v2_rejects_out_of_range_ranking_integers() {
        let client = Client::untracked(setup_testserver()).expect("valid instance");
        let (status, stored) = post_rules(&client, &rules_document(0, false));
        assert_eq!(status, Status::Ok);

        for path in [
            "weight",
            "priority",
            "category_set_priority",
            "set_priority",
        ] {
            for invalid_value in [
                json!(1_000_001),
                json!(-1_000_001),
                json!(true),
                json!(1.0),
                json!(1.5),
            ] {
                let mut invalid = stored.clone();
                match path {
                    "weight" => {
                        invalid["category_sets_v2"][0]["categories"][0]["rule"]["weight"] =
                            invalid_value
                    }
                    "priority" => {
                        invalid["category_sets_v2"][0]["categories"][0]["priority"] = invalid_value
                    }
                    "category_set_priority" => {
                        invalid["category_sets_v2"][0]["priority"] = invalid_value
                    }
                    "set_priority" => {
                        invalid["category_sets_v2"][0]["categories"][0]["set_priority"] =
                            invalid_value
                    }
                    _ => unreachable!(),
                }
                assert_eq!(post_rules(&client, &invalid).0, Status::BadRequest);
            }
        }
        let response = client
            .get("/api/0/settings/rules_v2")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        let unchanged: Value = serde_json::from_str(&response.into_string().unwrap()).unwrap();
        assert_eq!(unchanged, stored);
        compile_native_rules(&unchanged).unwrap();
    }

    #[test]
    fn test_malformed_historical_rules_remain_exportable_and_repairable() {
        let datastore = aw_datastore::Datastore::new_in_memory(false);
        datastore
            .set_key_value(
                "settings.rules_v2",
                r#"{"revision":7,"activity_profiles_v2":"broken"}"#,
            )
            .unwrap();
        datastore
            .set_key_value(
                "settings.classes",
                r#"[{"name":["Legacy"],"rule":{"type":"none"}}]"#,
            )
            .unwrap();
        let state = endpoints::ServerState {
            datastore,
            asset_resolver: endpoints::AssetResolver::new(None),
            device_id: "test_id".to_string(),
        };
        let client = Client::untracked(endpoints::build_rocket(state, config::AWConfig::default()))
            .expect("valid instance");

        let response = client
            .get("/api/0/settings/rules_v2")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let raw: Value = serde_json::from_str(&response.into_string().unwrap()).unwrap();
        assert_eq!(raw["revision"], 7);

        let response = client
            .get("/api/0/settings")
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        let settings: Value = serde_json::from_str(&response.into_string().unwrap()).unwrap();
        assert_eq!(settings["classes"][0]["name"], json!(["Legacy"]));

        let (status, repaired) = post_rules(&client, &rules_document(7, false));
        assert_eq!(status, Status::Ok);
        assert_eq!(repaired["revision"], 8);
    }

    #[test]
    fn test_malformed_historical_revisions_use_zero_for_explicit_repair() {
        for malformed in [
            r#"{"activity_profiles_v2":"broken"}"#,
            r#"{"revision":-1,"activity_profiles_v2":"broken"}"#,
            r#"{"revision":true,"activity_profiles_v2":"broken"}"#,
            r#"{"revision":1.0,"activity_profiles_v2":"broken"}"#,
            r#"{"revision":9007199254740992,"activity_profiles_v2":"broken"}"#,
            r#"{"revision":"7","activity_profiles_v2":"broken"}"#,
        ] {
            let datastore = aw_datastore::Datastore::new_in_memory(false);
            datastore
                .set_key_value("settings.rules_v2", malformed)
                .unwrap();
            let state = endpoints::ServerState {
                datastore,
                asset_resolver: endpoints::AssetResolver::new(None),
                device_id: "test_id".to_string(),
            };
            let client =
                Client::untracked(endpoints::build_rocket(state, config::AWConfig::default()))
                    .expect("valid instance");
            let (status, repaired) = post_rules(&client, &rules_document(0, false));
            assert_eq!(status, Status::Ok, "stored document: {malformed}");
            assert_eq!(repaired["revision"], 1);
        }
    }

    #[test]
    fn test_rules_v2_concurrent_cas_has_one_winner() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let datastore = aw_datastore::Datastore::new_in_memory(false);
        let clients = [datastore.clone(), datastore]
            .into_iter()
            .map(|datastore| {
                let state = endpoints::ServerState {
                    datastore,
                    asset_resolver: endpoints::AssetResolver::new(None),
                    device_id: "test_id".to_string(),
                };
                Client::untracked(endpoints::build_rocket(state, config::AWConfig::default()))
                    .expect("valid instance")
            })
            .collect::<Vec<_>>();
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for (client, profile_id) in clients.into_iter().zip(["one", "two"]) {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut document = rules_document(0, false);
                document["activity_profiles_v2"][0]["id"] = json!(profile_id);
                barrier.wait();
                post_rules(&client, &document).0
            }));
        }
        let mut statuses: Vec<Status> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        statuses.sort_by_key(|status| status.code);
        assert_eq!(statuses, vec![Status::Ok, Status::Conflict]);
    }

    #[test]
    fn test_cors_catching() {
        let server = setup_testserver();
        let client = Client::untracked(server).expect("valid instance");

        let res = client
            .options("/api/0/buckets/")
            .header(ContentType::JSON)
            .header(Header::new("Host", "127.0.0.1:5600"))
            .dispatch();
        assert_eq!(res.status(), rocket::http::Status::Ok);
    }
}
