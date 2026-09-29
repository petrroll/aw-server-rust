use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;

use aw_client_rust::queries::{
    full_desktop_query, try_build_canonical_events_v2, AdvancedQueryOptions,
    CanonicalQueryV2Options, QueryParams,
};
use aw_client_rust::rules_v2::{compile_profile_v2, migrate_legacy_settings, ProfileQueryRequest};
use aw_datastore::Datastore;
use aw_models::{Bucket, BucketMetadata, Event, TimeInterval};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

const RETURN_SUFFIX: &str = "\nRETURN = [events, not_afk];";

#[derive(Debug, Deserialize)]
struct Corpus {
    schema_version: u64,
    capabilities: Vec<String>,
    fixtures: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    interval: [String; 2],
    buckets: Vec<FixtureBucket>,
    options: Value,
    #[serde(default)]
    builder_mode: Option<String>,
    #[serde(default)]
    legacy_options: Option<Value>,
    #[serde(default)]
    profile_contract: Option<ProfileContract>,
    #[serde(default)]
    return_browser: bool,
    #[serde(default)]
    omit_capabilities_for: Vec<String>,
    #[serde(default)]
    legacy_variant: Option<String>,
    #[serde(default)]
    supported_builders: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ProfileContract {
    selected_profile_id: String,
    document: Value,
    #[serde(default)]
    canonical_absent: bool,
    #[serde(default)]
    lossy_classes: Value,
    #[serde(default)]
    legacy_settings: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct FixtureBucket {
    id: String,
    #[serde(rename = "type")]
    type_id: String,
    #[serde(default = "default_client")]
    client: String,
    hostname: String,
    #[serde(default)]
    data: Map<String, Value>,
    #[serde(default)]
    events: Vec<Event>,
}

fn default_client() -> String {
    "fixture".to_string()
}

#[derive(Debug, Serialize)]
struct Generated {
    schema_version: u64,
    builder: &'static str,
    queries: BTreeMap<String, Value>,
    options: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct QueryMatrix {
    schema_version: u64,
    queries: BTreeMap<String, BTreeMap<String, String>>,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut text = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    text.push('\n');
    fs::write(path, text).map_err(|error| format!("write {}: {error}", path.display()))
}

fn merged_options(corpus: &Corpus, fixture: &Fixture) -> Value {
    let mut options = fixture
        .options
        .as_object()
        .cloned()
        .expect("fixture options must be an object");
    options.insert("capabilities".to_string(), json!(corpus.capabilities));
    options
        .entry("filter_categories".to_string())
        .or_insert(Value::Null);
    Value::Object(options)
}

fn generate(corpus_path: &Path, output_path: &Path) -> Result<(), String> {
    let corpus: Corpus = read_json(corpus_path)?;
    if corpus.schema_version != 1 {
        return Err(format!(
            "unsupported fixture schema {}",
            corpus.schema_version
        ));
    }
    let mut generated = Generated {
        schema_version: 1,
        builder: "rust",
        queries: BTreeMap::new(),
        options: BTreeMap::new(),
    };
    for fixture in &corpus.fixtures {
        #[allow(deprecated)]
        let built: Result<(Value, String), String> = if fixture
            .supported_builders
            .as_ref()
            .is_some_and(|builders| !builders.iter().any(|builder| builder == "rust"))
        {
            Err("fixture does not apply to the Rust builder".to_string())
        } else if fixture.builder_mode.as_deref() == Some("legacy_desktop") {
            let mut options = fixture
                .legacy_options
                .clone()
                .ok_or_else(|| "legacy fixture is missing legacy_options".to_string())?;
            if !fixture
                .omit_capabilities_for
                .iter()
                .any(|builder| builder == "rust")
            {
                options
                    .as_object_mut()
                    .ok_or_else(|| "legacy_options must be an object".to_string())?
                    .insert("capabilities".to_string(), json!(corpus.capabilities));
            }
            let params: QueryParams =
                serde_json::from_value(options.clone()).map_err(|error| error.to_string())?;
            let advanced: AdvancedQueryOptions =
                serde_json::from_value(options.clone()).map_err(|error| error.to_string())?;
            if fixture.legacy_variant.as_deref() == Some("full_desktop") {
                match &params {
                    QueryParams::Desktop(desktop) => Ok((options, full_desktop_query(desktop))),
                    QueryParams::Android(_) => {
                        Err("full desktop fixture requires desktop parameters".to_string())
                    }
                }
            } else {
                params
                    .try_canonical_events_with_options(&advanced)
                    .map(|query| (options, query))
            }
        } else if let Some(contract) = &fixture.profile_contract {
            let buckets = fixture_bucket_map(fixture);
            let request = ProfileQueryRequest {
                profile_id: Some(contract.selected_profile_id.clone()),
                hostname: fixture
                    .options
                    .get("hostname")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                filter_afk: fixture
                    .options
                    .get("filter_afk")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
                filter_categories: fixture
                    .options
                    .get("filter_categories")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|error| error.to_string())?,
                explain_categories: fixture
                    .options
                    .get("explain_categories")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            };
            let document = if let Some(settings) = &contract.legacy_settings {
                migrate_legacy_settings(settings)
            } else if contract.canonical_absent {
                migrate_legacy_settings(&json!({
                    "activity_profiles_v2": contract.document["activity_profiles_v2"],
                    "category_sets_v2": contract.document["category_sets_v2"],
                    "classes": contract.lossy_classes.clone(),
                    "always_active_pattern": ""
                }))
            } else {
                contract.document.clone()
            };
            compile_profile_v2(&document, &buckets, corpus.capabilities.clone(), &request).and_then(
                |materialized| {
                    let options = serde_json::to_value(&materialized.options)
                        .map_err(|error| error.to_string())?;
                    let query = materialized.query()?;
                    Ok((options, query))
                },
            )
        } else {
            let options_value = merged_options(&corpus, fixture);
            serde_json::from_value::<CanonicalQueryV2Options>(options_value.clone())
                .map_err(|error| error.to_string())
                .and_then(|options| try_build_canonical_events_v2(&options))
                .map(|query| (options_value, query))
        };
        match built {
            Ok((options, query)) => {
                generated.options.insert(fixture.id.clone(), options);
                let suffix = if fixture.return_browser {
                    "\nRETURN = {\"events\": events, \"active\": not_afk, \"browser\": browser_events, \"browser_duration\": sum_durations(browser_events)};"
                } else {
                    RETURN_SUFFIX
                };
                generated.queries.insert(
                    fixture.id.clone(),
                    Value::String(format!("{query}{suffix}")),
                );
            }
            Err(error) => {
                generated
                    .queries
                    .insert(fixture.id.clone(), json!({"error": error}));
            }
        }
    }
    write_json(output_path, &generated)
}

fn fixture_bucket_map(fixture: &Fixture) -> std::collections::HashMap<String, Bucket> {
    fixture
        .buckets
        .iter()
        .map(|source| {
            (
                source.id.clone(),
                Bucket {
                    bid: None,
                    id: source.id.clone(),
                    _type: source.type_id.clone(),
                    client: source.client.clone(),
                    hostname: source.hostname.clone(),
                    created: None,
                    data: source.data.clone(),
                    metadata: BucketMetadata::default(),
                    events: None,
                    last_updated: None,
                },
            )
        })
        .collect()
}

fn datastore_for(fixture: &Fixture) -> Result<Datastore, String> {
    let datastore = Datastore::new_in_memory(false);
    for source in &fixture.buckets {
        let bucket = fixture_bucket_map(fixture)
            .remove(&source.id)
            .expect("fixture bucket map is complete");
        datastore
            .create_bucket(&bucket)
            .map_err(|error| format!("create bucket {}: {error:?}", source.id))?;
        datastore
            .insert_events(&source.id, &source.events)
            .map_err(|error| format!("insert events {}: {error:?}", source.id))?;
    }
    Ok(datastore)
}

fn execute(corpus_path: &Path, query_path: &Path, output_path: &Path) -> Result<(), String> {
    let corpus: Corpus = read_json(corpus_path)?;
    let matrix: QueryMatrix = read_json(query_path)?;
    if corpus.schema_version != 1 || matrix.schema_version != 1 {
        return Err("unsupported fixture/query schema".to_string());
    }
    let mut results: BTreeMap<String, BTreeMap<String, BTreeMap<String, Value>>> = BTreeMap::new();
    for fixture in &corpus.fixtures {
        let interval = TimeInterval::new_from_string(&format!(
            "{}/{}",
            fixture.interval[0], fixture.interval[1]
        ))
        .map_err(|error| format!("interval {}: {error:?}", fixture.id))?;
        let mut fixture_results = BTreeMap::new();
        for (builder, queries) in &matrix.queries {
            let wrapped = match queries.get(&fixture.id) {
                None => json!({"error": format!("missing query for {}", fixture.id)}),
                Some(query) => match datastore_for(fixture) {
                    Err(error) => json!({"error": error}),
                    Ok(datastore) => {
                        let value = match aw_query::query(query, &interval, &datastore) {
                            Ok(result) => serde_json::to_value(result)
                                .map(|result| json!({"result": result}))
                                .unwrap_or_else(|error| json!({"error": error.to_string()})),
                            Err(error) => json!({"error": error.to_string()}),
                        };
                        datastore.close();
                        value
                    }
                },
            };
            fixture_results.insert(
                builder.clone(),
                BTreeMap::from([("memory".to_string(), wrapped)]),
            );
        }
        results.insert(fixture.id.clone(), fixture_results);
    }
    write_json(
        output_path,
        &json!({"schema_version": 1, "engine": "rust", "results": results}),
    )
}

fn usage(program: &str) -> String {
    format!(
        "usage:\n  {program} generate FIXTURES.json OUTPUT.json\n  {program} execute FIXTURES.json QUERIES.json OUTPUT.json"
    )
}

fn real_main() -> Result<(), String> {
    let arguments: Vec<String> = env::args().collect();
    match arguments.as_slice() {
        [_, mode, corpus, output] if mode == "generate" => {
            generate(Path::new(corpus), Path::new(output))
        }
        [_, mode, corpus, queries, output] if mode == "execute" => {
            execute(Path::new(corpus), Path::new(queries), Path::new(output))
        }
        _ => Err(usage(
            arguments
                .first()
                .map(String::as_str)
                .unwrap_or("flexible_conformance"),
        )),
    }
}

fn main() {
    if let Err(error) = real_main() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
