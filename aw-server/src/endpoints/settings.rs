use crate::endpoints::rules_settings::{
    projection, translate_legacy_write, validate_envelope, RulesSettingsError, LEGACY_KEYS,
    MAX_SAFE_REVISION, RULES_KEY,
};
use crate::endpoints::{HttpErrorJson, ServerState};
use aw_datastore::DatastoreError;
use lazy_static::lazy_static;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::serde::json::Json;
use rocket::State;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

lazy_static! {
    // A CAS spans a datastore read and write. The datastore worker serializes
    // each command, while this mutex serializes the complete settings operation.
    // It intentionally covers old and new settings routes so no projection write
    // can interleave with a canonical replacement.
    static ref SETTINGS_LOCK: Mutex<()> = Mutex::new(());
}

pub struct IfMatch(Option<u64>);

fn parse_revision(raw: &str) -> Result<u64, String> {
    let mut value = raw.trim();
    if let Some(rest) = value.strip_prefix("W/") {
        value = rest.trim();
    }
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value = &value[1..value.len() - 1];
    }
    let revision = value
        .parse::<u64>()
        .map_err(|_| "revision must be a non-negative integer".to_string())?;
    if revision > MAX_SAFE_REVISION {
        return Err(format!(
            "revision must not exceed the maximum safe integer {MAX_SAFE_REVISION}"
        ));
    }
    Ok(revision)
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for IfMatch {
    type Error = String;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("If-Match") {
            None => Outcome::Success(IfMatch(None)),
            Some(raw) => match parse_revision(raw) {
                Ok(revision) => Outcome::Success(IfMatch(Some(revision))),
                Err(error) => Outcome::Error((Status::BadRequest, error)),
            },
        }
    }
}

fn parse_key(key: String) -> Result<String, HttpErrorJson> {
    if key.len() >= 128 {
        Err(HttpErrorJson::new(
            Status::BadRequest,
            "Too long key".to_string(),
        ))
    } else {
        Ok(format!("settings.{key}"))
    }
}

fn json_value(raw: String, key: &str) -> Result<Value, HttpErrorJson> {
    serde_json::from_str(&raw).map_err(|error| {
        HttpErrorJson::new(
            Status::InternalServerError,
            format!("Stored setting {key} contains invalid JSON: {error}"),
        )
    })
}

fn canonical_get(state: &State<ServerState>) -> Result<Option<Value>, HttpErrorJson> {
    match state.datastore.get_key_value("settings.rules_v2") {
        Ok(value) => Ok(Some(json_value(value, RULES_KEY)?)),
        Err(DatastoreError::NoSuchKey(_)) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn requested_revision(
    query_revision: Option<u64>,
    if_match: IfMatch,
) -> Result<Option<u64>, HttpErrorJson> {
    if query_revision.is_some() && if_match.0.is_some() {
        return Err(HttpErrorJson::new(
            Status::BadRequest,
            "Supply revision or If-Match, not both".to_string(),
        ));
    }
    Ok(query_revision.or(if_match.0))
}

fn check_revision(current: u64, expected: Option<u64>) -> Result<(), HttpErrorJson> {
    if let Some(expected) = expected {
        if expected != current {
            return Err(HttpErrorJson::new(
                Status::Conflict,
                format!(
                    "rules_v2 revision conflict: expected {expected}, current revision is {current}; reload or merge before retrying"
                ),
            ));
        }
    }
    Ok(())
}

#[get("/rules_v2", rank = 1)]
pub fn rules_get(state: &State<ServerState>) -> Result<Json<Value>, HttpErrorJson> {
    let _guard = SETTINGS_LOCK.lock().map_err(|_| {
        HttpErrorJson::new(
            Status::InternalServerError,
            "Settings lock is poisoned".to_string(),
        )
    })?;
    canonical_get(state)?.map(Json).ok_or_else(|| {
        HttpErrorJson::new(
            Status::NotFound,
            "No canonical rules_v2 document exists".to_string(),
        )
    })
}

#[post(
    "/rules_v2?<revision>",
    data = "<value>",
    format = "application/json",
    rank = 1
)]
pub fn rules_set(
    state: &State<ServerState>,
    revision: Option<u64>,
    if_match: IfMatch,
    value: Json<Value>,
) -> Result<Json<Value>, HttpErrorJson> {
    validate_envelope(&value.0).map_err(|error| HttpErrorJson::new(Status::BadRequest, error))?;
    let body_revision = value.0["revision"].as_u64().ok_or_else(|| {
        HttpErrorJson::new(
            Status::BadRequest,
            "rules_v2.revision must be a non-negative safe integer".to_string(),
        )
    })?;
    let header_revision = requested_revision(revision, if_match)?;
    if header_revision.is_some_and(|expected| expected != body_revision) {
        return Err(HttpErrorJson::new(
            Status::BadRequest,
            "If-Match/revision does not match the expected revision in the request body"
                .to_string(),
        ));
    }

    let _guard = SETTINGS_LOCK.lock().map_err(|_| {
        HttpErrorJson::new(
            Status::InternalServerError,
            "Settings lock is poisoned".to_string(),
        )
    })?;
    let current = canonical_get(state)?;
    let current_revision = current
        .as_ref()
        .and_then(|envelope| envelope["revision"].as_u64())
        .filter(|revision| *revision <= MAX_SAFE_REVISION)
        .unwrap_or(0);
    check_revision(current_revision, Some(body_revision))?;

    let next_revision = body_revision
        .checked_add(1)
        .filter(|revision| *revision <= MAX_SAFE_REVISION)
        .ok_or_else(|| {
            HttpErrorJson::new(
                Status::BadRequest,
                "rules_v2 revision has reached the maximum safe integer".to_string(),
            )
        })?;
    let mut stored = value.0;
    stored["revision"] = Value::from(next_revision);
    let serialized = serde_json::to_string(&stored).map_err(|error| {
        HttpErrorJson::new(Status::BadRequest, format!("Invalid JSON: {error}"))
    })?;
    state
        .datastore
        .set_key_value("settings.rules_v2", &serialized)?;
    Ok(Json(stored))
}

#[get("/")]
pub fn settings_get(
    state: &State<ServerState>,
) -> Result<Json<HashMap<String, Value>>, HttpErrorJson> {
    let _guard = SETTINGS_LOCK.lock().map_err(|_| {
        HttpErrorJson::new(
            Status::InternalServerError,
            "Settings lock is poisoned".to_string(),
        )
    })?;
    let settings = state.datastore.get_key_values("settings.%")?;
    let mut map: HashMap<String, Value> = HashMap::new();
    for (key, value) in settings {
        let stripped = key.strip_prefix("settings.").unwrap_or(&key).to_string();
        map.insert(stripped.clone(), json_value(value, &stripped)?);
    }
    if let Some(envelope) = canonical_get(state)? {
        map.insert(RULES_KEY.to_string(), envelope.clone());
        // Historical malformed documents remain exportable. They cannot be
        // projected safely, so retain persisted predecessor values until an
        // explicit validated canonical replacement succeeds.
        if let Ok(projected) = projection(&envelope) {
            for (key, value) in projected {
                map.insert(key, value);
            }
        }
    }
    Ok(Json(map))
}

#[get("/<key>", rank = 2)]
pub fn setting_get(state: &State<ServerState>, key: String) -> Result<Json<Value>, HttpErrorJson> {
    let setting_key = parse_key(key.clone())?;
    let _guard = SETTINGS_LOCK.lock().map_err(|_| {
        HttpErrorJson::new(
            Status::InternalServerError,
            "Settings lock is poisoned".to_string(),
        )
    })?;
    if LEGACY_KEYS.contains(&key.as_str()) {
        if let Some(envelope) = canonical_get(state)? {
            if let Ok(projected) = projection(&envelope) {
                return Ok(Json(projected[&key].clone()));
            }
        }
    }
    match state.datastore.get_key_value(&setting_key) {
        Ok(value) => Ok(Json(json_value(value, &key)?)),
        Err(DatastoreError::NoSuchKey(_)) => Ok(Json(Value::Null)),
        Err(error) => Err(error.into()),
    }
}

#[post(
    "/<key>?<revision>",
    data = "<value>",
    format = "application/json",
    rank = 2
)]
pub fn setting_set(
    state: &State<ServerState>,
    key: String,
    revision: Option<u64>,
    if_match: IfMatch,
    value: Json<Value>,
) -> Result<Status, HttpErrorJson> {
    if key == RULES_KEY {
        return Err(HttpErrorJson::new(
            Status::BadRequest,
            "rules_v2 must be written with the canonical endpoint".to_string(),
        ));
    }
    let setting_key = parse_key(key.clone())?;
    let expected = requested_revision(revision, if_match)?;
    let _guard = SETTINGS_LOCK.lock().map_err(|_| {
        HttpErrorJson::new(
            Status::InternalServerError,
            "Settings lock is poisoned".to_string(),
        )
    })?;
    if LEGACY_KEYS.contains(&key.as_str()) {
        if let Some(envelope) = canonical_get(state)? {
            validate_envelope(&envelope).map_err(|error| {
                HttpErrorJson::new(
                    Status::Conflict,
                    format!(
                        "legacy rule writes are disabled while rules_v2 requires explicit recovery: {error}"
                    ),
                )
            })?;
            let current_revision = envelope["revision"].as_u64().ok_or_else(|| {
                HttpErrorJson::new(
                    Status::Conflict,
                    "legacy rule writes are disabled while rules_v2 requires explicit recovery"
                        .to_string(),
                )
            })?;
            check_revision(current_revision, expected)?;
            let mut updated =
                translate_legacy_write(&envelope, &key, &value.0).map_err(|error| {
                    let status = match error {
                        RulesSettingsError::Validation(_) => Status::BadRequest,
                        RulesSettingsError::Conflict(_) => Status::Conflict,
                    };
                    HttpErrorJson::new(status, error.to_string())
                })?;
            let next_revision = current_revision
                .checked_add(1)
                .filter(|revision| *revision <= MAX_SAFE_REVISION)
                .ok_or_else(|| {
                    HttpErrorJson::new(
                        Status::BadRequest,
                        "rules_v2 revision has reached the maximum safe integer".to_string(),
                    )
                })?;
            updated["revision"] = Value::from(next_revision);
            let serialized = serde_json::to_string(&updated).map_err(|error| {
                HttpErrorJson::new(Status::BadRequest, format!("Invalid JSON: {error}"))
            })?;
            state
                .datastore
                .set_key_value("settings.rules_v2", &serialized)?;
            return Ok(Status::Created);
        }
        check_revision(0, expected)?;
    }
    let value_str = serde_json::to_string(&value.0).map_err(|error| {
        HttpErrorJson::new(Status::BadRequest, format!("Invalid JSON: {error}"))
    })?;
    state.datastore.set_key_value(&setting_key, &value_str)?;
    Ok(Status::Created)
}

#[delete("/<key>", rank = 2)]
pub fn setting_delete(state: &State<ServerState>, key: String) -> Result<(), HttpErrorJson> {
    let setting_key = parse_key(key.clone())?;
    let _guard = SETTINGS_LOCK.lock().map_err(|_| {
        HttpErrorJson::new(
            Status::InternalServerError,
            "Settings lock is poisoned".to_string(),
        )
    })?;
    if (key == RULES_KEY || LEGACY_KEYS.contains(&key.as_str())) && canonical_get(state)?.is_some()
    {
        return Err(HttpErrorJson::new(
            Status::Conflict,
            format!("{key} is derived from canonical rules_v2 and cannot be deleted independently"),
        ));
    }
    state.datastore.delete_key_value(&setting_key)?;
    Ok(())
}
