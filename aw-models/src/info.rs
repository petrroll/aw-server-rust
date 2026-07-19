use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Info {
    pub hostname: String,
    pub version: String,
    pub testing: bool,
    pub device_id: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InfoWithCapabilities {
    #[serde(flatten)]
    pub info: Info,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::{Info, InfoWithCapabilities};

    const RESPONSE: &str = r#"{
        "hostname":"host",
        "version":"v1",
        "testing":false,
        "device_id":"device",
        "capabilities":["query.categorize_v2.v1"]
    }"#;

    #[test]
    fn legacy_info_consumers_ignore_additive_capabilities() {
        let info: Info = serde_json::from_str(RESPONSE).unwrap();
        assert_eq!(info.hostname, "host");
    }

    #[test]
    fn capability_aware_consumers_can_read_the_extended_response() {
        let info: InfoWithCapabilities = serde_json::from_str(RESPONSE).unwrap();
        assert_eq!(info.info.hostname, "host");
        assert_eq!(info.capabilities, ["query.categorize_v2.v1"]);
    }
}
