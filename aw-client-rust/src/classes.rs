//! Default classes
//!
//! Taken from default classes in aw-webui

use serde::{Deserialize, Serialize};
use serde_json;

pub type CategoryId = Vec<String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySpec {
    #[serde(rename = "type")]
    pub spec_type: String,
    #[serde(default)]
    pub regex: String,
    #[serde(default)]
    pub ignore_case: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub select_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassSetting {
    #[serde(default)]
    pub id: Option<i32>,
    pub name: Vec<String>,
    pub rule: CategorySpec,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

/// Returns the default category settings shared with the WebUI.
pub fn default_class_settings() -> Vec<ClassSetting> {
    serde_json::from_value(serde_json::json!([
        {"name":["Work"], "rule":{"type":"regex", "regex":"Google Docs|libreoffice|ReText"}, "data":{"color":"#0F0", "score":10}},
        {"name":["Work","Programming"], "rule":{"type":"regex", "regex":"GitHub|Stack Overflow|BitBucket|Gitlab|vim|Spyder|kate|Ghidra|Scite"}},
        {"name":["Work","Programming","ActivityWatch"], "rule":{"type":"regex", "regex":"ActivityWatch|aw-", "ignore_case":true}},
        {"name":["Work","Image"], "rule":{"type":"regex", "regex":"GIMP|Inkscape"}},
        {"name":["Work","Video"], "rule":{"type":"regex", "regex":"Kdenlive"}},
        {"name":["Work","Audio"], "rule":{"type":"regex", "regex":"Audacity"}},
        {"name":["Work","3D"], "rule":{"type":"regex", "regex":"Blender"}},
        {"name":["Media"], "rule":{"type":"none"}, "data":{"color":"#F33"}},
        {"name":["Media","Games"], "rule":{"type":"regex", "regex":"Minecraft|RimWorld"}, "data":{"color":"#F80"}},
        {"name":["Media","Video"], "rule":{"type":"regex", "regex":"YouTube|Plex|VLC"}, "data":{"color":"#F33"}},
        {"name":["Media","Social Media"], "rule":{"type":"regex", "regex":"reddit|Facebook|Twitter|Instagram|devRant", "ignore_case":true}, "data":{"color":"#FCC400"}},
        {"name":["Media","Music"], "rule":{"type":"regex", "regex":"Spotify|Deezer", "ignore_case":true}, "data":{"color":"#A8FC00"}},
        {"name":["Comms"], "rule":{"type":"none"}, "data":{"color":"#9FF"}},
        {"name":["Comms","IM"], "rule":{"type":"regex", "regex":"Messenger|Telegram|Signal|WhatsApp|Rambox|Slack|Riot|Element|Discord|Nheko|NeoChat|Mattermost"}},
        {"name":["Comms","Email"], "rule":{"type":"regex", "regex":"Gmail|Thunderbird|mutt|alpine"}},
        {"name":["Uncategorized"], "rule":{"type":"none"}, "data":{"color":"#CCC"}}
    ])).expect("built-in categories are valid")
}

/// Returns defaults in the frozen tuple representation.
pub fn default_classes() -> Vec<(CategoryId, CategorySpec)> {
    default_class_settings()
        .into_iter()
        .map(|setting| (setting.name, setting.rule))
        .collect()
}
