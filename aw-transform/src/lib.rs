#[macro_use]
extern crate log;

// TODO: Move this to some more suitable place
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

pub mod classify;

mod classify_v2;
pub use classify_v2::{
    categorize_v2, categorize_v2_explain, categorize_v2_explain_for_host, categorize_v2_for_host,
    compile_category_rules, CategoryRule,
};

mod active_periods_v2;
pub use active_periods_v2::{active_periods_v2, active_periods_v2_for_host};

mod heartbeat;
pub use heartbeat::heartbeat;

mod find_bucket;
pub use find_bucket::find_bucket;

mod flood;
pub use flood::flood;

mod merge;
pub use merge::merge_events_by_keys;

mod merge_subwatcher_fields;
pub use merge_subwatcher_fields::merge_subwatcher_fields;

mod map_event_fields;
pub use map_event_fields::map_event_fields;

mod chunk;
pub use chunk::chunk_events_by_key;

mod sort;
pub use sort::{sort_by_duration, sort_by_timestamp};

mod filter_keyvals;
pub use filter_keyvals::{exclude_keyvals, filter_keyvals, filter_keyvals_regex};

mod filter_period;
pub use filter_period::filter_period_intersect;

mod split_url;
pub use split_url::split_url_event;

mod period_union;
pub use period_union::period_union;

mod union_no_overlap;
pub use union_no_overlap::union_no_overlap;
