use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap};

use aw_models::Event;
use chrono::{DateTime, Utc};

pub fn merge_subwatcher_fields(
    base_events: Vec<Event>,
    mut subwatcher_events: Vec<Event>,
    keys: &[String],
    conflict: &str,
    source_id: Option<&str>,
) -> Result<Vec<Event>, String> {
    if conflict != "base_wins" && conflict != "sub_wins" {
        return Err(format!(
            "conflict must be 'base_wins' or 'sub_wins', got {conflict:?}"
        ));
    }
    if let Some(source_id) = source_id {
        if source_id.is_empty()
            || !source_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
        {
            return Err("source_id may only contain letters, numbers, '_' and '-'".to_string());
        }
    }
    if subwatcher_events.is_empty() || keys.is_empty() {
        return Ok(base_events);
    }

    subwatcher_events.sort_by_key(|event| event.timestamp);
    let mut base_order: Vec<usize> = (0..base_events.len()).collect();
    base_order.sort_by_key(|index| base_events[*index].timestamp);

    let base_ends: Vec<DateTime<Utc>> = base_events.iter().map(Event::calculate_endtime).collect();
    let mut boundaries = BTreeSet::new();
    for index in &base_order {
        if base_events[*index].timestamp < base_ends[*index] {
            boundaries.insert(base_events[*index].timestamp);
            boundaries.insert(base_ends[*index]);
        }
    }

    let Some(first_boundary) = boundaries.first().copied() else {
        return Ok(base_events);
    };
    let last_boundary = boundaries.last().copied().unwrap();
    let overlapping_subwatchers: Vec<(&Event, DateTime<Utc>)> = subwatcher_events
        .iter()
        .filter_map(|event| {
            let end = event.calculate_endtime();
            (event.timestamp < last_boundary && end > first_boundary).then_some((event, end))
        })
        .collect();
    for (event, end) in &overlapping_subwatchers {
        boundaries.insert(event.timestamp.max(first_boundary));
        boundaries.insert((*end).min(last_boundary));
    }

    let boundary_points: Vec<DateTime<Utc>> = boundaries.into_iter().collect();
    let mut segments_by_base: Vec<Vec<Event>> = vec![Vec::new(); base_events.len()];
    let mut active_bases = BTreeSet::new();
    let mut base_expiry = BinaryHeap::new();
    let mut active_subwatchers = BinaryHeap::new();
    let mut next_base = 0;
    let mut next_subwatcher = 0;

    for boundary_pair in boundary_points.windows(2) {
        let start = boundary_pair[0];
        let end = boundary_pair[1];

        while next_base < base_order.len() && base_events[base_order[next_base]].timestamp <= start
        {
            let index = base_order[next_base];
            if base_ends[index] > start {
                active_bases.insert(index);
                base_expiry.push((Reverse(base_ends[index]), index));
            }
            next_base += 1;
        }
        while let Some((Reverse(expiry), index)) = base_expiry.peek().copied() {
            if expiry > start {
                break;
            }
            base_expiry.pop();
            active_bases.remove(&index);
        }

        while next_subwatcher < overlapping_subwatchers.len()
            && overlapping_subwatchers[next_subwatcher].0.timestamp <= start
        {
            let (subwatcher, subwatcher_end) = overlapping_subwatchers[next_subwatcher];
            active_subwatchers.push((
                subwatcher.timestamp,
                subwatcher_end,
                Reverse(next_subwatcher),
            ));
            next_subwatcher += 1;
        }
        while active_subwatchers
            .peek()
            .is_some_and(|(_, subwatcher_end, _)| *subwatcher_end <= start)
        {
            active_subwatchers.pop();
        }

        for index in &active_bases {
            let mut enriched = base_events[*index].clone();
            enriched.timestamp = start;
            enriched.duration = end - start;

            if let Some((_, _, Reverse(subwatcher_index))) = active_subwatchers.peek() {
                let subwatcher = overlapping_subwatchers[*subwatcher_index].0;
                for key in keys {
                    if let Some(value) = subwatcher.data.get(key) {
                        let target_key = match source_id {
                            Some(source_id) => format!("$source.{source_id}.{key}"),
                            None => key.clone(),
                        };
                        if conflict == "base_wins" && enriched.data.contains_key(&target_key) {
                            continue;
                        }
                        enriched.data.insert(target_key, value.clone());
                    }
                }
            }

            let base_segments = &mut segments_by_base[*index];
            if let Some(previous) = base_segments.last_mut() {
                if previous.calculate_endtime() == enriched.timestamp
                    && previous.data == enriched.data
                {
                    previous.duration += enriched.duration;
                    continue;
                }
            }
            base_segments.push(enriched);
        }
    }

    let mut result = Vec::new();
    for (index, base) in base_events.into_iter().enumerate() {
        if segments_by_base[index].is_empty() {
            result.push(base);
        } else {
            result.append(&mut segments_by_base[index]);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};
    use serde_json::json;

    use super::merge_subwatcher_fields;
    use aw_models::Event;

    fn event(offset_minutes: i64, duration_minutes: i64, data: serde_json::Value) -> Event {
        Event {
            id: None,
            timestamp: Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap()
                + Duration::minutes(offset_minutes),
            duration: Duration::minutes(duration_minutes),
            data: data.as_object().unwrap().clone(),
        }
    }

    #[test]
    fn splits_boundaries_and_conserves_duration() {
        let base = vec![event(0, 60, json!({"app": "vim"}))];
        let subwatcher = vec![event(15, 30, json!({"project": "myproject"}))];

        let result = merge_subwatcher_fields(
            base,
            subwatcher,
            &["project".to_string()],
            "base_wins",
            None,
        )
        .unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(
            result
                .iter()
                .map(|event| event.duration)
                .collect::<Vec<_>>(),
            vec![
                Duration::minutes(15),
                Duration::minutes(30),
                Duration::minutes(15)
            ]
        );
        assert!(result[0].data.get("project").is_none());
        assert_eq!(result[1].data.get("project"), Some(&json!("myproject")));
        assert!(result[2].data.get("project").is_none());
        assert_eq!(
            result.iter().map(|event| event.duration).sum::<Duration>(),
            Duration::hours(1)
        );
    }

    #[test]
    fn latest_overlapping_subwatcher_wins() {
        let base = vec![event(0, 60, json!({"app": "vim"}))];
        let subwatcher = vec![
            event(0, 40, json!({"project": "alpha"})),
            event(20, 40, json!({"project": "beta"})),
        ];

        let result = merge_subwatcher_fields(
            base,
            subwatcher,
            &["project".to_string()],
            "base_wins",
            None,
        )
        .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].duration, Duration::minutes(20));
        assert_eq!(result[1].duration, Duration::minutes(40));
        assert_eq!(result[0].data.get("project"), Some(&json!("alpha")));
        assert_eq!(result[1].data.get("project"), Some(&json!("beta")));
    }

    #[test]
    fn same_start_prefers_longer_overlap() {
        let base = vec![event(0, 60, json!({"app": "vim"}))];
        let subwatcher = vec![
            event(0, 20, json!({"project": "short"})),
            event(0, 40, json!({"project": "long"})),
        ];

        let result = merge_subwatcher_fields(
            base,
            subwatcher,
            &["project".to_string()],
            "base_wins",
            None,
        )
        .unwrap();

        assert_eq!(result[0].duration, Duration::minutes(40));
        assert_eq!(result[0].data.get("project"), Some(&json!("long")));
        assert_eq!(
            result.iter().map(|event| event.duration).sum::<Duration>(),
            Duration::hours(1)
        );
    }

    #[test]
    fn expired_newer_event_reveals_older_active_event() {
        let base = vec![event(0, 60, json!({"app": "vim"}))];
        let subwatcher = vec![
            event(0, 60, json!({"project": "background"})),
            event(10, 10, json!({"project": "foreground"})),
        ];

        let result = merge_subwatcher_fields(
            base,
            subwatcher,
            &["project".to_string()],
            "base_wins",
            None,
        )
        .unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(
            result
                .iter()
                .map(|event| (
                    event.duration,
                    event.data.get("project").unwrap().as_str().unwrap()
                ))
                .collect::<Vec<_>>(),
            vec![
                (Duration::minutes(10), "background"),
                (Duration::minutes(10), "foreground"),
                (Duration::minutes(40), "background"),
            ]
        );
    }

    #[test]
    fn end_boundary_is_exclusive_and_adjacent_event_starts_immediately() {
        let base = vec![event(0, 30, json!({"app": "vim"}))];
        let subwatcher = vec![
            event(0, 10, json!({"project": "first"})),
            event(10, 10, json!({"project": "second"})),
        ];

        let result = merge_subwatcher_fields(
            base,
            subwatcher,
            &["project".to_string()],
            "base_wins",
            None,
        )
        .unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].data.get("project"), Some(&json!("first")));
        assert_eq!(result[1].data.get("project"), Some(&json!("second")));
        assert!(result[2].data.get("project").is_none());
        assert_eq!(
            result
                .iter()
                .map(|event| event.duration)
                .collect::<Vec<_>>(),
            vec![
                Duration::minutes(10),
                Duration::minutes(10),
                Duration::minutes(10)
            ]
        );
    }

    #[test]
    fn boundary_sweep_handles_many_overlaps_and_coalesces_equal_segments() {
        const SEGMENTS: i64 = 10_000;

        let base = vec![event(0, SEGMENTS, json!({"app": "vim"}))];
        let mut subwatcher = vec![event(
            0,
            SEGMENTS,
            json!({"project": "same", "kind": "background"}),
        )];
        subwatcher.extend(
            (0..SEGMENTS)
                .map(|offset| event(offset, 1, json!({"project": "same", "kind": "foreground"}))),
        );

        let result = merge_subwatcher_fields(
            base,
            subwatcher,
            &["project".to_string()],
            "base_wins",
            None,
        )
        .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].duration, Duration::minutes(SEGMENTS));
        assert_eq!(result[0].data.get("project"), Some(&json!("same")));
    }

    #[test]
    fn cross_base_sweep_does_not_rescan_later_subwatchers() {
        const EVENT_COUNT: i64 = 10_000;

        let base: Vec<Event> = (0..EVENT_COUNT)
            .rev()
            .map(|offset| event(offset, 1, json!({"offset": offset})))
            .collect();
        let mut subwatcher = vec![event(0, EVENT_COUNT, json!({"project": "background"}))];
        subwatcher.extend(
            (1..EVENT_COUNT).map(|offset| event(offset, 1, json!({"project": "foreground"}))),
        );

        let result = merge_subwatcher_fields(
            base,
            subwatcher,
            &["project".to_string()],
            "base_wins",
            None,
        )
        .unwrap();

        assert_eq!(result.len(), EVENT_COUNT as usize);
        assert!(result
            .windows(2)
            .all(|pair| pair[0].timestamp > pair[1].timestamp));
        assert_eq!(
            result.first().unwrap().data.get("project"),
            Some(&json!("foreground"))
        );
        assert_eq!(
            result.last().unwrap().data.get("project"),
            Some(&json!("background"))
        );
    }

    #[test]
    fn supports_conflicts_and_namespacing() {
        let base = vec![event(0, 10, json!({"file": "base.py"}))];
        let subwatcher = vec![event(
            3,
            4,
            json!({"file": "sub.py", "vdesktop": "Personal"}),
        )];

        let base_wins = merge_subwatcher_fields(
            base.clone(),
            subwatcher.clone(),
            &["file".to_string()],
            "base_wins",
            None,
        )
        .unwrap();
        assert!(base_wins
            .iter()
            .all(|event| event.data.get("file") == Some(&json!("base.py"))));

        let sub_wins = merge_subwatcher_fields(
            base.clone(),
            subwatcher.clone(),
            &["file".to_string()],
            "sub_wins",
            None,
        )
        .unwrap();
        assert_eq!(sub_wins[1].data.get("file"), Some(&json!("sub.py")));

        let namespaced = merge_subwatcher_fields(
            base,
            subwatcher,
            &["vdesktop".to_string()],
            "base_wins",
            Some("vdesktop"),
        )
        .unwrap();
        assert_eq!(
            namespaced[1].data.get("$source.vdesktop.vdesktop"),
            Some(&json!("Personal"))
        );
    }

    #[test]
    fn sweep_cursor_preserves_overlap_for_ordered_and_unordered_base_events() {
        let subwatcher = vec![
            event(-20, 10, json!({"project": "expired"})),
            event(5, 10, json!({"project": "first"})),
            event(25, 10, json!({"project": "second"})),
        ];
        let ordered = merge_subwatcher_fields(
            vec![
                event(0, 20, json!({"app": "vim"})),
                event(20, 20, json!({"app": "vim"})),
            ],
            subwatcher.clone(),
            &["project".to_string()],
            "base_wins",
            None,
        )
        .unwrap();
        let unordered = merge_subwatcher_fields(
            vec![
                event(20, 20, json!({"app": "vim"})),
                event(0, 20, json!({"app": "vim"})),
            ],
            subwatcher,
            &["project".to_string()],
            "base_wins",
            None,
        )
        .unwrap();

        assert_eq!(ordered.len(), 6);
        assert_eq!(ordered[1].data.get("project"), Some(&json!("first")));
        assert_eq!(ordered[4].data.get("project"), Some(&json!("second")));
        assert_eq!(unordered.len(), 6);
        assert_eq!(unordered[1].data.get("project"), Some(&json!("second")));
        assert_eq!(unordered[4].data.get("project"), Some(&json!("first")));
    }

    #[test]
    fn rejects_invalid_options() {
        assert!(
            merge_subwatcher_fields(Vec::new(), Vec::new(), &[], "invalid", None)
                .unwrap_err()
                .contains("conflict must be")
        );
        assert!(merge_subwatcher_fields(
            Vec::new(),
            Vec::new(),
            &[],
            "base_wins",
            Some("invalid.source")
        )
        .unwrap_err()
        .contains("source_id"));
    }
}
