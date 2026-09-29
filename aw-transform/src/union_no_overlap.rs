use aw_models::Event;
use chrono::{DateTime, Utc};

/// Merges two eventlists and removes overlap, the first eventlist will have precedence
///
/// aw-core implementation: https://github.com/ActivityWatch/aw-core/blob/master/aw_transform/union_no_overlap.py
///
/// # Example
/// ```ignore
///   events1  | xxx    xx     xxx     |
///   events2  |  ----     ------   -- |
///   result   | xxx--  xx ----xxx  -- |
/// ```
pub fn union_no_overlap(mut events1: Vec<Event>, mut events2: Vec<Event>) -> Vec<Event> {
    events1.sort_by_key(|event| event.timestamp);
    events2.sort_by_key(|event| event.timestamp);

    // Resolve first-stream coverage independently of its fact segmentation.
    // First-stream events themselves remain untouched in the result.
    let mut first_coverage: Vec<(DateTime<Utc>, DateTime<Utc>)> = Vec::new();
    for event in &events1 {
        let end = event.calculate_endtime();
        if end <= event.timestamp {
            continue;
        }
        if let Some((_, coverage_end)) = first_coverage.last_mut() {
            if event.timestamp <= *coverage_end {
                *coverage_end = (*coverage_end).max(end);
                continue;
            }
        }
        first_coverage.push((event.timestamp, end));
    }

    let mut lower_priority = Vec::new();
    for event in events2 {
        let event_end = event.calculate_endtime();
        if event_end <= event.timestamp {
            lower_priority.push(event);
            continue;
        }

        let mut cursor = event.timestamp;
        let first_relevant = first_coverage.partition_point(|(_, end)| *end <= cursor);
        for (coverage_start, coverage_end) in &first_coverage[first_relevant..] {
            if *coverage_start >= event_end {
                break;
            }
            if *coverage_start > cursor {
                lower_priority.push(event_slice(
                    &event,
                    cursor,
                    (*coverage_start).min(event_end),
                ));
            }
            cursor = cursor.max(*coverage_end);
            if cursor >= event_end {
                break;
            }
        }
        if cursor < event_end {
            lower_priority.push(event_slice(&event, cursor, event_end));
        }
    }

    events1.extend(lower_priority);
    events1.sort_by_key(|event| event.timestamp);
    events1
}

fn event_slice(event: &Event, start: DateTime<Utc>, end: DateTime<Utc>) -> Event {
    let mut slice = event.clone();
    slice.timestamp = start;
    slice.duration = end - start;
    slice
}

#[cfg(test)]
fn split_event(event: &Event, timestamp: DateTime<Utc>) -> (Event, Option<Event>) {
    let end = event.calculate_endtime();
    if event.timestamp < timestamp && timestamp < end {
        (
            event_slice(event, event.timestamp, timestamp),
            Some(event_slice(event, timestamp, end)),
        )
    } else {
        (event.clone(), None)
    }
}

// Some tests
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_split_event() {
        let now = Utc::now();
        let td1h = Duration::hours(1);
        let e = Event {
            id: None,
            timestamp: now,
            duration: Duration::hours(2),
            data: serde_json::Map::new(),
        };
        let (e1, e2_opt) = split_event(&e, now + td1h);
        assert_eq!(e1.timestamp, now);
        assert_eq!(e1.duration, td1h);

        let e2 = e2_opt.unwrap();
        assert_eq!(e2.timestamp, now + td1h);
        assert_eq!(e2.duration, td1h);

        // Now a test which does not lead to a split
        let (e1, e2_opt) = split_event(&e, now);
        assert_eq!(e1.timestamp, now);
        assert_eq!(e1.duration, Duration::hours(2));
        assert!(e2_opt.is_none());
    }

    #[test]
    fn test_union_no_overlap() {
        // A test without any actual overlap
        let now = Utc::now();
        let td1h = Duration::hours(1);
        let e1 = Event::new(now, td1h, serde_json::Map::new());
        let e2 = Event::new(now + td1h, td1h, serde_json::Map::new());
        let events1 = vec![e1.clone()];
        let events2 = vec![e2.clone()];
        let events_union = union_no_overlap(events1, events2);

        assert_eq!(events_union.len(), 2);
        assert_eq!(events_union[0].timestamp, now);
        assert_eq!(events_union[0].duration, td1h);
        assert_eq!(events_union[1].timestamp, now + td1h);
        assert_eq!(events_union[1].duration, td1h);

        // Now do in reverse order
        let events1 = vec![e2];
        let events2 = vec![e1];
        let events_union = union_no_overlap(events1, events2);

        // Resulting order should be the same, since there is no overlap.
        assert_eq!(events_union.len(), 2);
        assert_eq!(events_union[0].timestamp, now);
        assert_eq!(events_union[0].duration, td1h);
        assert_eq!(events_union[1].timestamp, now + td1h);
        assert_eq!(events_union[1].duration, td1h);
    }

    #[test]
    fn test_union_no_overlap_with_overlap() {
        // A test where the events overlap
        let now = Utc::now();
        let td1h = Duration::hours(1);
        let e1 = Event::new(now, td1h, serde_json::Map::new());
        let e2 = Event::new(now, Duration::hours(2), serde_json::Map::new());
        let events1 = vec![e1];
        let events2 = vec![e2];
        let events_union = union_no_overlap(events1, events2);

        assert_eq!(events_union.len(), 2);
        assert_eq!(events_union[0].timestamp, now);
        assert_eq!(events_union[0].duration, td1h);
        assert_eq!(events_union[1].timestamp, now + td1h);
        assert_eq!(events_union[1].duration, td1h);

        // Now test the case where e2 starts before e1
        let e1 = Event::new(now + td1h, td1h, serde_json::Map::new());
        let e2 = Event::new(now, Duration::hours(2), serde_json::Map::new());
        let events1 = vec![e1];
        let events2 = vec![e2];
        let events_union = union_no_overlap(events1, events2);

        assert_eq!(events_union.len(), 2);
        assert_eq!(events_union[0].timestamp, now);
        assert_eq!(events_union[0].duration, td1h);
        assert_eq!(events_union[1].timestamp, now + td1h);
        assert_eq!(events_union[1].duration, td1h);
    }

    fn named_event(start: DateTime<Utc>, offset: i64, duration: i64, source: &str) -> Event {
        Event::new(
            start + Duration::seconds(offset),
            Duration::seconds(duration),
            serde_json::Map::from_iter([("source".to_string(), serde_json::json!(source))]),
        )
    }

    #[test]
    fn first_stream_suppresses_every_covered_lower_segment() {
        let start = Utc::now();
        let high = named_event(start, 0, 60, "high");
        let original_repro = vec![
            named_event(start, 0, 30, "low-first"),
            named_event(start, 30, 30, "low-second"),
        ];
        assert_eq!(
            union_no_overlap(vec![high.clone()], original_repro),
            vec![high.clone()]
        );

        let low = vec![
            named_event(start, 0, 20, "low-1"),
            named_event(start, 20, 20, "low-2"),
            named_event(start, 40, 20, "low-3"),
        ];

        let result = union_no_overlap(vec![high.clone()], low.clone());
        assert_eq!(result, vec![high.clone()]);

        let result = union_no_overlap(vec![high.clone()], low.into_iter().rev().collect());
        assert_eq!(result, vec![high]);

        let reversed_priority = union_no_overlap(
            vec![
                named_event(start, 40, 20, "low-3"),
                named_event(start, 20, 20, "low-2"),
                named_event(start, 0, 20, "low-1"),
            ],
            vec![named_event(start, 0, 60, "high")],
        );
        assert_eq!(reversed_priority.len(), 3);
        assert!(reversed_priority
            .iter()
            .all(|event| event.data["source"].as_str().unwrap().starts_with("low-")));
    }

    #[test]
    fn trims_lower_segments_at_every_partial_boundary() {
        let start = Utc::now();
        let result = union_no_overlap(
            vec![named_event(start, 10, 10, "high")],
            vec![
                named_event(start, 25, 5, "low-3"),
                named_event(start, 15, 10, "low-2"),
                named_event(start, 0, 15, "low-1"),
            ],
        );

        assert_eq!(
            result
                .iter()
                .map(|event| (
                    (event.timestamp - start).num_seconds(),
                    event.duration.num_seconds(),
                    event.data["source"].as_str().unwrap(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (0, 10, "low-1"),
                (10, 10, "high"),
                (20, 5, "low-2"),
                (25, 5, "low-3"),
            ]
        );
    }

    #[test]
    fn splits_one_lower_event_around_multiple_high_priority_intervals() {
        let start = Utc::now();
        let result = union_no_overlap(
            vec![
                named_event(start, 30, 10, "high-2"),
                named_event(start, 10, 10, "high-1"),
            ],
            vec![named_event(start, 0, 50, "low")],
        );

        assert_eq!(
            result
                .iter()
                .map(|event| (
                    (event.timestamp - start).num_seconds(),
                    event.duration.num_seconds(),
                    event.data["source"].as_str().unwrap(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (0, 10, "low"),
                (10, 10, "high-1"),
                (20, 10, "low"),
                (30, 10, "high-2"),
                (40, 10, "low"),
            ]
        );
    }

    #[test]
    fn precedence_is_invariant_to_fact_partitioning() {
        let start = Utc::now();
        let low = vec![
            named_event(start, 0, 12, "low"),
            named_event(start, 12, 18, "low"),
            named_event(start, 30, 30, "low"),
        ];
        let coarse = union_no_overlap(vec![named_event(start, 10, 40, "high")], low.clone());
        let partitioned = union_no_overlap(
            vec![
                named_event(start, 10, 5, "high"),
                named_event(start, 15, 20, "high"),
                named_event(start, 35, 15, "high"),
            ],
            low,
        );

        let owners = |events: &[Event]| {
            (0..60)
                .map(|second| {
                    let timestamp = start + Duration::seconds(second);
                    events
                        .iter()
                        .find(|event| {
                            event.timestamp <= timestamp && event.calculate_endtime() > timestamp
                        })
                        .map(|event| event.data["source"].as_str().unwrap().to_string())
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(owners(&coarse), owners(&partitioned));
        assert_eq!(
            owners(&coarse),
            (0..60)
                .map(|second| Some(
                    if (10..50).contains(&second) {
                        "high"
                    } else {
                        "low"
                    }
                    .to_string()
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_union_no_overlap_preserves_first_stream_data_precedence() {
        let now = Utc::now();
        let high_priority = Event::new(
            now + Duration::hours(1),
            Duration::hours(2),
            serde_json::Map::from_iter([("source".to_string(), serde_json::json!("high"))]),
        );
        let low_priority = Event::new(
            now,
            Duration::hours(4),
            serde_json::Map::from_iter([("source".to_string(), serde_json::json!("low"))]),
        );

        let events = union_no_overlap(vec![high_priority], vec![low_priority]);

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].data["source"], serde_json::json!("low"));
        assert_eq!(events[0].duration, Duration::hours(1));
        assert_eq!(events[1].data["source"], serde_json::json!("high"));
        assert_eq!(events[1].duration, Duration::hours(2));
        assert_eq!(events[2].data["source"], serde_json::json!("low"));
        assert_eq!(events[2].duration, Duration::hours(1));
    }
}
