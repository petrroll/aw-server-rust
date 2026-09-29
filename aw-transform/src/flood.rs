use aw_models::Event;

use crate::sort_by_timestamp;

/// Fill short positive heartbeat gaps using the v2 deterministic policy.
///
/// Gaps are the uncovered intervals between connected coverage components of
/// the immutable original records. The left boundary fact has the furthest end
/// (latest start, then later input on ties), while the right boundary fact has
/// the earliest start (longest end, then later input on ties). The longer original boundary fact receives the whole
/// gap as a separate synthetic event and equal durations favor the left.
/// Original bounds and overlapping originals are retained, so fills never
/// influence later decisions or overlap precedence.
pub fn flood_v2(events: Vec<Event>, threshold: chrono::Duration) -> Result<Vec<Event>, String> {
    if threshold < chrono::Duration::zero() {
        return Err("flood_v2 threshold_seconds must be a finite non-negative number".to_string());
    }
    let originals = sort_by_timestamp(events);
    if originals.len() < 2 {
        return Ok(originals);
    }

    // (coverage start, coverage end, left anchor index, right anchor index).
    // All indexes refer to immutable originals.
    let mut components = Vec::new();
    let mut component_start = originals[0].timestamp;
    let mut component_end = originals[0].calculate_endtime();
    let mut left_anchor = 0;
    let mut right_anchor = 0;
    for (index, event) in originals.iter().enumerate().skip(1) {
        let event_end = event.calculate_endtime();
        if event.timestamp <= component_end {
            if event.timestamp == component_start
                && event_end >= originals[right_anchor].calculate_endtime()
            {
                right_anchor = index;
            }
            if event_end > component_end {
                component_end = event_end;
                left_anchor = index;
            } else if event_end == component_end
                && event.timestamp >= originals[left_anchor].timestamp
            {
                left_anchor = index;
            }
            continue;
        }

        components.push((component_start, component_end, left_anchor, right_anchor));
        component_start = event.timestamp;
        component_end = event_end;
        left_anchor = index;
        right_anchor = index;
    }
    components.push((component_start, component_end, left_anchor, right_anchor));

    let mut flooded = originals.clone();
    for pair in components.windows(2) {
        let gap_start = pair[0].1;
        let gap_end = pair[1].0;
        let gap = gap_end - gap_start;
        if gap <= chrono::Duration::zero() || gap > threshold {
            continue;
        }
        let left_index = pair[0].2;
        let right_index = pair[1].3;
        let anchor_index = if originals[left_index].duration >= originals[right_index].duration {
            left_index
        } else {
            right_index
        };
        let mut synthetic = originals[anchor_index].clone();
        synthetic.id = None;
        synthetic.timestamp = gap_start;
        synthetic.duration = gap;
        flooded.push(synthetic);
    }
    Ok(sort_by_timestamp(flooded))
}

/// Legacy Query2 transform that floods events to their nearest neighbour.
///
/// Also merges events if they have the same data and are within the pulsetime.
///
/// "Flooding" actually performs two similar, but slightly different tasks, which we can describe as:
///  - Flooding: removes small gaps between events, by extending nearby events to fill the space.
///  - Merging: merging adjacent or overlapping events that have the same data.
///     - This is sometimes done in conjunction with flooding, if events with nearby events have the same data.
///
/// Python implementation:
///     https://github.com/ActivityWatch/aw-core/blob/master/aw_transform/flood.py
/// Python re-implementation using generators (different spec):
///     https://github.com/ErikBjare/copilot-testing/blob/master/playground/flooding.py
///
/// # Example
///
/// Example with forward-fill:
///
/// ```ignore
/// pulsetime: 1 second (one space)
/// input:  [a] [b] [c]
/// output: [a ][b ][c]
/// ```
///
/// Example with forward-fill and event merging:
///
/// ```ignore
/// pulsetime: 1 second (one space)
/// input:  [a] [a] [b ][b]
/// output: [a    ] [b    ]
/// ```
pub fn flood(events: Vec<Event>, pulsetime: chrono::Duration) -> Vec<Event> {
    let mut new_events = Vec::new();
    let mut events_sorted = sort_by_timestamp(events);
    let mut e1_iter = events_sorted.drain(..).peekable();

    let mut gap_prev: Option<chrono::Duration> = None;
    let mut retry_e: Option<Event> = None;

    // If negative gaps are smaller than this, prune them to become zero
    let negative_gap_trim_thres = chrono::Duration::milliseconds(100);

    let mut warned_negative_gap_safe = false;
    let mut warned_negative_gap_unsafe = false;

    while let Some(mut e1) = match retry_e {
        Some(e) => {
            retry_e = None;
            Some(e)
        }
        None => e1_iter.next(),
    } {
        if let Some(gap) = gap_prev {
            e1.timestamp -= gap / 2;
            e1.duration += gap / 2;
            gap_prev = None;
        }
        let e2 = match e1_iter.peek() {
            Some(e) => e,
            None => {
                new_events.push(e1);
                break;
            }
        };

        // Ensure that ordering is preserved, at least in tests
        debug_assert!(e1.timestamp <= e2.timestamp);

        let gap = e2.timestamp - e1.calculate_endtime();

        // We split the program flow into 2 parts: positive and negative gaps
        // First we check negative gaps (if events overlap)
        if gap < chrono::Duration::seconds(0) {
            // Python implementation:
            //
            // if gap < timedelta(0) and e1.data == e2.data:
            //     start = min(e1.timestamp, e2.timestamp)
            //     end = max(e1.timestamp + e1.duration, e2.timestamp + e2.duration)
            //     e1.timestamp, e1.duration = start, (end - start)
            //     e2.timestamp, e2.duration = end, timedelta(0)
            //     if not warned_about_negative_gap_safe:
            //         logger.warning(
            //             "Gap was of negative duration but could be safely merged ({}s). This message will only show once per batch.".format(
            //                 gap.total_seconds()
            //             )
            //         )
            //         warned_about_negative_gap_safe = True

            // If data is same, we can safely merge them.
            if e1.data == e2.data {
                // Gap was negative and could be safely merged
                if !warned_negative_gap_safe {
                    warn!("Gap was of negative duration ({}s), but could be safely merged. This error will only show once per batch.", gap);
                    warned_negative_gap_safe = true;
                }
                let start = std::cmp::min(e1.timestamp, e2.timestamp);
                let end = std::cmp::max(e1.calculate_endtime(), e2.calculate_endtime()); // e2 isn't guaranteed to end last
                e1.timestamp = start;
                e1.duration = end - start;
                // Drop next event since it is merged/flooded into e1
                e1_iter.next();
                // Retry this event again to give it a change to merge e1
                // with 'e3'
                retry_e = Some(e1);
                continue;
            // If data differs and gap is negative beyond the trim thres, throw a warning
            } else if gap < -negative_gap_trim_thres && !warned_negative_gap_unsafe {
                // Events with negative gap but differing data cannot be merged safely
                warn!("Gap was of negative duration and could NOT be safely merged ({}s). This warning will only show once per batch.", gap);
                warned_negative_gap_unsafe = true;
            }

        // By now, we've ensured gap is non-negative, now we want to know if the gap is smaller
        // than pulsetime, in which case we should fill it.
        } else if gap < pulsetime {
            // Python implementation:
            //
            // elif gap < -negative_gap_trim_thres and not warned_about_negative_gap_unsafe:
            //     # Events with negative gap but differing data cannot be merged safely
            //     logger.warning(
            //         "Gap was of negative duration and could NOT be safely merged ({}s). This warning will only show once per batch.".format(
            //             gap.total_seconds()
            //         )
            //     )
            //     warned_about_negative_gap_unsafe = True

            // Ensure that gap is actually non-negative here, at least in tests
            debug_assert!(gap >= chrono::Duration::seconds(0));

            // If data is the same, we should merge them.
            if e1.data == e2.data {
                // Choose the longest event and set the endtime to it
                let start = std::cmp::min(e1.timestamp, e2.timestamp); // isn't e1 guaranteed to start?
                let end = std::cmp::max(e1.calculate_endtime(), e2.calculate_endtime()); // e2 isn't guaranteed to end last
                e1.timestamp = start;
                e1.duration = end - start;
                // Drop next event since it is merged/flooded into e1
                e1_iter.next();
                // Retry this event again to give it a change to merge e1
                // with 'e3'
                retry_e = Some(e1);
                // Since we are retrying on this event we don't want to push it
                // to the new_events vec
                continue;
            } else {
                // Extend e1 to middle of the gap.
                e1.duration += gap / 2;

                // Make sure next event (e2) is gets extended before it's processed
                gap_prev = Some(gap);
            }
        }
        // else: nothing to do, events not near each other

        new_events.push(e1);
    }
    new_events
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use chrono::DateTime;
    use chrono::Duration;
    use serde_json::json;

    use aw_models::Event;

    use super::{flood, flood_v2};

    #[test]
    fn flood_v2_assigns_gap_to_longer_neighbor_and_ties_left() {
        let start = DateTime::from_str("2000-01-01T00:00:00Z").unwrap();
        let old_long = Event {
            id: None,
            timestamp: start,
            duration: Duration::seconds(10),
            data: json_map! {"name": json!("old")},
        };
        let new_short = Event {
            id: None,
            timestamp: start + Duration::seconds(14),
            duration: Duration::seconds(2),
            data: json_map! {"name": json!("new")},
        };
        let result = flood_v2(vec![new_short, old_long], Duration::seconds(5)).unwrap();
        assert_eq!(result[0].duration, Duration::seconds(10));
        assert_eq!(result[1].timestamp, start + Duration::seconds(10));
        assert_eq!(result[1].duration, Duration::seconds(4));
        assert_eq!(result[1].data["name"], "old");
        assert_eq!(result[2].timestamp, start + Duration::seconds(14));

        let old_short = Event {
            id: None,
            timestamp: start,
            duration: Duration::seconds(2),
            data: json_map! {"name": json!("old")},
        };
        let new_long = Event {
            id: None,
            timestamp: start + Duration::seconds(6),
            duration: Duration::seconds(10),
            data: json_map! {"name": json!("new")},
        };
        let result = flood_v2(vec![new_long, old_short.clone()], Duration::seconds(5)).unwrap();
        assert_eq!(result[0].duration, Duration::seconds(2));
        assert_eq!(result[1].timestamp, start + Duration::seconds(2));
        assert_eq!(result[1].duration, Duration::seconds(4));
        assert_eq!(result[1].data["name"], "new");
        assert_eq!(result[2].timestamp, start + Duration::seconds(6));
        assert_eq!(result[2].duration, Duration::seconds(10));

        let tied_new = Event {
            id: None,
            timestamp: start + Duration::seconds(6),
            duration: Duration::seconds(2),
            data: json_map! {"name": json!("new")},
        };
        let result = flood_v2(vec![tied_new, old_short], Duration::seconds(5)).unwrap();
        assert_eq!(result[0].duration, Duration::seconds(2));
        assert_eq!(result[1].timestamp, start + Duration::seconds(2));
        assert_eq!(result[1].duration, Duration::seconds(4));
        assert_eq!(result[1].data["name"], "old");
        assert_eq!(result[2].timestamp, start + Duration::seconds(6));
    }

    #[test]
    fn flood_v2_anchor_exact_ties_prefer_later_input() {
        let start = DateTime::from_str("2000-01-01T00:00:00Z").unwrap();
        let event = |id, offset, duration, state| Event {
            id: Some(id),
            timestamp: start + Duration::seconds(offset),
            duration: Duration::seconds(duration),
            data: json_map! {"state": json!(state)},
        };

        let left = flood_v2(
            vec![
                event(1, 0, 10, "off"),
                event(2, 0, 10, "on"),
                event(3, 12, 1, "on"),
            ],
            Duration::seconds(5),
        )
        .unwrap();
        let left_gap = left
            .iter()
            .find(|event| event.timestamp == start + Duration::seconds(10))
            .unwrap();
        assert_eq!(left_gap.duration, Duration::seconds(2));
        assert_eq!(left_gap.data["state"], "on");

        let right = flood_v2(
            vec![
                event(1, 0, 1, "on"),
                event(2, 3, 10, "off"),
                event(3, 3, 10, "on"),
            ],
            Duration::seconds(5),
        )
        .unwrap();
        let right_gap = right
            .iter()
            .find(|event| event.timestamp == start + Duration::seconds(1))
            .unwrap();
        assert_eq!(right_gap.duration, Duration::seconds(2));
        assert_eq!(right_gap.data["state"], "on");
    }

    #[test]
    fn flood_v2_retains_overlaps_and_includes_threshold() {
        let start = DateTime::from_str("2000-01-01T00:00:00Z").unwrap();
        let old = Event {
            id: None,
            timestamp: start,
            duration: Duration::seconds(10),
            data: json_map! {"name": json!("same")},
        };
        let overlapping = Event {
            id: None,
            timestamp: start + Duration::seconds(5),
            duration: Duration::seconds(2),
            data: json_map! {"name": json!("same")},
        };
        let result =
            flood_v2(vec![overlapping.clone(), old.clone()], Duration::seconds(5)).unwrap();
        assert_eq!(result, vec![old.clone(), overlapping]);

        let at_threshold = Event {
            id: None,
            timestamp: start + Duration::seconds(15),
            duration: Duration::seconds(1),
            data: json_map! {"name": json!("next")},
        };
        let result = flood_v2(vec![old, at_threshold], Duration::seconds(5)).unwrap();
        assert_eq!(result[0].duration, Duration::seconds(10));
        assert_eq!(result[1].timestamp, start + Duration::seconds(10));
        assert_eq!(result[1].duration, Duration::seconds(5));
        assert_eq!(result[2].timestamp, start + Duration::seconds(15));
    }

    #[test]
    fn flood_v2_uses_original_durations_for_each_component_gap() {
        let start = DateTime::from_str("2000-01-01T00:00:00Z").unwrap();
        let events = vec![
            Event {
                id: None,
                timestamp: start,
                duration: Duration::seconds(99),
                data: json_map! {"name": json!("a")},
            },
            Event {
                id: None,
                timestamp: start + Duration::seconds(104),
                duration: Duration::seconds(100),
                data: json_map! {"name": json!("b")},
            },
            Event {
                id: None,
                timestamp: start + Duration::seconds(205),
                duration: Duration::milliseconds(100_500),
                data: json_map! {"name": json!("c")},
            },
        ];

        let result = flood_v2(events, Duration::seconds(5)).unwrap();

        assert_eq!(result[0].timestamp, start);
        assert_eq!(result[0].duration, Duration::seconds(99));
        assert_eq!(result[1].timestamp, start + Duration::seconds(99));
        assert_eq!(result[1].duration, Duration::seconds(5));
        assert_eq!(result[1].data["name"], "b");
        assert_eq!(result[2].timestamp, start + Duration::seconds(104));
        assert_eq!(result[2].duration, Duration::seconds(100));
        assert_eq!(result[3].timestamp, start + Duration::seconds(204));
        assert_eq!(result[3].duration, Duration::seconds(1));
        assert_eq!(result[3].data["name"], "c");
        assert_eq!(result[4].timestamp, start + Duration::seconds(205));
        assert_eq!(result[4].duration, Duration::milliseconds(100_500));
    }

    #[test]
    fn flood_v2_finds_component_boundary_past_nested_records() {
        let start = DateTime::from_str("2000-01-01T00:00:00Z").unwrap();
        let events = vec![
            Event {
                id: None,
                timestamp: start,
                duration: Duration::seconds(1000),
                data: json_map! {"name": json!("long")},
            },
            Event {
                id: None,
                timestamp: start + Duration::seconds(10),
                duration: Duration::seconds(1),
                data: json_map! {"name": json!("nested")},
            },
            Event {
                id: None,
                timestamp: start + Duration::seconds(1002),
                duration: Duration::seconds(1),
                data: json_map! {"name": json!("right")},
            },
        ];

        let result = flood_v2(events.clone(), Duration::seconds(5)).unwrap();

        assert_eq!(result[0], events[0]);
        assert_eq!(result[1], events[1]);
        assert_eq!(result[2].timestamp, start + Duration::seconds(1000));
        assert_eq!(result[2].duration, Duration::seconds(2));
        assert_eq!(result[2].data["name"], "long");
        assert_eq!(result[3], events[2]);
    }

    #[test]
    fn test_flood_merge() {
        // Test merging of events with the same data
        let e1 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"test": json!(1)},
        };
        let e2 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:03Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"test": json!(1)},
        };
        let e_expected = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(4),
            data: json_map! {"test": json!(1)},
        };
        let res = flood(vec![e1, e2], Duration::seconds(5));
        assert_eq!(1, res.len());
        assert_eq!(&res[0], &e_expected);
    }

    #[test]
    fn test_flood_meet_in_middle() {
        // Test flood gap between two different events which should meet in the middle
        let e1 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"test": json!(1)},
        };
        let e2 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:03Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"test": json!(2)},
        };
        let e1_expected = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(2),
            data: json_map! {"test": json!(1)},
        };
        let e2_expected = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:02Z").unwrap(),
            duration: Duration::seconds(2),
            data: json_map! {"test": json!(2)},
        };
        let res = flood(vec![e1, e2], Duration::seconds(5));
        assert_eq!(2, res.len());
        assert_eq!(&res[0], &e1_expected);
        assert_eq!(&res[1], &e2_expected);
    }

    #[test]
    fn test_flood_partial_overlap() {
        // Tests flooding an identical event contained within another event
        let e1 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(10),
            data: json_map! {"type": "a"},
        };
        let e2 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:05Z").unwrap(),
            duration: Duration::seconds(10),
            data: json_map! {"type": "a"},
        };
        let e1_expected = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(15),
            data: json_map! {"type": "a"},
        };
        let res = flood(vec![e1, e2], Duration::seconds(5));
        assert_eq!(1, res.len());
        assert_eq!(&res[0], &e1_expected);
    }

    #[test]
    fn test_flood_containing() {
        // Tests flooding an identical event contained within another event
        let e1 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(10),
            data: json_map! {"type": "a"},
        };
        let e2 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:01Z").unwrap(),
            duration: Duration::seconds(5),
            data: json_map! {"type": "a"},
        };
        let res = flood(vec![e1.clone(), e2], Duration::seconds(5));
        assert_eq!(1, res.len());
        assert_eq!(&res[0], &e1);
    }

    #[test]
    fn test_flood_containing_diff() {
        // Tests flooding an event with different data contained within another event
        // Events should pass unmodified.
        let e1 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(10),
            data: json_map! {"type": "a"},
        };
        let e2 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:01Z").unwrap(),
            duration: Duration::seconds(5),
            data: json_map! {"type": "b"},
        };
        let res = flood(vec![e1.clone(), e2.clone()], Duration::seconds(5));
        assert_eq!(2, res.len());
        assert_eq!(&res[0], &e1);
        assert_eq!(&res[1], &e2);
    }

    #[test]
    fn test_flood_same_timestamp() {
        // e1, stay same
        // e2, base merge (longest duration, this should be the duration selected)
        // e3, merge with e2
        // e4, stay same
        let e1 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"status": "afk"},
        };
        let e2 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:01Z").unwrap(),
            duration: Duration::seconds(5),
            data: json_map! {"status": "not-afk"},
        };
        let e3 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:01Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"status": "not-afk"},
        };
        let e4 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:06Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"status": "afk"},
        };
        let res = flood(
            vec![e1.clone(), e2.clone(), e3, e4.clone()],
            Duration::seconds(5),
        );
        assert_eq!(3, res.len());
        assert_eq!(&res[0], &e1);
        assert_eq!(&res[1], &e2);
        assert_eq!(&res[2], &e4);
    }

    #[test]
    fn test_flood_same_timestamp_duplicates() {
        // e1, stay same
        // e2, base merge
        // e3, merge with e2
        // e4, merge with e2 (longest duration, this should be the duration selected)
        // e5, stay same
        let e1 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"status": "afk"},
        };
        let e2 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:01Z").unwrap(),
            duration: Duration::seconds(5),
            data: json_map! {"status": "not-afk"},
        };
        let e3 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:01Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"status": "not-afk"},
        };
        let e4 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:01Z").unwrap(),
            duration: Duration::seconds(10),
            data: json_map! {"status": "not-afk"},
        };
        let e5 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:11Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"status": "afk"},
        };
        let res = flood(
            vec![e1.clone(), e2, e3, e4.clone(), e5.clone()],
            Duration::seconds(5),
        );
        assert_eq!(3, res.len());
        assert_eq!(&res[0], &e1);
        assert_eq!(&res[1], &e4);
        assert_eq!(&res[2], &e5);
    }
}
