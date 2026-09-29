use std::collections::{BTreeSet, BinaryHeap};

use aw_models::Event;
use chrono::{DateTime, Utc};

/// Resolves overlapping records into fact slices.
///
/// The newest start wins, then the later end, then the later input record. The
/// last rule makes exact ties follow concatenated source order.
pub(crate) fn resolve_fact_slices(events: &[Event]) -> Vec<Event> {
    let ends = events
        .iter()
        .map(Event::calculate_endtime)
        .collect::<Vec<_>>();
    let mut boundaries = BTreeSet::new();
    let mut start_order = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event.timestamp < ends[index] {
            boundaries.insert(event.timestamp);
            boundaries.insert(ends[index]);
            start_order.push(index);
        }
    }
    start_order.sort_by_key(|index| (events[*index].timestamp, *index));

    let mut active = BinaryHeap::<(DateTime<Utc>, DateTime<Utc>, usize)>::new();
    let mut next_start = 0;
    let mut result: Vec<Event> = Vec::new();
    let mut last_winner = None;
    let boundary_points = boundaries.into_iter().collect::<Vec<_>>();
    for pair in boundary_points.windows(2) {
        let start = pair[0];
        let end = pair[1];
        while next_start < start_order.len() && events[start_order[next_start]].timestamp <= start {
            let index = start_order[next_start];
            active.push((events[index].timestamp, ends[index], index));
            next_start += 1;
        }
        while active
            .peek()
            .is_some_and(|(_, event_end, _)| *event_end <= start)
        {
            active.pop();
        }
        let Some((_, _, winner)) = active.peek().copied() else {
            continue;
        };

        let mut slice = events[winner].clone();
        slice.timestamp = start;
        slice.duration = end - start;
        if let Some(previous) = result.last_mut() {
            if last_winner == Some(winner) && previous.calculate_endtime() == slice.timestamp {
                previous.duration += slice.duration;
                continue;
            }
        }
        result.push(slice);
        last_winner = Some(winner);
    }
    result
}

#[cfg(test)]
mod tests {
    use aw_models::Event;
    use chrono::{Duration, TimeZone, Utc};
    use serde_json::json;

    use super::resolve_fact_slices;

    fn event(start: i64, duration: i64, id: i64, state: &str) -> Event {
        Event {
            id: Some(id),
            timestamp: Utc.timestamp_opt(start, 0).unwrap(),
            duration: Duration::seconds(duration),
            data: json!({"state": state}).as_object().unwrap().clone(),
        }
    }

    #[test]
    fn latest_fact_expires_back_to_the_older_fact() {
        let facts = resolve_fact_slices(&[event(0, 30, 1, "on"), event(10, 10, 2, "off")]);
        assert_eq!(
            facts
                .iter()
                .map(|event| (
                    event.timestamp.timestamp(),
                    event.duration.num_seconds(),
                    event.data["state"].as_str().unwrap()
                ))
                .collect::<Vec<_>>(),
            vec![(0, 10, "on"), (10, 10, "off"), (20, 10, "on")]
        );
    }

    #[test]
    fn exact_ties_prefer_the_later_input_record() {
        let facts = resolve_fact_slices(&[event(0, 30, 100, "first"), event(0, 30, 101, "second")]);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].data["state"], json!("second"));
        assert_eq!(facts[0].id, Some(101));
    }
}
