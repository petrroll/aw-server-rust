use aw_models::Event;
use serde_json::Value;

pub fn map_event_fields(mut events: Vec<Event>, mappings: &Value) -> Result<Vec<Event>, String> {
    let mappings = mappings
        .as_object()
        .ok_or_else(|| "field mappings must be an object".to_string())?;
    let mappings = mappings
        .iter()
        .map(|(target, source)| match source {
            Value::String(source) if !target.is_empty() && !source.is_empty() => {
                Ok((target.clone(), source.clone()))
            }
            _ => Err("field mappings must map non-empty target names to source names".to_string()),
        })
        .collect::<Result<Vec<_>, _>>()?;

    for event in &mut events {
        let original_data = event.data.clone();
        for (target, source) in &mappings {
            if let Some(value) = original_data.get(source).cloned() {
                event.data.insert(target.clone(), value);
            }
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use aw_models::Event;
    use serde_json::json;

    use super::map_event_fields;

    #[test]
    fn maps_existing_fields_to_canonical_names() {
        let mut event = Event::default();
        event.data.insert("subject".to_string(), json!("Planning"));
        let result = map_event_fields(vec![event], &json!({"title": "subject"})).unwrap();
        assert_eq!(result[0].data["title"], json!("Planning"));
    }

    #[test]
    fn mappings_read_from_the_original_event_data() {
        let mut event = Event::default();
        event.data.insert("provider".to_string(), json!("Teams"));
        event.data.insert("app".to_string(), json!("Original"));

        let result =
            map_event_fields(vec![event], &json!({"app": "provider", "title": "app"})).unwrap();

        assert_eq!(result[0].data["app"], json!("Teams"));
        assert_eq!(result[0].data["title"], json!("Original"));
    }
}
