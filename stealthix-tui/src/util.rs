use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};
use serde_json::Value;
use std::collections::HashSet;

pub(crate) fn render_field<'a>(title: &'a str, value: &'a str, focused: bool) -> Paragraph<'a> {
    let block = if focused {
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::Cyan))
    } else {
        Block::bordered().title(title)
    };
    Paragraph::new(value.to_string())
        .block(block)
        .wrap(Wrap { trim: true })
}

pub(crate) fn render_simple_list<'a>(
    title: &'a str,
    items: &'a [String],
    selected: usize,
    focused: bool,
) -> List<'a> {
    let block = if focused {
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::Cyan))
    } else {
        Block::bordered().title(title)
    };
    let rows = items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let prefix = if idx == selected { "▶" } else { " " };
            ListItem::new(format!("{prefix} {item}"))
        })
        .collect::<Vec<_>>();
    List::new(rows).block(block)
}

pub(crate) fn render_simple_list_with_marks<'a>(
    title: &'a str,
    items: &'a [String],
    selected_items: &HashSet<String>,
    selected_index: usize,
    focused: bool,
) -> List<'a> {
    let block = if focused {
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::Cyan))
    } else {
        Block::bordered().title(title)
    };
    let rows = items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let cursor = if idx == selected_index { "▶" } else { " " };
            let mark = if selected_items.contains(item) {
                "*"
            } else {
                " "
            };
            ListItem::new(format!("{cursor} [{mark}] {item}"))
        })
        .collect::<Vec<_>>();
    List::new(rows).block(block)
}

pub(crate) fn format_duration_seconds(seconds: usize) -> String {
    let mins = seconds / 60;
    let secs = seconds % 60;
    if mins == 0 {
        format!("{secs}s")
    } else {
        format!("{mins}m {secs}s")
    }
}

pub(crate) fn centered_rect(width_percent: u16, height_percent: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - height_percent) / 2),
        Constraint::Percentage(height_percent),
        Constraint::Percentage((100 - height_percent) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - width_percent) / 2),
        Constraint::Percentage(width_percent),
        Constraint::Percentage((100 - width_percent) / 2),
    ])
    .split(vertical[1])[1]
}

pub(crate) fn cycle_index(index: &mut usize, len: usize, delta: isize) {
    if len == 0 {
        *index = 0;
    } else if delta >= 0 {
        *index = (*index + 1) % len;
    } else {
        *index = if *index == 0 { len - 1 } else { *index - 1 };
    }
}

pub(crate) fn blank_to_null(value: &str) -> Value {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Value::Null
    } else {
        Value::String(trimmed.to_string())
    }
}

pub(crate) fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn uppercase_or_info(level: &str) -> String {
    if level.trim().is_empty() {
        "INFO".to_string()
    } else {
        level.to_ascii_uppercase()
    }
}

pub(crate) fn map_to_blob(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_object)
        .map(|items| {
            items
                .iter()
                .map(|(key, value)| format!("{key}: {}", value.as_str().unwrap_or_default()))
                .collect::<Vec<_>>()
                .join(";")
        })
        .unwrap_or_default()
}

pub(crate) fn payload_to_body_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(v)) => v.clone(),
        Some(Value::Object(items)) => items
            .iter()
            .map(|(key, value)| {
                let rendered = value
                    .as_str()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| value.to_string());
                format!("{key}={rendered}")
            })
            .collect::<Vec<_>>()
            .join(";"),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

pub(crate) fn prettify_json_str(raw: &str) -> String {
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|value| serde_json::to_string_pretty(&value).ok())
        .unwrap_or_else(|| raw.to_string())
}
