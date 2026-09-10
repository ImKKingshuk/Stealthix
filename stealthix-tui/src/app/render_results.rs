use super::App;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::util::render_field;

impl App {
    pub(super) fn render_results(&mut self, frame: &mut Frame, area: Rect) {
        let [filters_area, body_area] =
            Layout::vertical([Constraint::Length(7), Constraint::Fill(1)]).areas(area);
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)])
                .areas(body_area);
        let Some(result) = self.result.clone() else {
            frame.render_widget(
                Paragraph::new("No results yet. Run a scan from the Scan tab.")
                    .block(Block::bordered().title("Results")),
                area,
            );
            return;
        };

        let kind_options = self.result_kind_options();
        let [filter_top, filter_bottom] =
            Layout::vertical([Constraint::Length(3), Constraint::Length(3)]).areas(filters_area);
        let filter_top_chunks: [Rect; 4] = Layout::horizontal([
            Constraint::Percentage(32),
            Constraint::Percentage(16),
            Constraint::Percentage(24),
            Constraint::Percentage(28),
        ])
        .areas(filter_top);
        let filter_bottom_chunks: [Rect; 4] = Layout::horizontal([
            Constraint::Percentage(28),
            Constraint::Percentage(20),
            Constraint::Percentage(24),
            Constraint::Percentage(28),
        ])
        .areas(filter_bottom);
        frame.render_widget(
            render_field("Search", &self.results.search, self.results.focus == 0),
            filter_top_chunks[0],
        );
        frame.render_widget(
            render_field(
                "Severity",
                Self::severity_options()
                    .get(self.results.severity_index)
                    .copied()
                    .unwrap_or("All"),
                self.results.focus == 1,
            ),
            filter_top_chunks[1],
        );
        frame.render_widget(
            render_field(
                "Kind",
                kind_options
                    .get(self.results.kind_index)
                    .map(String::as_str)
                    .unwrap_or("All"),
                self.results.focus == 2,
            ),
            filter_top_chunks[2],
        );
        frame.render_widget(
            render_field(
                "Primary Sort",
                match self.results.sort_index {
                    1 => "Severity",
                    2 => "Kind",
                    3 => "Target",
                    _ => "CVSS",
                },
                self.results.focus == 3,
            ),
            filter_top_chunks[3],
        );
        frame.render_widget(
            render_field(
                "Secondary Sort",
                match self.results.secondary_sort_index {
                    1 => "Kind",
                    2 => "Target",
                    3 => "Severity",
                    _ => "None",
                },
                self.results.focus == 4,
            ),
            filter_bottom_chunks[0],
        );
        frame.render_widget(
            render_field(
                "Direction",
                if self.results.sort_desc {
                    "Desc"
                } else {
                    "Asc"
                },
                self.results.focus == 5,
            ),
            filter_bottom_chunks[1],
        );
        let tested_count = result
            .metadata
            .get("tested_params")
            .and_then(|value| value.as_array())
            .map(|items| items.len())
            .unwrap_or(0);
        let tested_count_text = tested_count.to_string();
        frame.render_widget(
            render_field(
                "Selected Only",
                if self.results.selected_only {
                    "on"
                } else {
                    "off"
                },
                self.results.focus == 6,
            ),
            filter_bottom_chunks[2],
        );
        frame.render_widget(
            render_field("Tested Params", &tested_count_text, false),
            filter_bottom_chunks[3],
        );

        let visible = self.filtered_finding_indices();
        let items: Vec<ListItem> = visible
            .iter()
            .filter_map(|idx| result.findings.get(*idx).map(|finding| (*idx, finding)))
            .map(|(idx, finding)| {
                let selected_marker = if self.results.selected.contains(&idx) {
                    "*"
                } else {
                    " "
                };
                ListItem::new(format!(
                    "{selected_marker} {} [{}] {:.1} → {}",
                    finding.kind, finding.severity, finding.cvss, finding.target
                ))
            })
            .collect();
        let list = List::new(items)
            .block(Block::bordered().title(format!(
                "Findings ({}/{})",
                visible.len(),
                result.findings.len()
            )))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(list, left, &mut self.findings_state);

        let detail = self
            .current_result_index()
            .and_then(|idx| result.findings.get(idx).cloned())
            .unwrap_or_default();
        let detail_text =
            serde_json::to_string_pretty(&detail).unwrap_or_else(|_| "{}".to_string());
        let meta_text =
            serde_json::to_string_pretty(&result.metadata).unwrap_or_else(|_| "{}".to_string());
        let export_hint = if self.init.report_formats.is_empty() {
            "json · markdown · html · pdf".to_string()
        } else {
            self.init.report_formats.join(" · ")
        };
        let panel = Paragraph::new(Text::from(vec![
            Line::from(format!("Target: {}", result.target)).bold(),
            Line::from(format!(
                "Filtered findings: {} · Selected set: {} · Tested params: {}",
                visible.len(),
                self.results.selected.len(),
                tested_count,
            )),
            Line::from(""),
            Line::from("Finding detail:"),
            Line::from(detail_text),
            Line::from(""),
            Line::from("Metadata:"),
            Line::from(meta_text),
            Line::from(""),
            Line::from(format!("Export: 1/2/3/4 → {export_hint}")),
            Line::from("Tab focus filters · Space toggle selection · o selected-only · z reset"),
            Line::from("Primary sort + secondary sort mirror the old multi-sort flow."),
        ]))
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Detail"));
        frame.render_widget(panel, right);
    }
}
