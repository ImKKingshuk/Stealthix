use super::App;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Clear, Gauge, List, ListItem, Paragraph, Tabs, Wrap};
use ratatui::Frame;

use crate::state::Screen;
use crate::util::{centered_rect, format_duration_seconds, uppercase_or_info};

impl App {
    pub(super) fn render(&mut self, frame: &mut Frame) {
        let [tabs_area, body_area, footer_area] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Fill(1),
            Constraint::Length(2),
        ])
        .areas(frame.area());

        let title = format!("Stealthix [{}]", self.theme.name());
        let tabs = Tabs::new(vec!["Scan", "Running", "Results", "Extract", "Proxy"])
            .select(self.screen.index())
            .block(Block::bordered().title(title))
            .highlight_style(
                Style::default()
                    .fg(self.theme.primary())
                    .add_modifier(Modifier::BOLD),
            );
        frame.render_widget(tabs, tabs_area);

        match self.screen {
            Screen::Scan => self.render_scan(frame, body_area),
            Screen::Running => self.render_running(frame, body_area),
            Screen::Results => self.render_results(frame, body_area),
            Screen::Extract => self.render_extract(frame, body_area),
            Screen::Proxy => self.render_proxy(frame, body_area),
        }

        let footer = Paragraph::new(self.status_line.clone())
            .wrap(Wrap { trim: true })
            .block(Block::bordered().title(
                "Status / shortcuts: q quit · s scan · r results · e extract · w proxy · t theme · ? help",
            ));
        frame.render_widget(footer, footer_area);

        if self.show_help {
            self.render_help(frame);
        }
    }

    fn render_running(&self, frame: &mut Frame, area: Rect) {
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
                .areas(area);
        let [gauge_area, summary_area] =
            Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).areas(left);
        let gauge = Gauge::default()
            .block(Block::bordered().title("Progress"))
            .gauge_style(Style::default().fg(self.theme.primary()).bg(Color::Black))
            .percent(self.running.progress_percent.min(100) as u16)
            .label(format!(
                "{}% · {} · {} finding(s)",
                self.running.progress_percent, self.running.phase, self.running.finding_count
            ));
        frame.render_widget(gauge, gauge_area);
        let summary = Paragraph::new(Text::from(vec![
            Line::from(format!("Status: {}", self.running.status)).fg(self.theme.primary()),
            Line::from(format!("Phase: {}", self.running.phase)),
            Line::from(format!("Progress: {}%", self.running.progress_percent)),
            Line::from(format!(
                "Job ID: {}",
                self.running.job_id.as_deref().unwrap_or("-")
            )),
            Line::from(format!(
                "Started: {}",
                self.running.started_at.as_deref().unwrap_or("-")
            )),
            Line::from(format!(
                "Finished: {}",
                self.running.finished_at.as_deref().unwrap_or("-")
            )),
            Line::from(format!("Findings: {}", self.running.finding_count)),
            Line::from(format!(
                "Requests: {}/{}",
                self.running.request_count,
                if self.running.estimated_total_requests == 0 {
                    "?".to_string()
                } else {
                    self.running.estimated_total_requests.to_string()
                }
            )),
            Line::from(format!(
                "ETA: {}",
                self.running
                    .eta_seconds
                    .map(format_duration_seconds)
                    .unwrap_or_else(|| "-".to_string())
            )),
            Line::from(format!(
                "Active time: {}",
                format_duration_seconds(self.running.active_elapsed_seconds.round() as usize)
            )),
            Line::from(format!(
                "Paused: {}",
                if self.running.paused { "yes" } else { "no" }
            )),
            Line::from(format!(
                "Tested params: {}",
                self.running.tested_params_summary
            )),
            Line::from(""),
            Line::from(self.running.message.clone()),
            Line::from(""),
            Line::from("Press space to pause/resume, p to poll immediately, c to cancel."),
            Line::from("The gauge above mirrors the old running-screen progress widget."),
        ]))
        .block(Block::bordered().title("Running"))
        .wrap(Wrap { trim: true });
        frame.render_widget(summary, summary_area);

        let log_lines: Vec<ListItem> = self
            .messages
            .iter()
            .rev()
            .take(20)
            .rev()
            .map(|entry| {
                ListItem::new(format!(
                    "[{}] {}",
                    uppercase_or_info(&entry.level),
                    entry.message
                ))
            })
            .collect();
        let logs = List::new(log_lines).block(Block::bordered().title("Bridge / job logs"));
        frame.render_widget(logs, right);
    }

    fn render_help(&self, frame: &mut Frame) {
        let area = centered_rect(80, 70, frame.area());
        frame.render_widget(Clear, area);
        let help = Paragraph::new(Text::from(vec![
            Line::from("Stealthix Rust TUI shortcuts")
                .bold()
                .fg(self.theme.primary()),
            Line::from(""),
            Line::from("q quit"),
            Line::from("s scan screen"),
            Line::from("r results screen"),
            Line::from("e extraction screen"),
            Line::from("w proxy workspace screen"),
            Line::from("t cycle color theme (Cyan, Matrix Green, Dracula, High Contrast)"),
            Line::from("? or F1 or h toggle help dialog"),
            Line::from("Tab / Shift+Tab move focus"),
            Line::from("F5 run the primary action on the current screen"),
            Line::from("Ctrl+S save profile from scan screen"),
            Line::from("Ctrl+L load profile from scan screen"),
            Line::from(
                "Ctrl+D discover params · Ctrl+P restore default payloads for active family",
            ),
            Line::from("Running: Space pause/resume · p poll · c cancel"),
            Line::from("Results: / search · y copy finding · Tab filters · Space select · o selected-only · z reset"),
            Line::from("1/2/3/4/5 export report in results screen (JSON / MD / HTML / PDF / CSV)"),
            Line::from("Extract: browse db/table/column lists and export dump with j/v"),
            Line::from("Proxy: j/k select records · l refresh persistent history"),
            Line::from(""),
            Line::from("Press Esc, ?, h, or F1 to close this dialog."),
        ]))
        .block(Block::bordered().title("Help"))
        .wrap(Wrap { trim: true });
        frame.render_widget(help, area);
    }

    fn render_proxy(&self, frame: &mut Frame, area: Rect) {
        let [top, body] =
            Layout::vertical([Constraint::Length(5), Constraint::Fill(1)]).areas(area);
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
                .areas(body);
        let stats_text =
            serde_json::to_string_pretty(&self.proxy.stats).unwrap_or_else(|_| "{}".to_string());
        let summary = Paragraph::new(Text::from(vec![
            Line::from("Persistent proxy workspace").bold().fg(Color::Cyan),
            Line::from(format!("Records loaded: {}", self.proxy.records.len())),
            Line::from("Use the headless proxy import/search/export commands to capture and persist history."),
            Line::from(self.proxy.last_error.clone()),
        ]))
        .wrap(Wrap { trim: true })
        .block(Block::bordered().title("Proxy Workspace"));
        frame.render_widget(summary, top);

        let items: Vec<ListItem> = self
            .proxy
            .records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                let request = record.get("request").and_then(|value| value.as_object());
                let method = request
                    .and_then(|value| value.get("method"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("-");
                let url = request
                    .and_then(|value| value.get("url"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("-");
                let response = record.get("response").and_then(|value| value.as_object());
                let status = response
                    .and_then(|value| value.get("status_code"))
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let marker = if index == self.proxy.selected_index {
                    ">"
                } else {
                    " "
                };
                ListItem::new(format!("{marker} {method} {status} {url}"))
            })
            .collect();
        let list = List::new(items).block(Block::bordered().title("History"));
        frame.render_widget(list, left);

        let selected = self
            .proxy
            .records
            .get(self.proxy.selected_index)
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"message": "No proxy records captured yet."}));
        let detail_text =
            serde_json::to_string_pretty(&selected).unwrap_or_else(|_| "{}".to_string());
        let detail = Paragraph::new(Text::from(vec![
            Line::from("Stats:").bold(),
            Line::from(stats_text),
            Line::from(""),
            Line::from("Selected record:").bold(),
            Line::from(detail_text),
            Line::from(""),
            Line::from("j/k select · l refresh"),
        ]))
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Detail"));
        frame.render_widget(detail, right);
    }
}
