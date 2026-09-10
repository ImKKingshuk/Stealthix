use super::App;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Stylize;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::util::render_field;

impl App {
    pub(super) fn render_scan(&self, frame: &mut Frame, area: Rect) {
        let [top, bottom] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(7)]).areas(area);
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);

        let left_areas: [Rect; 9] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .areas(left);
        let right_areas: [Rect; 8] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Fill(1),
        ])
        .areas(right);

        frame.render_widget(
            render_field("Target URL", &self.scan_form.url, self.scan_form.focus == 0),
            left_areas[0],
        );
        frame.render_widget(
            render_field("Method", &self.current_method(), self.scan_form.focus == 1),
            left_areas[1],
        );
        frame.render_widget(
            render_field(
                "DBMS",
                self.current_dbms().as_deref().unwrap_or("auto"),
                self.scan_form.focus == 2,
            ),
            left_areas[2],
        );
        frame.render_widget(
            render_field(
                "Technique",
                &self.scan_form.technique,
                self.scan_form.focus == 3,
            ),
            left_areas[3],
        );
        frame.render_widget(
            render_field(
                "Risk",
                &self.current_risk().to_string(),
                self.scan_form.focus == 4,
            ),
            left_areas[4],
        );
        frame.render_widget(
            render_field(
                "Level",
                &self.current_level().to_string(),
                self.scan_form.focus == 5,
            ),
            left_areas[5],
        );
        frame.render_widget(
            render_field(
                "Threads",
                &self.scan_form.threads,
                self.scan_form.focus == 13,
            ),
            left_areas[6],
        );
        frame.render_widget(
            render_field(
                "Verify TLS",
                if self.scan_form.verify_tls {
                    "on"
                } else {
                    "off"
                },
                self.scan_form.focus == 14,
            ),
            left_areas[7],
        );
        frame.render_widget(
            render_field(
                "Discovered Params",
                &self.scan_form.discovered_params.join(", "),
                false,
            ),
            left_areas[8],
        );

        frame.render_widget(
            render_field(
                "Body Format",
                self.current_body_format(),
                self.scan_form.focus == 6,
            ),
            right_areas[0],
        );
        frame.render_widget(
            render_field(
                "Body (k=v;k2=v2 or JSON)",
                &self.scan_form.body,
                self.scan_form.focus == 7,
            ),
            right_areas[1],
        );
        frame.render_widget(
            render_field(
                "Headers (k:v;k2:v2)",
                &self.scan_form.headers,
                self.scan_form.focus == 8,
            ),
            right_areas[2],
        );
        frame.render_widget(
            render_field(
                "Cookies (k=v;k2=v2)",
                &self.scan_form.cookies,
                self.scan_form.focus == 9,
            ),
            right_areas[3],
        );
        frame.render_widget(
            render_field("Proxy", &self.scan_form.proxy, self.scan_form.focus == 10),
            right_areas[4],
        );
        frame.render_widget(
            render_field(
                "Target Params (csv)",
                &self.scan_form.target_params,
                self.scan_form.focus == 11,
            ),
            right_areas[5],
        );
        frame.render_widget(
            render_field(
                "Profile Name",
                &self.scan_form.profile_name,
                self.scan_form.focus == 12,
            ),
            right_areas[6],
        );
        frame.render_widget(
            render_field(
                "Payload Family / Editor (Ctrl+P loads defaults)",
                &format!(
                    "{}\n{}",
                    self.active_payload_family(),
                    self.scan_form.payload_editor
                ),
                self.scan_form.focus == 15 || self.scan_form.focus == 16,
            ),
            right_areas[7],
        );

        let profiles = if self.init.profiles.is_empty() {
            "Profiles: none saved yet".to_string()
        } else {
            format!("Profiles: {}", self.init.profiles.join(", "))
        };
        let [actions_area, discovery_area] =
            Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)])
                .areas(bottom);
        let hints = Paragraph::new(Text::from(vec![
            Line::from("F5 / Ctrl+Enter start scan".bold()),
            Line::from("Ctrl+S save profile · Ctrl+L load profile · Ctrl+D discover params"),
            Line::from("Ctrl+P load default payloads for current family · Left/Right cycle dropdown fields"),
            Line::from(profiles),
        ]))
        .block(Block::bordered().title("Actions"))
        .wrap(Wrap { trim: true });
        frame.render_widget(hints, actions_area);
        let discovery = Paragraph::new(self.scan_form.discovered_params.join("\n"))
            .block(Block::bordered().title("Discovered Param Notes"))
            .wrap(Wrap { trim: true });
        frame.render_widget(discovery, discovery_area);
    }
}
