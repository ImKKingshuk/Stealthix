use super::App;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Stylize;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::util::{render_field, render_simple_list, render_simple_list_with_marks};

impl App {
    pub(super) fn render_extract(&self, frame: &mut Frame, area: Rect) {
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)])
                .areas(area);
        let left_areas: [Rect; 9] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Fill(1),
        ])
        .areas(left);

        frame.render_widget(
            render_field(
                "Action",
                self.extract.action().label(),
                self.extract.focus == 0,
            ),
            left_areas[0],
        );
        frame.render_widget(
            render_field("Database", &self.extract.database, self.extract.focus == 1),
            left_areas[1],
        );
        frame.render_widget(
            render_field("Table", &self.extract.table, self.extract.focus == 2),
            left_areas[2],
        );
        frame.render_widget(
            render_field(
                "Columns (csv)",
                &self.extract.columns,
                self.extract.focus == 3,
            ),
            left_areas[3],
        );
        frame.render_widget(
            render_field(
                "File Path",
                &self.extract.file_path,
                self.extract.focus == 4,
            ),
            left_areas[4],
        );
        frame.render_widget(
            render_field("Command", &self.extract.command, self.extract.focus == 5),
            left_areas[5],
        );
        frame.render_widget(
            render_simple_list(
                "Databases",
                &self.extract.databases,
                self.extract.selected_database_index,
                self.extract.focus == 6,
            ),
            left_areas[6],
        );
        frame.render_widget(
            render_simple_list(
                "Tables",
                &self.extract.tables,
                self.extract.selected_table_index,
                self.extract.focus == 7,
            ),
            left_areas[7],
        );
        frame.render_widget(
            render_simple_list_with_marks(
                "Columns / selection",
                &self.extract.available_columns,
                &self.extract.selected_columns,
                self.extract.selected_column_index,
                self.extract.focus == 8,
            ),
            left_areas[8],
        );

        let [output_area, help_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(6)]).areas(right);
        let output = Paragraph::new(self.extract.output.clone())
            .block(Block::bordered().title("Output / dump preview"))
            .wrap(Wrap { trim: false });
        frame.render_widget(output, output_area);
        let help = Paragraph::new(Text::from(vec![
            Line::from("F5 / Enter execute extraction".bold()),
            Line::from("Tab moves focus · Up/Down browse lists · Space applies/toggles list item"),
            Line::from("j export dump JSON · v export dump CSV"),
            Line::from("A completed scan session is required for extraction."),
        ]))
        .block(Block::bordered().title("Hints"))
        .wrap(Wrap { trim: true });
        frame.render_widget(help, help_area);
    }
}
