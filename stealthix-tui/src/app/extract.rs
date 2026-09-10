use super::App;
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::{json, Value};

use crate::state::ExtractAction;
use crate::util::{blank_to_null, cycle_index, prettify_json_str, split_csv};

impl App {
    pub(super) fn handle_extract_key(&mut self, key: KeyEvent) -> Result<()> {
        match (key.code, key.modifiers) {
            (KeyCode::Tab, _) => self.extract.focus_next(),
            (KeyCode::BackTab, _) => self.extract.focus_prev(),
            (KeyCode::Left, _) => self.adjust_extract_field(-1),
            (KeyCode::Right, _) => self.adjust_extract_field(1),
            (KeyCode::F(5), _) | (KeyCode::Enter, _) => self.run_extract_action()?,
            (KeyCode::Down, _) => self.navigate_extract_list(1),
            (KeyCode::Up, _) => self.navigate_extract_list(-1),
            (KeyCode::Char(' '), _) => self.toggle_extract_column_selection(),
            (KeyCode::Char('j'), _) => self.export_dump("json")?,
            (KeyCode::Char('v'), _) => self.export_dump("csv")?,
            (KeyCode::Char(c), mods) if mods.is_empty() || mods == KeyModifiers::SHIFT => {
                self.push_extract_char(c)
            }
            (KeyCode::Backspace, _) => self.pop_extract_char(),
            _ => {}
        }
        Ok(())
    }

    fn run_extract_action(&mut self) -> Result<()> {
        let Some(session) = self.session.clone() else {
            self.status_line = "No active scan session available for extraction.".to_string();
            return Ok(());
        };
        let params = json!({
            "session": session,
            "database": blank_to_null(&self.extract.database),
            "table": blank_to_null(&self.extract.table),
            "columns": self.current_extract_columns(),
            "path": blank_to_null(&self.extract.file_path),
            "command": blank_to_null(&self.extract.command),
        });
        let action = self.extract.action().action_name();
        let response = self.invoke(action, params)?;
        self.status_line = response
            .message
            .unwrap_or_else(|| format!("{} complete.", self.extract.action().label()));
        if let Some(data_json) = response.data_json {
            self.extract.output = prettify_json_str(&data_json);
            self.apply_extract_response(action, &data_json);
        }
        Ok(())
    }

    fn current_extract_columns(&self) -> Vec<String> {
        if !self.extract.selected_columns.is_empty() {
            let mut values = self
                .extract
                .selected_columns
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            values.sort();
            values
        } else {
            split_csv(&self.extract.columns)
        }
    }

    fn apply_extract_response(&mut self, action: &str, data_json: &str) {
        let payload = serde_json::from_str::<Value>(data_json).unwrap_or_else(|_| json!({}));
        match action {
            "extract.enum_databases" => {
                self.extract.databases = payload
                    .get("databases")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(ToString::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                self.extract.selected_database_index = 0;
            }
            "extract.enum_tables" => {
                self.extract.tables = payload
                    .get("tables")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(ToString::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                self.extract.selected_table_index = 0;
            }
            "extract.enum_columns" => {
                self.extract.available_columns = payload
                    .get("columns")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(ToString::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                self.extract.selected_columns.clear();
                self.extract.selected_column_index = 0;
            }
            "extract.dump_table" => {
                self.extract.last_dump = Some(payload);
            }
            _ => {}
        }
    }

    fn navigate_extract_list(&mut self, delta: isize) {
        let list_len = match self.extract.focus {
            6 => self.extract.databases.len(),
            7 => self.extract.tables.len(),
            8 => self.extract.available_columns.len(),
            _ => {
                if delta > 0 {
                    self.extract.focus_next();
                } else {
                    self.extract.focus_prev();
                }
                return;
            }
        };
        match self.extract.focus {
            6 => cycle_index(&mut self.extract.selected_database_index, list_len, delta),
            7 => cycle_index(&mut self.extract.selected_table_index, list_len, delta),
            8 => cycle_index(&mut self.extract.selected_column_index, list_len, delta),
            _ => {}
        }
    }

    fn toggle_extract_column_selection(&mut self) {
        match self.extract.focus {
            6 => {
                if let Some(database) = self
                    .extract
                    .databases
                    .get(self.extract.selected_database_index)
                    .cloned()
                {
                    self.extract.database = database;
                }
            }
            7 => {
                if let Some(table) = self
                    .extract
                    .tables
                    .get(self.extract.selected_table_index)
                    .cloned()
                {
                    self.extract.table = table;
                }
            }
            8 => {
                if let Some(column) = self
                    .extract
                    .available_columns
                    .get(self.extract.selected_column_index)
                    .cloned()
                {
                    if !self.extract.selected_columns.insert(column.clone()) {
                        self.extract.selected_columns.remove(&column);
                    }
                    let mut values = self
                        .extract
                        .selected_columns
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>();
                    values.sort();
                    self.extract.columns = values.join(",");
                }
            }
            _ => {}
        }
    }

    fn export_dump(&mut self, format_name: &str) -> Result<()> {
        let Some(session) = self.session.clone() else {
            self.status_line = "Run a scan first to unlock dump export.".to_string();
            return Ok(());
        };
        let Some(dump) = self.extract.last_dump.clone() else {
            self.status_line = "No dump payload available yet. Run Dump Table first.".to_string();
            return Ok(());
        };
        let response = self.invoke(
            "extract.export_dump",
            json!({
                "session": session,
                "format": format_name,
                "table": blank_to_null(&self.extract.table),
                "columns": self.current_extract_columns(),
                "dump": dump,
            }),
        )?;
        self.status_line = response
            .message
            .unwrap_or_else(|| format!("Dump exported as {format_name}."));
        Ok(())
    }

    fn adjust_extract_field(&mut self, delta: isize) {
        if self.extract.focus == 0 {
            cycle_index(
                &mut self.extract.action_index,
                ExtractAction::all().len(),
                delta,
            );
        }
    }

    fn push_extract_char(&mut self, c: char) {
        if let Some(target) = self.extract_text_field_mut() {
            target.push(c);
        }
    }

    fn pop_extract_char(&mut self) {
        if let Some(target) = self.extract_text_field_mut() {
            target.pop();
        }
    }

    fn extract_text_field_mut(&mut self) -> Option<&mut String> {
        match self.extract.focus {
            1 => Some(&mut self.extract.database),
            2 => Some(&mut self.extract.table),
            3 => Some(&mut self.extract.columns),
            4 => Some(&mut self.extract.file_path),
            5 => Some(&mut self.extract.command),
            _ => None,
        }
    }
}
