use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum Theme {
    #[default]
    CyanDark,
    MatrixGreen,
    Dracula,
    HighContrast,
}

#[allow(dead_code)]
impl Theme {
    pub(crate) fn next(self) -> Self {
        match self {
            Theme::CyanDark => Theme::MatrixGreen,
            Theme::MatrixGreen => Theme::Dracula,
            Theme::Dracula => Theme::HighContrast,
            Theme::HighContrast => Theme::CyanDark,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Theme::CyanDark => "Cyan Dark",
            Theme::MatrixGreen => "Matrix Green",
            Theme::Dracula => "Dracula",
            Theme::HighContrast => "High Contrast",
        }
    }

    pub(crate) fn primary(self) -> ratatui::style::Color {
        match self {
            Theme::CyanDark => ratatui::style::Color::Cyan,
            Theme::MatrixGreen => ratatui::style::Color::Green,
            Theme::Dracula => ratatui::style::Color::Magenta,
            Theme::HighContrast => ratatui::style::Color::Yellow,
        }
    }

    pub(crate) fn secondary(self) -> ratatui::style::Color {
        match self {
            Theme::CyanDark => ratatui::style::Color::Blue,
            Theme::MatrixGreen => ratatui::style::Color::DarkGray,
            Theme::Dracula => ratatui::style::Color::Cyan,
            Theme::HighContrast => ratatui::style::Color::White,
        }
    }

    pub(crate) fn accent(self) -> ratatui::style::Color {
        match self {
            Theme::CyanDark => ratatui::style::Color::Yellow,
            Theme::MatrixGreen => ratatui::style::Color::LightGreen,
            Theme::Dracula => ratatui::style::Color::LightYellow,
            Theme::HighContrast => ratatui::style::Color::LightCyan,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_cycle() {
        let mut t = Theme::default();
        assert_eq!(t, Theme::CyanDark);
        t = t.next();
        assert_eq!(t, Theme::MatrixGreen);
        t = t.next();
        assert_eq!(t, Theme::Dracula);
        t = t.next();
        assert_eq!(t, Theme::HighContrast);
        t = t.next();
        assert_eq!(t, Theme::CyanDark);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Screen {
    Scan,
    Running,
    Results,
    Extract,
    Proxy,
}

impl Screen {
    pub(crate) fn index(self) -> usize {
        match self {
            Screen::Scan => 0,
            Screen::Running => 1,
            Screen::Results => 2,
            Screen::Extract => 3,
            Screen::Proxy => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtractAction {
    EnumDatabases,
    EnumTables,
    EnumColumns,
    DumpTable,
    ReadFile,
    ExecuteCommand,
    ExtractHashes,
}

impl ExtractAction {
    pub(crate) fn all() -> &'static [ExtractAction] {
        &[
            ExtractAction::EnumDatabases,
            ExtractAction::EnumTables,
            ExtractAction::EnumColumns,
            ExtractAction::DumpTable,
            ExtractAction::ReadFile,
            ExtractAction::ExecuteCommand,
            ExtractAction::ExtractHashes,
        ]
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            ExtractAction::EnumDatabases => "Enum DBs",
            ExtractAction::EnumTables => "Enum Tables",
            ExtractAction::EnumColumns => "Enum Columns",
            ExtractAction::DumpTable => "Dump Table",
            ExtractAction::ReadFile => "Read File",
            ExtractAction::ExecuteCommand => "OS Command",
            ExtractAction::ExtractHashes => "Extract Hashes",
        }
    }

    pub(crate) fn action_name(self) -> &'static str {
        match self {
            ExtractAction::EnumDatabases => "extract.enum_databases",
            ExtractAction::EnumTables => "extract.enum_tables",
            ExtractAction::EnumColumns => "extract.enum_columns",
            ExtractAction::DumpTable => "extract.dump_table",
            ExtractAction::ReadFile => "extract.read_file",
            ExtractAction::ExecuteCommand => "extract.execute_command",
            ExtractAction::ExtractHashes => "extract.hashes",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ScanForm {
    pub(crate) url: String,
    pub(crate) method_index: usize,
    pub(crate) dbms_index: usize,
    pub(crate) technique: String,
    pub(crate) risk_index: usize,
    pub(crate) level_index: usize,
    pub(crate) threads: String,
    pub(crate) body_format_index: usize,
    pub(crate) body: String,
    pub(crate) headers: String,
    pub(crate) cookies: String,
    pub(crate) proxy: String,
    pub(crate) target_params: String,
    pub(crate) profile_name: String,
    pub(crate) verify_tls: bool,
    pub(crate) payload_family_index: usize,
    pub(crate) payload_editor: String,
    pub(crate) custom_payloads: HashMap<String, Vec<String>>,
    pub(crate) discovered_params: Vec<String>,
    pub(crate) focus: usize,
    pub(crate) loaded_metadata: Value,
}

impl Default for ScanForm {
    fn default() -> Self {
        Self {
            url: String::new(),
            method_index: 0,
            dbms_index: 0,
            technique: String::new(),
            risk_index: 0,
            level_index: 0,
            threads: "5".to_string(),
            body_format_index: 0,
            body: String::new(),
            headers: String::new(),
            cookies: String::new(),
            proxy: String::new(),
            target_params: String::new(),
            profile_name: String::new(),
            verify_tls: true,
            payload_family_index: 0,
            payload_editor: String::new(),
            custom_payloads: HashMap::new(),
            discovered_params: Vec::new(),
            focus: 0,
            loaded_metadata: json!({}),
        }
    }
}

impl ScanForm {
    const FIELD_COUNT: usize = 17;

    pub(crate) fn focus_next(&mut self) {
        self.focus = (self.focus + 1) % Self::FIELD_COUNT;
    }

    pub(crate) fn focus_prev(&mut self) {
        self.focus = if self.focus == 0 {
            Self::FIELD_COUNT - 1
        } else {
            self.focus - 1
        };
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RunningState {
    pub(crate) job_id: Option<String>,
    pub(crate) status: String,
    pub(crate) message: String,
    pub(crate) started_at: Option<String>,
    pub(crate) finished_at: Option<String>,
    pub(crate) finding_count: usize,
    pub(crate) phase: String,
    pub(crate) progress_percent: usize,
    pub(crate) request_count: usize,
    pub(crate) estimated_total_requests: usize,
    pub(crate) eta_seconds: Option<usize>,
    pub(crate) active_elapsed_seconds: f64,
    pub(crate) tested_params_summary: String,
    pub(crate) paused: bool,
    pub(crate) last_poll: Instant,
}

impl Default for RunningState {
    fn default() -> Self {
        Self {
            job_id: None,
            status: "idle".to_string(),
            message: "No active scan.".to_string(),
            started_at: None,
            finished_at: None,
            finding_count: 0,
            phase: "Idle".to_string(),
            progress_percent: 0,
            request_count: 0,
            estimated_total_requests: 0,
            eta_seconds: None,
            active_elapsed_seconds: 0.0,
            tested_params_summary: "-".to_string(),
            paused: false,
            last_poll: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResultsState {
    pub(crate) focus: usize,
    pub(crate) search: String,
    pub(crate) severity_index: usize,
    pub(crate) kind_index: usize,
    pub(crate) sort_index: usize,
    pub(crate) secondary_sort_index: usize,
    pub(crate) sort_desc: bool,
    pub(crate) selected_only: bool,
    pub(crate) selected: HashSet<usize>,
}

impl Default for ResultsState {
    fn default() -> Self {
        Self {
            focus: 0,
            search: String::new(),
            severity_index: 0,
            kind_index: 0,
            sort_index: 0,
            secondary_sort_index: 1,
            sort_desc: true,
            selected_only: false,
            selected: HashSet::new(),
        }
    }
}

impl ResultsState {
    const FIELD_COUNT: usize = 7;

    pub(crate) fn focus_next(&mut self) {
        self.focus = (self.focus + 1) % Self::FIELD_COUNT;
    }

    pub(crate) fn focus_prev(&mut self) {
        self.focus = if self.focus == 0 {
            Self::FIELD_COUNT - 1
        } else {
            self.focus - 1
        };
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExtractState {
    pub(crate) action_index: usize,
    pub(crate) database: String,
    pub(crate) table: String,
    pub(crate) columns: String,
    pub(crate) file_path: String,
    pub(crate) command: String,
    pub(crate) output: String,
    pub(crate) databases: Vec<String>,
    pub(crate) tables: Vec<String>,
    pub(crate) available_columns: Vec<String>,
    pub(crate) selected_columns: HashSet<String>,
    pub(crate) selected_database_index: usize,
    pub(crate) selected_table_index: usize,
    pub(crate) selected_column_index: usize,
    pub(crate) last_dump: Option<Value>,
    pub(crate) focus: usize,
}

impl Default for ExtractState {
    fn default() -> Self {
        Self {
            action_index: 0,
            database: String::new(),
            table: String::new(),
            columns: String::new(),
            file_path: "/etc/passwd".to_string(),
            command: "whoami".to_string(),
            output: "Extraction output will appear here.".to_string(),
            databases: Vec::new(),
            tables: Vec::new(),
            available_columns: Vec::new(),
            selected_columns: HashSet::new(),
            selected_database_index: 0,
            selected_table_index: 0,
            selected_column_index: 0,
            last_dump: None,
            focus: 0,
        }
    }
}

impl ExtractState {
    const FIELD_COUNT: usize = 9;

    pub(crate) fn action(&self) -> ExtractAction {
        ExtractAction::all()[self.action_index]
    }

    pub(crate) fn focus_next(&mut self) {
        self.focus = (self.focus + 1) % Self::FIELD_COUNT;
    }

    pub(crate) fn focus_prev(&mut self) {
        self.focus = if self.focus == 0 {
            Self::FIELD_COUNT - 1
        } else {
            self.focus - 1
        };
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyState {
    pub(crate) stats: Value,
    pub(crate) records: Vec<Value>,
    pub(crate) selected_index: usize,
    pub(crate) last_error: String,
}

impl Default for ProxyState {
    fn default() -> Self {
        Self {
            stats: json!({}),
            records: Vec::new(),
            selected_index: 0,
            last_error: String::new(),
        }
    }
}
