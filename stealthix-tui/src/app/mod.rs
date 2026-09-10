mod extract;
mod render;
mod render_extract;
mod render_results;
mod render_scan;
mod results;
mod scan;
mod scan_form;

use anyhow::{anyhow, Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::widgets::ListState;
use ratatui::DefaultTerminal;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::models::{BridgeCallback, BridgeResponse, InitPayload, LogEntry, ScanResultData};
use crate::state::{ExtractState, ProxyState, ResultsState, RunningState, ScanForm, Screen};

pub(crate) struct App {
    callback: BridgeCallback,
    init: InitPayload,
    screen: Screen,
    should_quit: bool,
    show_help: bool,
    status_line: String,
    messages: Vec<LogEntry>,
    scan_form: ScanForm,
    running: RunningState,
    result: Option<ScanResultData>,
    results: ResultsState,
    session: Option<Value>,
    findings_state: ListState,
    extract: ExtractState,
    proxy: ProxyState,
}

impl App {
    pub(crate) fn new(callback: BridgeCallback) -> Self {
        let mut findings_state = ListState::default();
        findings_state.select(Some(0));
        Self {
            callback,
            init: InitPayload {
                dbms: vec!["auto".to_string()],
                methods: vec!["GET".to_string(), "POST".to_string()],
                profiles: Vec::new(),
                report_formats: vec![
                    "json".to_string(),
                    "markdown".to_string(),
                    "html".to_string(),
                    "pdf".to_string(),
                ],
                payload_families: vec![
                    "sqli".to_string(),
                    "nosqli".to_string(),
                    "newsql".to_string(),
                ],
                default_payloads: HashMap::new(),
                initial_config: None,
            },
            screen: Screen::Scan,
            should_quit: false,
            show_help: false,
            status_line: "Loading Stealthix runtime…".to_string(),
            messages: Vec::new(),
            scan_form: ScanForm::default(),
            running: RunningState::default(),
            result: None,
            results: ResultsState::default(),
            session: None,
            findings_state,
            extract: ExtractState::default(),
            proxy: ProxyState::default(),
        }
    }

    pub(crate) fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        self.initialize();
        while !self.should_quit {
            self.on_tick();
            terminal.draw(|frame| self.render(frame))?;
            if event::poll(Duration::from_millis(120))? {
                self.handle_event(event::read()?)?;
            }
        }
        Ok(())
    }

    fn initialize(&mut self) {
        match self.invoke("app.init", json!({})) {
            Ok(response) => {
                if let Some(data_json) = response.data_json {
                    if let Ok(payload) = serde_json::from_str::<InitPayload>(&data_json) {
                        self.init = payload;
                    }
                }
                if self.init.dbms.is_empty() {
                    self.init.dbms = vec!["auto".to_string()];
                }
                if self.init.payload_families.is_empty() {
                    self.init.payload_families = vec![
                        "sqli".to_string(),
                        "nosqli".to_string(),
                        "newsql".to_string(),
                    ];
                }
                self.scan_form.custom_payloads = self.init.default_payloads.clone();
                if let Some(initial_config) = self.init.initial_config.clone() {
                    self.apply_config_payload(&initial_config);
                }
                self.sync_payload_editor_from_family();
                self.status_line = response
                    .message
                    .unwrap_or_else(|| "Rust TUI ready.".to_string());
            }
            Err(err) => {
                self.status_line = format!("Initialization warning: {err}");
            }
        }
    }

    fn invoke(&mut self, action: &str, params: Value) -> Result<BridgeResponse> {
        let raw = (self.callback)(action, params).map_err(|err| anyhow!(err))?;
        let response: BridgeResponse =
            serde_json::from_value(raw).context("invalid callback response")?;
        if let Some(logs) = &response.logs {
            for log in logs {
                self.push_log(log.clone());
            }
        }
        if !response.ok {
            let msg = response
                .error
                .clone()
                .or(response.message.clone())
                .unwrap_or_else(|| format!("action failed: {action}"));
            return Err(anyhow!(msg));
        }
        Ok(response)
    }

    fn on_tick(&mut self) {
        if self.screen == Screen::Running
            && self.running.job_id.is_some()
            && self.running.last_poll.elapsed() >= Duration::from_millis(450)
        {
            self.running.last_poll = Instant::now();
            if let Err(err) = self.poll_scan() {
                self.status_line = format!("Polling error: {err}");
            }
        }
    }

    fn handle_event(&mut self, event: Event) -> Result<()> {
        if let Event::Key(key) = event {
            if key.kind != KeyEventKind::Press {
                return Ok(());
            }
            if self.show_help {
                if matches!(key.code, KeyCode::Esc | KeyCode::F(1) | KeyCode::Char('h')) {
                    self.show_help = false;
                }
                return Ok(());
            }
            if self.handle_global_key(key)? {
                return Ok(());
            }
            match self.screen {
                Screen::Scan => self.handle_scan_key(key)?,
                Screen::Running => self.handle_running_key(key)?,
                Screen::Results => self.handle_results_key(key)?,
                Screen::Extract => self.handle_extract_key(key)?,
                Screen::Proxy => self.handle_proxy_key(key)?,
            }
        }
        Ok(())
    }

    fn handle_global_key(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
                return Ok(true);
            }
            KeyCode::F(1) | KeyCode::Char('h') => {
                self.show_help = true;
                return Ok(true);
            }
            KeyCode::Char('s') if key.modifiers.is_empty() => {
                self.screen = Screen::Scan;
                return Ok(true);
            }
            KeyCode::Char('r') if key.modifiers.is_empty() => {
                if self.result.is_some() {
                    self.screen = Screen::Results;
                } else {
                    self.status_line = "No scan results yet.".to_string();
                }
                return Ok(true);
            }
            KeyCode::Char('e') if key.modifiers.is_empty() => {
                if self.session.is_some() {
                    self.screen = Screen::Extract;
                } else {
                    self.status_line = "Run a scan first to unlock extraction.".to_string();
                }
                return Ok(true);
            }
            KeyCode::Char('w') if key.modifiers.is_empty() => {
                self.refresh_proxy_workspace();
                self.screen = Screen::Proxy;
                return Ok(true);
            }
            _ => {}
        }
        Ok(false)
    }

    fn push_log(&mut self, log: LogEntry) {
        self.messages.push(log);
        if self.messages.len() > 200 {
            let overflow = self.messages.len() - 200;
            self.messages.drain(0..overflow);
        }
    }

    fn refresh_proxy_workspace(&mut self) {
        match self.invoke("proxy.search", json!({"limit": 100})) {
            Ok(response) => {
                if let Some(data_json) = response.data_json {
                    if let Ok(payload) = serde_json::from_str::<Value>(&data_json) {
                        self.proxy.stats =
                            payload.get("stats").cloned().unwrap_or_else(|| json!({}));
                        self.proxy.records = payload
                            .get("records")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        if self.proxy.selected_index >= self.proxy.records.len() {
                            self.proxy.selected_index = self.proxy.records.len().saturating_sub(1);
                        }
                        self.proxy.last_error.clear();
                    }
                }
                self.status_line = response
                    .message
                    .unwrap_or_else(|| "Loaded proxy workspace.".to_string());
            }
            Err(err) => {
                self.proxy.last_error = err.to_string();
                self.status_line = format!("Proxy workspace error: {err}");
            }
        }
    }

    fn handle_proxy_key(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down if !self.proxy.records.is_empty() => {
                self.proxy.selected_index =
                    (self.proxy.selected_index + 1).min(self.proxy.records.len() - 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.proxy.selected_index = self.proxy.selected_index.saturating_sub(1);
            }
            KeyCode::Char('R') | KeyCode::Char('l') => self.refresh_proxy_workspace(),
            _ => {}
        }
        Ok(())
    }
}
