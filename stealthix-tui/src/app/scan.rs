use super::App;
use anyhow::{Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

use crate::models::PollPayload;
use crate::util::blank_to_null;

impl App {
    pub(super) fn handle_scan_key(&mut self, key: KeyEvent) -> Result<()> {
        match (key.code, key.modifiers) {
            (KeyCode::Tab, _) | (KeyCode::Down, _) => self.scan_form.focus_next(),
            (KeyCode::BackTab, _) | (KeyCode::Up, _) => self.scan_form.focus_prev(),
            (KeyCode::Left, _) => self.adjust_scan_field(-1),
            (KeyCode::Right, _) => self.adjust_scan_field(1),
            (KeyCode::F(5), _) => self.start_scan()?,
            (KeyCode::Enter, KeyModifiers::CONTROL) => self.start_scan()?,
            (KeyCode::Char('s'), KeyModifiers::CONTROL) => self.save_profile()?,
            (KeyCode::Char('l'), KeyModifiers::CONTROL) => self.load_profile()?,
            (KeyCode::Char('d'), KeyModifiers::CONTROL) => self.discover_params()?,
            (KeyCode::Char('p'), KeyModifiers::CONTROL) => {
                self.load_default_payloads_for_active_family()
            }
            (KeyCode::Char(c), mods) if mods.is_empty() || mods == KeyModifiers::SHIFT => {
                self.push_scan_char(c)
            }
            (KeyCode::Backspace, _) => self.pop_scan_char(),
            (KeyCode::Enter, _) => {
                if self.scan_form.focus == 14 {
                    self.scan_form.verify_tls = !self.scan_form.verify_tls;
                } else if self.scan_form.focus == 15 {
                    self.load_default_payloads_for_active_family();
                } else {
                    self.start_scan()?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn handle_running_key(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('c') => self.cancel_scan()?,
            KeyCode::Char('p') => self.poll_scan()?,
            KeyCode::Char(' ') => self.toggle_pause_resume()?,
            _ => {}
        }
        Ok(())
    }

    fn start_scan(&mut self) -> Result<()> {
        if self.scan_form.url.trim().is_empty() {
            self.status_line = "Target URL is required.".to_string();
            return Ok(());
        }
        self.store_payload_editor_into_family();
        let params = json!({
            "url": self.scan_form.url,
            "method": self.current_method(),
            "dbms": self.current_dbms(),
            "technique": blank_to_null(&self.scan_form.technique),
            "risk": self.current_risk(),
            "level": self.current_level(),
            "body_format": self.current_body_format(),
            "body": blank_to_null(&self.scan_form.body),
            "headers": blank_to_null(&self.scan_form.headers),
            "cookies": blank_to_null(&self.scan_form.cookies),
            "proxy": blank_to_null(&self.scan_form.proxy),
            "target_params": blank_to_null(&self.scan_form.target_params),
            "threads": blank_to_null(&self.scan_form.threads),
            "verify_tls": self.scan_form.verify_tls,
            "custom_payloads": self.active_custom_payloads_value(),
            "metadata": self.scan_form.loaded_metadata,
        });
        let response = self.invoke("scan.start", params)?;
        let job_json = response.job_json.unwrap_or_else(|| "{}".to_string());
        let job = serde_json::from_str::<Value>(&job_json).unwrap_or_else(|_| json!({}));
        let job_id = job
            .get("job_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        self.running.job_id = if job_id.is_empty() {
            None
        } else {
            Some(job_id)
        };
        self.running.status = "running".to_string();
        self.running.message = response
            .message
            .unwrap_or_else(|| "Scan started.".to_string());
        self.running.started_at = None;
        self.running.finished_at = None;
        self.running.finding_count = 0;
        self.running.phase = "Queued".to_string();
        self.running.progress_percent = 0;
        self.running.request_count = 0;
        self.running.estimated_total_requests = 0;
        self.running.eta_seconds = None;
        self.running.active_elapsed_seconds = 0.0;
        self.running.tested_params_summary = "-".to_string();
        self.running.paused = false;
        self.running.last_poll = Instant::now() - Duration::from_secs(1);
        self.screen = crate::state::Screen::Running;
        self.status_line = self.running.message.clone();
        Ok(())
    }

    pub(super) fn poll_scan(&mut self) -> Result<()> {
        let Some(job_id) = self.running.job_id.clone() else {
            return Ok(());
        };
        let response = self.invoke("scan.poll", json!({ "job_id": job_id }))?;
        if let Some(data_json) = response.data_json {
            let payload =
                serde_json::from_str::<PollPayload>(&data_json).context("invalid poll payload")?;
            if !payload.job_id.is_empty() {
                self.running.job_id = Some(payload.job_id.clone());
            }
            self.running.status = payload.status.clone();
            self.running.message = payload
                .message
                .clone()
                .or(response.message.clone())
                .unwrap_or_else(|| "Polling scan…".to_string());
            self.running.started_at = payload.started_at.clone();
            self.running.finished_at = payload.finished_at.clone();
            self.running.finding_count = payload.finding_count.unwrap_or(0);
            self.running.phase = if payload.phase.trim().is_empty() {
                "Running".to_string()
            } else {
                payload.phase.clone()
            };
            self.running.progress_percent = payload.progress_percent.unwrap_or(0);
            self.running.request_count = payload.request_count.unwrap_or(0);
            self.running.estimated_total_requests = payload.estimated_total_requests.unwrap_or(0);
            self.running.eta_seconds = payload.eta_seconds;
            self.running.active_elapsed_seconds = payload.active_elapsed_seconds.unwrap_or(0.0);
            self.running.tested_params_summary = if payload.tested_params_summary.trim().is_empty()
            {
                "-".to_string()
            } else {
                payload.tested_params_summary.clone()
            };
            self.running.paused = payload.paused.unwrap_or(false);
            self.status_line = self.running.message.clone();
            if let Some(session) = payload.session {
                self.session = Some(session);
            }
            if let Some(result) = payload.result {
                self.result = Some(result);
                self.results.selected.clear();
                self.findings_state.select(Some(0));
            }
            match payload.status.as_str() {
                "done" => {
                    self.screen = crate::state::Screen::Results;
                    self.status_line =
                        format!("Scan finished — {} finding(s).", self.running.finding_count);
                }
                "failed" => {
                    self.status_line = payload.error.unwrap_or_else(|| "Scan failed.".to_string());
                }
                "cancelled" => {
                    self.status_line = "Scan cancelled.".to_string();
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn cancel_scan(&mut self) -> Result<()> {
        let Some(job_id) = self.running.job_id.clone() else {
            return Ok(());
        };
        let response = self.invoke("scan.cancel", json!({ "job_id": job_id }))?;
        self.status_line = response
            .message
            .unwrap_or_else(|| "Cancellation requested.".to_string());
        Ok(())
    }

    fn save_profile(&mut self) -> Result<()> {
        if self.scan_form.profile_name.trim().is_empty() {
            self.status_line = "Enter a profile name before saving.".to_string();
            return Ok(());
        }
        self.store_payload_editor_into_family();
        let params = json!({
            "name": self.scan_form.profile_name,
            "url": self.scan_form.url,
            "method": self.current_method(),
            "dbms": self.current_dbms(),
            "technique": blank_to_null(&self.scan_form.technique),
            "risk": self.current_risk(),
            "level": self.current_level(),
            "body_format": self.current_body_format(),
            "body": blank_to_null(&self.scan_form.body),
            "headers": blank_to_null(&self.scan_form.headers),
            "cookies": blank_to_null(&self.scan_form.cookies),
            "proxy": blank_to_null(&self.scan_form.proxy),
            "target_params": blank_to_null(&self.scan_form.target_params),
            "threads": blank_to_null(&self.scan_form.threads),
            "verify_tls": self.scan_form.verify_tls,
            "custom_payloads": self.active_custom_payloads_value(),
            "metadata": self.scan_form.loaded_metadata,
        });
        let response = self.invoke("profile.save", params)?;
        self.status_line = response
            .message
            .unwrap_or_else(|| "Profile saved.".to_string());
        self.refresh_profiles();
        Ok(())
    }

    fn load_profile(&mut self) -> Result<()> {
        if self.scan_form.profile_name.trim().is_empty() {
            self.status_line = "Enter a profile name before loading.".to_string();
            return Ok(());
        }
        let response = self.invoke(
            "profile.load",
            json!({ "name": self.scan_form.profile_name }),
        )?;
        let Some(data_json) = response.data_json else {
            self.status_line = "Profile load returned no data.".to_string();
            return Ok(());
        };
        let payload =
            serde_json::from_str::<Value>(&data_json).context("invalid profile payload")?;
        let config = payload.get("config").cloned().unwrap_or_else(|| json!({}));
        self.apply_config_payload(&config);
        self.scan_form.loaded_metadata = payload
            .get("metadata")
            .cloned()
            .unwrap_or_else(|| json!({}));
        self.status_line = response
            .message
            .unwrap_or_else(|| "Profile loaded.".to_string());
        Ok(())
    }

    fn refresh_profiles(&mut self) {
        if let Ok(response) = self.invoke("profile.list", json!({})) {
            if let Some(data_json) = response.data_json {
                if let Ok(profiles) = serde_json::from_str::<Vec<String>>(&data_json) {
                    self.init.profiles = profiles;
                }
            }
        }
    }

    fn discover_params(&mut self) -> Result<()> {
        if self.scan_form.url.trim().is_empty() {
            self.status_line = "Enter a target URL before discovering params.".to_string();
            return Ok(());
        }
        self.store_payload_editor_into_family();
        let response = self.invoke(
            "scan.discover_params",
            json!({
                "url": self.scan_form.url,
                "method": self.current_method(),
                "dbms": self.current_dbms(),
                "body_format": self.current_body_format(),
                "body": blank_to_null(&self.scan_form.body),
                "headers": blank_to_null(&self.scan_form.headers),
                "cookies": blank_to_null(&self.scan_form.cookies),
                "proxy": blank_to_null(&self.scan_form.proxy),
                "threads": blank_to_null(&self.scan_form.threads),
                "verify_tls": self.scan_form.verify_tls,
                "custom_payloads": self.active_custom_payloads_value(),
            }),
        )?;
        if let Some(data_json) = response.data_json {
            let payload = serde_json::from_str::<Value>(&data_json).unwrap_or_else(|_| json!({}));
            let params = payload
                .get("params")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            self.scan_form.discovered_params = params
                .iter()
                .filter_map(|item| {
                    let name = item.get("name").and_then(Value::as_str)?;
                    let location = item
                        .get("location")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    Some(if location.is_empty() {
                        name.to_string()
                    } else {
                        format!("{name}@{location}")
                    })
                })
                .collect();
            let discovered_names = params
                .iter()
                .filter_map(|item| item.get("name").and_then(Value::as_str))
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            self.scan_form.target_params = discovered_names.join(",");
        }
        self.status_line = response
            .message
            .unwrap_or_else(|| "Parameter discovery complete.".to_string());
        Ok(())
    }

    fn toggle_pause_resume(&mut self) -> Result<()> {
        let Some(job_id) = self.running.job_id.clone() else {
            return Ok(());
        };
        let action = if self.running.paused {
            "scan.resume"
        } else {
            "scan.pause"
        };
        let response = self.invoke(action, json!({ "job_id": job_id }))?;
        self.status_line = response
            .message
            .unwrap_or_else(|| "Updated scan state.".to_string());
        self.running.last_poll = Instant::now() - Duration::from_millis(500);
        Ok(())
    }
}
