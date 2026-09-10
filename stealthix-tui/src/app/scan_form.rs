use super::App;
use serde_json::Value;
use std::cmp::min;
use std::collections::HashMap;

use crate::util::{cycle_index, map_to_blob, payload_to_body_string};

impl App {
    pub(super) fn active_payload_family(&self) -> String {
        self.init
            .payload_families
            .get(self.scan_form.payload_family_index)
            .cloned()
            .unwrap_or_else(|| "sqli".to_string())
    }

    pub(super) fn sync_payload_editor_from_family(&mut self) {
        let family = self.active_payload_family();
        let payloads = self
            .scan_form
            .custom_payloads
            .get(&family)
            .cloned()
            .unwrap_or_default();
        self.scan_form.payload_editor = payloads.join("\n");
    }

    pub(super) fn store_payload_editor_into_family(&mut self) {
        let family = self.active_payload_family();
        let values = self
            .scan_form
            .payload_editor
            .lines()
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if values.is_empty() {
            self.scan_form.custom_payloads.remove(&family);
        } else {
            self.scan_form.custom_payloads.insert(family, values);
        }
    }

    pub(super) fn load_default_payloads_for_active_family(&mut self) {
        let family = self.active_payload_family();
        if let Some(defaults) = self.init.default_payloads.get(&family).cloned() {
            self.scan_form
                .custom_payloads
                .insert(family.clone(), defaults);
            self.sync_payload_editor_from_family();
            self.status_line = format!("Loaded default {family} payloads into the editor.");
        }
    }

    pub(super) fn active_custom_payloads_value(&self) -> Value {
        let mut map = serde_json::Map::new();
        for (family, items) in &self.scan_form.custom_payloads {
            if !items.is_empty() {
                map.insert(
                    family.clone(),
                    Value::Array(items.iter().cloned().map(Value::String).collect()),
                );
            }
        }
        Value::Object(map)
    }

    pub(super) fn adjust_scan_field(&mut self, delta: isize) {
        match self.scan_form.focus {
            1 => cycle_index(
                &mut self.scan_form.method_index,
                self.init.methods.len(),
                delta,
            ),
            2 => cycle_index(&mut self.scan_form.dbms_index, self.init.dbms.len(), delta),
            4 => cycle_index(&mut self.scan_form.risk_index, 3, delta),
            5 => cycle_index(&mut self.scan_form.level_index, 5, delta),
            6 => cycle_index(&mut self.scan_form.body_format_index, 2, delta),
            15 => {
                self.store_payload_editor_into_family();
                cycle_index(
                    &mut self.scan_form.payload_family_index,
                    self.init.payload_families.len(),
                    delta,
                );
                self.sync_payload_editor_from_family();
            }
            14 => self.scan_form.verify_tls = !self.scan_form.verify_tls,
            _ => {}
        }
    }

    pub(super) fn push_scan_char(&mut self, c: char) {
        let is_payload_editor = self.scan_form.focus == 16;
        if let Some(target) = self.scan_text_field_mut() {
            target.push(c);
        }
        if is_payload_editor {
            self.store_payload_editor_into_family();
        }
    }

    pub(super) fn pop_scan_char(&mut self) {
        let is_payload_editor = self.scan_form.focus == 16;
        if let Some(target) = self.scan_text_field_mut() {
            target.pop();
        }
        if is_payload_editor {
            self.store_payload_editor_into_family();
        }
    }

    fn scan_text_field_mut(&mut self) -> Option<&mut String> {
        match self.scan_form.focus {
            0 => Some(&mut self.scan_form.url),
            3 => Some(&mut self.scan_form.technique),
            7 => Some(&mut self.scan_form.body),
            8 => Some(&mut self.scan_form.headers),
            9 => Some(&mut self.scan_form.cookies),
            10 => Some(&mut self.scan_form.proxy),
            11 => Some(&mut self.scan_form.target_params),
            12 => Some(&mut self.scan_form.profile_name),
            13 => Some(&mut self.scan_form.threads),
            16 => Some(&mut self.scan_form.payload_editor),
            _ => None,
        }
    }

    pub(super) fn current_method(&self) -> String {
        self.init
            .methods
            .get(self.scan_form.method_index)
            .cloned()
            .unwrap_or_else(|| "GET".to_string())
    }

    pub(super) fn current_dbms(&self) -> Option<String> {
        let value = self
            .init
            .dbms
            .get(self.scan_form.dbms_index)
            .cloned()
            .unwrap_or_else(|| "auto".to_string());
        if value == "auto" || value.is_empty() {
            None
        } else {
            Some(value)
        }
    }

    pub(super) fn current_risk(&self) -> usize {
        self.scan_form.risk_index + 1
    }

    pub(super) fn current_level(&self) -> usize {
        self.scan_form.level_index + 1
    }

    pub(super) fn current_body_format(&self) -> &'static str {
        if self.scan_form.body_format_index == 1 {
            "json"
        } else {
            "form"
        }
    }

    pub(super) fn apply_config_payload(&mut self, payload: &Value) {
        self.scan_form.url = payload
            .get("base_url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        self.scan_form.technique = payload
            .get("technique")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        self.scan_form.proxy = payload
            .get("proxy")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        self.scan_form.verify_tls = payload
            .get("verify_tls")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        self.scan_form.target_params = payload
            .get("target_params")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        self.scan_form.headers = map_to_blob(payload.get("headers"));
        self.scan_form.cookies = map_to_blob(payload.get("cookies"));
        self.scan_form.body = payload_to_body_string(payload.get("data"));

        let method = payload
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET");
        self.scan_form.method_index = self
            .init
            .methods
            .iter()
            .position(|item| item.eq_ignore_ascii_case(method))
            .unwrap_or(0);

        let dbms = payload
            .get("dbms")
            .and_then(Value::as_str)
            .unwrap_or("auto");
        self.scan_form.dbms_index = self
            .init
            .dbms
            .iter()
            .position(|item| item.eq_ignore_ascii_case(dbms))
            .unwrap_or(0);

        let risk = payload.get("risk").and_then(Value::as_u64).unwrap_or(1);
        self.scan_form.risk_index = min(risk.saturating_sub(1) as usize, 2);
        let level = payload.get("level").and_then(Value::as_u64).unwrap_or(1);
        self.scan_form.level_index = min(level.saturating_sub(1) as usize, 4);
        self.scan_form.threads = payload
            .get("threads")
            .and_then(|value| match value {
                Value::Number(number) => Some(number.to_string()),
                Value::String(text) => Some(text.clone()),
                _ => None,
            })
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "5".to_string());
        let body_format = payload
            .get("body_format")
            .and_then(Value::as_str)
            .unwrap_or("form");
        self.scan_form.body_format_index = if body_format.eq_ignore_ascii_case("json") {
            1
        } else {
            0
        };
        self.scan_form.custom_payloads = payload
            .get("custom_payloads")
            .and_then(Value::as_object)
            .map(|items| {
                items
                    .iter()
                    .map(|(family, values)| {
                        let payloads = values
                            .as_array()
                            .map(|entries| {
                                entries
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(ToString::to_string)
                                    .collect()
                            })
                            .unwrap_or_else(Vec::new);
                        (family.clone(), payloads)
                    })
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_else(|| self.init.default_payloads.clone());
        self.sync_payload_editor_from_family();
    }
}
