use super::App;
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::json;
use std::cmp::Ordering;
use std::collections::BTreeSet;

use crate::models::ScanResultData;
use crate::state::ResultsState;
use crate::util::cycle_index;

impl App {
    fn finding_sort_value<'a>(
        finding: &'a crate::models::FindingData,
        index: usize,
    ) -> SortValue<'a> {
        match index {
            1 => SortValue::Text(&finding.severity),
            2 => SortValue::Text(&finding.kind),
            3 => SortValue::Text(&finding.target),
            _ => SortValue::Float(finding.cvss),
        }
    }

    fn secondary_sort_value<'a>(
        finding: &'a crate::models::FindingData,
        index: usize,
    ) -> Option<SortValue<'a>> {
        match index {
            1 => Some(SortValue::Text(&finding.kind)),
            2 => Some(SortValue::Text(&finding.target)),
            3 => Some(SortValue::Text(&finding.severity)),
            _ => None,
        }
    }

    pub(super) fn handle_results_key(&mut self, key: KeyEvent) -> Result<()> {
        match (key.code, key.modifiers) {
            (KeyCode::Tab, _) => self.results.focus_next(),
            (KeyCode::BackTab, _) => self.results.focus_prev(),
            (KeyCode::Left, _) => self.adjust_results_filter(-1),
            (KeyCode::Right, _) => self.adjust_results_filter(1),
            (KeyCode::Down | KeyCode::Char('j'), _) => self.next_finding(),
            (KeyCode::Up | KeyCode::Char('k'), _) => self.previous_finding(),
            (KeyCode::Char(' '), _) => self.toggle_selected_finding(),
            (KeyCode::Char('x'), _) => self.clear_selected_findings(),
            (KeyCode::Char('o'), _) => self.results.selected_only = !self.results.selected_only,
            (KeyCode::Char('z'), _) => self.reset_result_filters(),
            (KeyCode::Char('1'), _) => self.export_report("json")?,
            (KeyCode::Char('2'), _) => self.export_report("markdown")?,
            (KeyCode::Char('3'), _) => self.export_report("html")?,
            (KeyCode::Char('4'), _) => self.export_report("pdf")?,
            (KeyCode::Char('5'), _) => self.export_report("csv")?,
            (KeyCode::Char('/'), _) if self.results.focus != 0 => {
                self.results.focus = 0;
            }
            (KeyCode::Char('y'), _) if self.results.focus != 0 => {
                let visible = self.filtered_finding_indices();
                if let Some(selected) = self
                    .findings_state
                    .selected()
                    .and_then(|idx| visible.get(idx).copied())
                {
                    if let Some(finding) =
                        self.result.as_ref().and_then(|r| r.findings.get(selected))
                    {
                        let payload_str = finding
                            .details
                            .get("payload")
                            .and_then(|p| p.as_str())
                            .or(finding.parameter.as_deref())
                            .unwrap_or("-");
                        self.status_line = format!(
                            "Yanked finding: [{}] {} target={} payload={}",
                            finding.severity, finding.kind, finding.target, payload_str
                        );
                    }
                }
            }
            (KeyCode::Esc, _) if self.results.focus == 0 => {
                self.results.focus = 1;
            }
            (KeyCode::Char(c), mods)
                if (mods.is_empty() || mods == KeyModifiers::SHIFT) && self.results.focus == 0 =>
            {
                self.results.search.push(c);
                let visible_len = self.filtered_finding_indices().len();
                self.findings_state
                    .select(if visible_len == 0 { None } else { Some(0) });
            }
            (KeyCode::Backspace, _) if self.results.focus == 0 => {
                self.results.search.pop();
                let visible_len = self.filtered_finding_indices().len();
                self.findings_state
                    .select(if visible_len == 0 { None } else { Some(0) });
            }
            _ => {}
        }
        Ok(())
    }

    fn export_report(&mut self, format_name: &str) -> Result<()> {
        let Some(result) = self.result_for_export() else {
            self.status_line = "No scan result available to export.".to_string();
            return Ok(());
        };
        let response = self.invoke(
            "report.export",
            json!({ "format": format_name, "result": result }),
        )?;
        self.status_line = response
            .message
            .unwrap_or_else(|| format!("Exported {format_name} report."));
        Ok(())
    }

    fn next_finding(&mut self) {
        let visible = self.filtered_finding_indices();
        let len = visible.len();
        if len == 0 {
            self.findings_state.select(None);
            return;
        }
        let next = self
            .findings_state
            .selected()
            .map(|idx| (idx + 1) % len)
            .unwrap_or(0);
        self.findings_state.select(Some(next));
    }

    fn previous_finding(&mut self) {
        let visible = self.filtered_finding_indices();
        let len = visible.len();
        if len == 0 {
            self.findings_state.select(None);
            return;
        }
        let prev = self
            .findings_state
            .selected()
            .map(|idx| if idx == 0 { len - 1 } else { idx - 1 })
            .unwrap_or(0);
        self.findings_state.select(Some(prev));
    }

    pub(super) fn severity_options() -> &'static [&'static str] {
        &["All", "Critical", "High", "Medium", "Low", "Info"]
    }

    pub(super) fn result_kind_options(&self) -> Vec<String> {
        let mut kinds = BTreeSet::new();
        if let Some(result) = &self.result {
            for finding in &result.findings {
                if !finding.kind.trim().is_empty() {
                    kinds.insert(finding.kind.clone());
                }
            }
        }
        let mut values = vec!["All".to_string()];
        values.extend(kinds);
        values
    }

    pub(super) fn filtered_finding_indices(&self) -> Vec<usize> {
        let Some(result) = &self.result else {
            return Vec::new();
        };
        let search = self.results.search.trim().to_ascii_lowercase();
        let severity_filter = Self::severity_options()
            .get(self.results.severity_index)
            .copied()
            .unwrap_or("All");
        let kind_options = self.result_kind_options();
        let kind_filter = kind_options
            .get(self.results.kind_index)
            .map(String::as_str)
            .unwrap_or("All");
        let mut indices = result
            .findings
            .iter()
            .enumerate()
            .filter(|(idx, finding)| {
                if self.results.selected_only && !self.results.selected.contains(idx) {
                    return false;
                }
                if severity_filter != "All"
                    && !finding.severity.eq_ignore_ascii_case(severity_filter)
                {
                    return false;
                }
                if kind_filter != "All" && finding.kind != kind_filter {
                    return false;
                }
                if search.is_empty() {
                    return true;
                }
                let haystack = format!(
                    "{} {} {} {} {}",
                    finding.kind,
                    finding.target,
                    finding.parameter.as_deref().unwrap_or_default(),
                    finding.location.as_deref().unwrap_or_default(),
                    serde_json::to_string(&finding.details).unwrap_or_default()
                )
                .to_ascii_lowercase();
                haystack.contains(&search)
            })
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        indices.sort_by(|a, b| {
            let left = &result.findings[*a];
            let right = &result.findings[*b];
            let mut ordering = Self::finding_sort_value(left, self.results.sort_index)
                .cmp(&Self::finding_sort_value(right, self.results.sort_index));
            if ordering == Ordering::Equal {
                if let (Some(left_secondary), Some(right_secondary)) = (
                    Self::secondary_sort_value(left, self.results.secondary_sort_index),
                    Self::secondary_sort_value(right, self.results.secondary_sort_index),
                ) {
                    ordering = left_secondary.cmp(&right_secondary);
                }
            }
            if self.results.sort_desc {
                ordering.reverse()
            } else {
                ordering
            }
        });
        indices
    }

    pub(super) fn current_result_index(&self) -> Option<usize> {
        let visible = self.filtered_finding_indices();
        let selected = self.findings_state.selected().unwrap_or(0);
        visible.get(selected).copied()
    }

    fn toggle_selected_finding(&mut self) {
        if let Some(index) = self.current_result_index() {
            if !self.results.selected.insert(index) {
                self.results.selected.remove(&index);
            }
        }
    }

    fn clear_selected_findings(&mut self) {
        self.results.selected.clear();
    }

    fn reset_result_filters(&mut self) {
        self.results = ResultsState::default();
        self.findings_state.select(Some(0));
    }

    fn adjust_results_filter(&mut self, delta: isize) {
        let kind_len = self.result_kind_options().len();
        match self.results.focus {
            1 => cycle_index(
                &mut self.results.severity_index,
                Self::severity_options().len(),
                delta,
            ),
            2 => cycle_index(&mut self.results.kind_index, kind_len, delta),
            3 => cycle_index(&mut self.results.sort_index, 4, delta),
            4 => cycle_index(&mut self.results.secondary_sort_index, 4, delta),
            5 => self.results.sort_desc = !self.results.sort_desc,
            6 => self.results.selected_only = !self.results.selected_only,
            _ => {}
        }
        let visible_len = self.filtered_finding_indices().len();
        if visible_len == 0 {
            self.findings_state.select(None);
        } else {
            let selected = self
                .findings_state
                .selected()
                .unwrap_or(0)
                .min(visible_len - 1);
            self.findings_state.select(Some(selected));
        }
    }

    fn result_for_export(&self) -> Option<ScanResultData> {
        let result = self.result.clone()?;
        if !self.results.selected_only {
            return Some(result);
        }
        let indices = self.filtered_finding_indices();
        if indices.is_empty() {
            return None;
        }
        Some(ScanResultData {
            target: result.target,
            metadata: result.metadata,
            findings: indices
                .into_iter()
                .filter_map(|idx| result.findings.get(idx).cloned())
                .collect(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum SortValue<'a> {
    Text(&'a str),
    Float(f64),
}

impl<'a> SortValue<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (SortValue::Text(left), SortValue::Text(right)) => left.cmp(right),
            (SortValue::Float(left), SortValue::Float(right)) => {
                left.partial_cmp(right).unwrap_or(Ordering::Equal)
            }
            (SortValue::Text(_), SortValue::Float(_)) => Ordering::Less,
            (SortValue::Float(_), SortValue::Text(_)) => Ordering::Greater,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::App;
    use crate::models::ScanResultData;
    use serde_json::json;

    fn app_with_findings(findings: serde_json::Value) -> App {
        let mut app = App::new(Box::new(|_, _| Ok(json!({}))));
        app.result = Some(
            serde_json::from_value::<ScanResultData>(json!({
                "target": "http://example.com",
                "metadata": {},
                "findings": findings,
            }))
            .expect("valid scan result payload"),
        );
        app
    }

    #[test]
    fn secondary_sort_breaks_ties_for_primary_sort() {
        let mut app = app_with_findings(json!([
            {"kind": "sqli", "target": "/b", "severity": "High", "cvss": 7.5, "details": {}},
            {"kind": "sqli", "target": "/a", "severity": "High", "cvss": 7.5, "details": {}},
            {"kind": "sqli", "target": "/c", "severity": "Medium", "cvss": 4.0, "details": {}},
        ]));
        app.results.sort_index = 1;
        app.results.secondary_sort_index = 2;
        app.results.sort_desc = false;

        let indices = app.filtered_finding_indices();
        let targets = indices
            .into_iter()
            .map(|idx| app.result.as_ref().unwrap().findings[idx].target.clone())
            .collect::<Vec<_>>();

        assert_eq!(targets, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn none_secondary_sort_preserves_primary_order_only() {
        let mut app = app_with_findings(json!([
            {"kind": "nosqli", "target": "/b", "severity": "High", "cvss": 7.5, "details": {}},
            {"kind": "sqli", "target": "/a", "severity": "High", "cvss": 7.5, "details": {}},
        ]));
        app.results.sort_index = 1;
        app.results.secondary_sort_index = 0;
        app.results.sort_desc = false;

        let indices = app.filtered_finding_indices();
        assert_eq!(indices, vec![0, 1]);
    }
}
