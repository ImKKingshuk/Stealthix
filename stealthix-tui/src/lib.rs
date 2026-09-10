mod app;
mod models;
mod state;
mod util;

use anyhow::Result;
use app::App;
use serde_json::Value;

pub fn run_tui<F>(callback: F) -> Result<()>
where
    F: FnMut(&str, Value) -> std::result::Result<Value, String> + 'static,
{
    let mut terminal = ratatui::init();
    let mut app = App::new(Box::new(callback));
    let result = app.run(&mut terminal);
    ratatui::restore();
    result
}
