mod app;
mod maps;
mod programs;
use color_eyre::Result;

use ratatui;
mod helpers;
mod uis;
mod utils;

fn main() -> Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init();
    let app_result = app::MainMenu::new().run(terminal);
    ratatui::restore();
    app_result
}
