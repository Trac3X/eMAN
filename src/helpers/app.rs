use crate::uis::table::TableRow;
use ratatui::widgets::Cell;

pub struct MenuItem {
    pub name: String,
    pub description: String,
}

impl TableRow for MenuItem {
    fn id(&self) -> u32 {
        0
    }
    fn cells(&self) -> Vec<Cell<'static>> {
        vec![
            Cell::from(self.name.clone()),
            Cell::from(self.description.clone()),
        ]
    }
}
