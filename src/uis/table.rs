// src/uis/table.rs

use ratatui::{
    Frame,
    layout::Rect,
    prelude::Constraint,
    style::{Modifier, Style, Stylize},
    widgets::{Cell, Row, Table, TableState},
};

pub trait TableRow {
    fn id(&self) -> u32;
    fn cells(&self) -> Vec<Cell<'static>>; // or Vec<Cell<'a>> with lifetime
}

pub fn render_table<T: TableRow>(
    frame: &mut Frame,
    area: Rect,
    items: &[T],
    state: &mut TableState,
    headers: &[&str],
) {
    let header = headers.iter().map(|h| Cell::from(*h)).collect::<Row>();

    let rows = items
        .iter()
        .map(|item| Row::new(item.cells()))
        .collect::<Vec<_>>();

    let widths: Vec<Constraint> = headers.iter().map(|_| Constraint::Min(10)).collect();

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(" >> ")
        .bold();

    frame.render_stateful_widget(table, area, state);
}
