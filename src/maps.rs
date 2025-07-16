use std::time::Duration;

use color_eyre::eyre::Result;
use libbpf_sys::bpf_map_info;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Layout},
    widgets::{ScrollbarState, TableState},
};

use crate::{helpers, uis};

pub struct Maps {
    state: TableState,
    items: Vec<bpf_map_info>,
    scroll_state: ScrollbarState,
}

const ITEM_HEIGHT: usize = 4;
const FOOTER_TEXT: [&str; 1] =
    ["(Esc) quit | (↑) move up | (↓) move down | (←) move left | (→) move right"];
const HEADER_TEXT: [&str; 1] = ["eBPF Maps"];

impl Maps {
    pub fn new() -> Self {
        let bpf_maps_data = helpers::maps::fetch_maps();
        Self {
            scroll_state: ScrollbarState::new((bpf_maps_data.len() - 1) * ITEM_HEIGHT),
            state: TableState::default().with_selected(0),
            items: bpf_maps_data,
        }
    }
    pub fn next_row(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * ITEM_HEIGHT);
    }

    pub fn previous_row(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * ITEM_HEIGHT);
    }
    pub fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        loop {
            self.items = helpers::maps::fetch_maps();
            terminal.draw(|frame| self.draw(frame))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        // let shift_pressed = key.modifiers.contains(KeyModifiers::SHIFT);
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                            KeyCode::Char('j') | KeyCode::Down => self.next_row(),
                            KeyCode::Char('k') | KeyCode::Up => self.previous_row(),
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let vertical = &Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ]);
        let rects = vertical.split(frame.area());

        uis::header::render_header(&HEADER_TEXT, frame, rects[0]);
        uis::table::render_table(
            frame,
            rects[1],
            &self.items,
            &mut self.state,
            &["ID", "Name", "Max-Entires", "Type"],
        );

        uis::scrollbar::render_scrollbar(&mut self.scroll_state, frame, rects[1]);
        uis::footer::render_footer(&FOOTER_TEXT, frame, rects[2]);
    }
}
