use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Layout},
    widgets::{ScrollbarState, TableState},
};

use crate::{helpers::app, maps, programs, uis};

const FOOTER_TEXT: [&str; 1] =
    ["(Esc) quit | (↑) move up | (↓) move down | (←) move left | (→) move right"];
const HEADER_TEXT: [&str; 1] = ["eMAN :: You UI friendly eBPF Manager"];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    Maps,
    Programs,
}

pub struct MainMenu {
    table_state: TableState,
    scroll_state: ScrollbarState,
    state: MenuItem,
    items: Vec<MenuItem>,
}

impl MainMenu {
    pub fn new() -> Self {
        MainMenu {
            state: MenuItem::Maps,
            items: vec![MenuItem::Maps, MenuItem::Programs],
            table_state: TableState::default().with_selected(0),
            scroll_state: ScrollbarState::new(2),
        }
    }

    fn next(&mut self) {
        let idx = self
            .items
            .iter()
            .position(|&x| x == self.state)
            .unwrap_or(0);
        let next_idx = (idx + 1) % self.items.len();
        self.state = self.items[next_idx];
        self.table_state.select(Some(next_idx));
    }

    fn prev(&mut self) {
        let idx = self
            .items
            .iter()
            .position(|&x| x == self.state)
            .unwrap_or(0);
        let prev_idx = if idx == 0 {
            self.items.len() - 1
        } else {
            idx - 1
        };
        self.state = self.items[prev_idx];
        self.table_state.select(Some(prev_idx));
    }

    pub fn run(mut self, mut terminal: DefaultTerminal) -> color_eyre::Result<()> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;

            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                            KeyCode::Char('j') | KeyCode::Down => self.next(),
                            KeyCode::Char('k') | KeyCode::Up => self.prev(),
                            KeyCode::Enter => match self.state {
                                MenuItem::Maps => {
                                    let maps = maps::Maps::new();
                                    maps.run(terminal)?;
                                    return Ok(());
                                }
                                MenuItem::Programs => {
                                    let programs = programs::Programs::new();
                                    programs.run(terminal)?;
                                    return Ok(());
                                }
                            },
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let vertical = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ]);
        let rects = vertical.split(frame.area());

        uis::header::render_header(&HEADER_TEXT, frame, rects[0]);
        let items = vec![
            app::MenuItem {
                name: "1. Maps".to_string(),
                description: "Manage eBPF maps".to_string(),
            },
            app::MenuItem {
                name: "2. Programs".to_string(),
                description: "Manage eBPF programs".to_string(),
            },
        ];
        uis::table::render_table(
            frame,
            rects[1],
            &items,
            &mut self.table_state,
            &["Name", "Description"],
        );
        uis::scrollbar::render_scrollbar(&mut self.scroll_state, frame, rects[1]);

        uis::footer::render_footer(&FOOTER_TEXT, frame, rects[2]);
    }
}
