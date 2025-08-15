use std::time::Duration;

use crate::{
    helpers, uis,
    utils::{self},
};
use color_eyre::Result;
use libbpf_sys::bpf_map_info;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Layout, Rect},
    widgets::{ScrollbarState, TableState},
};

// Constants
const ITEM_HEIGHT: usize = 4;
const HEADER_TEXT: [&str; 1] = ["eBPF Maps"];
const FOOTER_TEXT: [&str; 1] =
    ["(Esc) quit | (↑) move up | (↓) move down | (←) move left | (→) move right"];

/// Main UI struct for managing the Maps view
pub struct Maps {
    state: TableState,
    items: Vec<bpf_map_info>,
    scroll_state: ScrollbarState,
    screen: Screen,
}

/// Different screens in the Maps UI
enum Screen {
    MapsList,
    MapInfo(MapInfo),
}

/// Detailed view state for a single map
struct MapInfo {
    map_id: u32,
    item: bpf_map_info,
}

impl Maps {
    pub fn new() -> Self {
        let items = helpers::maps::fetch_maps();
        let scroll_state = ScrollbarState::new((items.len().saturating_sub(1)) * ITEM_HEIGHT);
        Self {
            state: TableState::default().with_selected(0),
            items,
            scroll_state,
            screen: Screen::MapsList,
        }
    }

    pub fn next_row(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len().saturating_sub(1) {
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
                    self.items.len().saturating_sub(1)
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
            // Refresh map list on each loop
            self.items = helpers::maps::fetch_maps();

            terminal.draw(|frame| self.draw(frame))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match &self.screen {
                            Screen::MapsList => match key.code {
                                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                                KeyCode::Char('j') | KeyCode::Down => self.next_row(),
                                KeyCode::Char('k') | KeyCode::Up => self.previous_row(),
                                KeyCode::Enter => {
                                    if let Some(i) = self.state.selected() {
                                        let map_id = self.items[i].id;
                                        if let Some(info) = helpers::maps::fetch_map_by_id(map_id) {
                                            self.screen =
                                                Screen::MapInfo(MapInfo { map_id, item: info });
                                        }
                                    }
                                }
                                _ => {}
                            },
                            Screen::MapInfo(_) => match key.code {
                                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('b') => {
                                    self.screen = Screen::MapsList;
                                }
                                _ => {}
                            },
                        }
                    }
                }
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let layout = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());
        let layout_arr: [Rect; 3] = layout.as_ref().try_into().unwrap();
        match &self.screen {
            Screen::MapsList => {
                uis::header::render_header(&HEADER_TEXT, frame, layout[0]);
                uis::table::render_table(
                    frame,
                    layout[1],
                    &self.items,
                    &mut self.state,
                    &["ID", "Name", "Max Entries", "Type"],
                );
                uis::scrollbar::render_scrollbar(&mut self.scroll_state, frame, layout[1]);
                uis::footer::render_footer(&FOOTER_TEXT, frame, layout[2]);
            }
            Screen::MapInfo(info) => {
                self.draw_map_detail(frame, info, layout_arr);
            }
        }
    }

    fn draw_map_detail(
        &self,
        frame: &mut Frame,
        info: &MapInfo,
        rects: [ratatui::layout::Rect; 3],
    ) {
        let map = &info.item;

        // Format name safely
        let name =
            utils::programs::cstring_from_i8_array(map.name).unwrap_or_else(|| "N/A".to_string());

        let map_type = utils::maps::bpf_map_type_to_str(map.type_);

        // Grouped key-value blocks
        let blocks: &[(&str, &[(&str, String)])] = &[
            (
                "Identity",
                &[
                    ("ID", map.id.to_string()),
                    ("Name", name),
                    ("Type", format!("{} ({})", map.type_, map_type)),
                    ("Flags", format!("{:#x}", map.map_flags)),
                ],
            ),
            (
                "Sizes",
                &[
                    ("Key Size", format!("{} bytes", map.key_size)),
                    ("Value Size", format!("{} bytes", map.value_size)),
                    ("Max Entries", map.max_entries.to_string()),
                    ("Map Extra", format!("{:#x}", map.map_extra)),
                ],
            ),
            (
                "BTF Info",
                &[
                    ("BTF ID", map.btf_id.to_string()),
                    ("BTF Key Type ID", map.btf_key_type_id.to_string()),
                    ("BTF Value Type ID", map.btf_value_type_id.to_string()),
                    (
                        "BTF VMLinux Value Type ID",
                        if map.btf_vmlinux_value_type_id > 0 {
                            map.btf_vmlinux_value_type_id.to_string()
                        } else {
                            "N/A".into()
                        },
                    ),
                    (
                        "BTF VMLinux ID",
                        if map.btf_vmlinux_id > 0 {
                            map.btf_vmlinux_id.to_string()
                        } else {
                            "N/A".into()
                        },
                    ),
                ],
            ),
            (
                "Namespace & Device",
                &[
                    ("IfIndex", map.ifindex.to_string()),
                    ("Netns Dev", format!("{:#x}", map.netns_dev)),
                    ("Netns Ino", format!("{:#x}", map.netns_ino)),
                ],
            ),
        ];

        // Split into two columns
        let mid = (blocks.len() + 1) / 2;
        let (left_blocks, right_blocks) = blocks.split_at(mid);

        let cols = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rects[1]);

        let left_chunks = Layout::vertical(
            left_blocks
                .iter()
                .map(|_| Constraint::Length(7))
                .collect::<Vec<_>>(),
        )
        .margin(1)
        .split(cols[0]);

        for (i, (title, fields)) in left_blocks.iter().enumerate() {
            frame.render_widget(uis::block::render_kv_block(title, fields), left_chunks[i]);
        }

        let right_chunks = Layout::vertical(
            right_blocks
                .iter()
                .map(|_| Constraint::Length(7))
                .collect::<Vec<_>>(),
        )
        .margin(1)
        .split(cols[1]);

        for (i, (title, fields)) in right_blocks.iter().enumerate() {
            frame.render_widget(uis::block::render_kv_block(title, fields), right_chunks[i]);
        }

        uis::footer::render_footer(&["(Esc/q/b) back | (↑/↓) n/a | (←/→) n/a"], frame, rects[2]);
    }
}
