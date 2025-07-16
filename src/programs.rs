use std::time::Duration;

use crate::{
    helpers::{self, programs},
    uis, utils,
};
use color_eyre::Result;
use libbpf_sys::bpf_prog_info;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Direction, Layout},
    widgets::{ScrollbarState, TableState},
};

const ITEM_HEIGHT: usize = 4;
const FOOTER_TEXT: [&str; 1] =
    ["(Esc) quit | (↑) move up | (↓) move down | (←) move left | (→) move right"];
const HEADER_TEXT: [&str; 1] = ["eBPF Programs"];

pub struct Programs {
    state: TableState,
    items: Vec<bpf_prog_info>,
    scroll_state: ScrollbarState,
    screen: Screen,
}

enum Screen {
    ProgramsList,
    ProgramInfo(ProgramInfo),
}

struct ProgramInfo {
    prog_id: u32,
    item: bpf_prog_info,
}

impl Programs {
    pub fn new() -> Self {
        let bpf_programs_data = programs::fetch_programs();
        Self {
            state: TableState::default().with_selected(0),
            scroll_state: ScrollbarState::new((bpf_programs_data.len() - 1) * ITEM_HEIGHT),
            items: bpf_programs_data,
            screen: Screen::ProgramsList,
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
            self.items = helpers::programs::fetch_programs();
            terminal.draw(|frame| self.draw(frame))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match self.screen {
                            Screen::ProgramsList => match key.code {
                                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                                KeyCode::Char('j') | KeyCode::Down => self.next_row(),
                                KeyCode::Char('k') | KeyCode::Up => self.previous_row(),
                                KeyCode::Enter => {
                                    if let Some(i) = self.state.selected() {
                                        let prog_id = self.items[i].id;
                                        let info = helpers::programs::fetch_programs_by_id(prog_id);
                                        self.screen = Screen::ProgramInfo(ProgramInfo {
                                            prog_id,
                                            item: info,
                                        });
                                    }
                                }
                                _ => {}
                            },
                            Screen::ProgramInfo(_) => match key.code {
                                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('b') => {
                                    self.screen = Screen::ProgramsList;
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
        let vertical = &Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ]);
        let rects = vertical.split(frame.area());

        match self.screen {
            Screen::ProgramsList => {
                uis::footer::render_footer(&HEADER_TEXT, frame, rects[0]);
                uis::table::render_table(
                    frame,
                    rects[1],
                    &self.items,
                    &mut self.state,
                    &["ID", "Name", "Tag", "Type"],
                );
                uis::scrollbar::render_scrollbar(&mut self.scroll_state, frame, rects[1]);
                uis::footer::render_footer(&FOOTER_TEXT, frame, rects[2]);
            }
            Screen::ProgramInfo(ref info) => {
                let prog: bpf_prog_info = format_info(info.item);

                // let columns = Layout::default()
                //     .direction(Direction::Horizontal)
                //     .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                //     .split(rects[1]);

                // Create key-value pairs for all relevant fields
                // let fields = vec![
                //     ("ID", prog.id.to_string()),
                //     (
                //         "Type",
                //         format!(
                //             "{} ({})",
                //             prog.type_,
                //             utils::programs::bpf_prog_type_to_str(prog.type_)
                //         ),
                //     ),
                //     (
                //         "Name",
                //         utils::programs::cstring_from_i8_array(prog.name)
                //             .unwrap_or_else(|| "N/A".into()),
                //     ),
                //     ("Tag", format_tag(prog.tag)),
                //     ("JITed Len", format!("{}B", prog.jited_prog_len)),
                //     ("Xlated Len", format!("{}B", prog.xlated_prog_len)),
                //     ("JITed Prog", format!("{:#x}", prog.jited_prog_insns)),
                //     ("Xlated Prog", format!("{:#x}", prog.xlated_prog_insns)),
                //     ("Load Time", format_ns(prog.load_time)),
                //     (
                //         "Loaded At",
                //         chrono::NaiveDateTime::from_timestamp_opt(
                //             (prog.load_time / 1_000_000_000) as i64,
                //             0,
                //         )
                //         .map(|dt| {
                //             chrono::DateTime::<chrono::Local>::from_utc(
                //                 dt,
                //                 *chrono::Local::now().offset(),
                //             )
                //         })
                //         .map(|dt| dt.to_rfc3339())
                //         .unwrap_or_else(|| "N/A".into()),
                //     ),
                //     ("Created By UID", prog.created_by_uid.to_string()),
                //     ("Nr Map IDs", prog.nr_map_ids.to_string()),
                //     ("Map IDs", format!("{:#x}", prog.map_ids)),
                //     ("IfIndex", prog.ifindex.to_string()),
                //     ("Netns Dev", format!("{:#x}", prog.netns_dev)),
                //     ("Netns Ino", prog.netns_ino.to_string()),
                //     ("Nr JITed Ksyms", prog.nr_jited_ksyms.to_string()),
                //     ("Nr JITed Func Lens", prog.nr_jited_func_lens.to_string()),
                //     ("JITed Ksyms", format!("{:#x}", prog.jited_ksyms)),
                //     ("JITed Func Lens", format!("{:#x}", prog.jited_func_lens)),
                //     ("BTF ID", prog.btf_id.to_string()),
                //     ("Func Info Rec Size", prog.func_info_rec_size.to_string()),
                //     ("Func Info", format!("{:#x}", prog.func_info)),
                //     ("Nr Func Info", prog.nr_func_info.to_string()),
                //     ("Nr Line Info", prog.nr_line_info.to_string()),
                //     ("Line Info", format!("{:#x}", prog.line_info)),
                //     ("JITed Line Info", format!("{:#x}", prog.jited_line_info)),
                //     ("Nr JITed Line Info", prog.nr_jited_line_info.to_string()),
                //     ("Line Info Rec Size", prog.line_info_rec_size.to_string()),
                //     (
                //         "JITed Line Info Rec Size",
                //         prog.jited_line_info_rec_size.to_string(),
                //     ),
                //     ("Nr Prog Tags", prog.nr_prog_tags.to_string()),
                //     ("Prog Tags", format!("{:#x}", prog.prog_tags)),
                //     ("Run Time (ns)", prog.run_time_ns.to_string()),
                //     ("Run Count", prog.run_cnt.to_string()),
                //     ("Recursion Misses", prog.recursion_misses.to_string()),
                //     ("Verified Insns", prog.verified_insns.to_string()),
                //     ("Attach BTF Obj ID", prog.attach_btf_obj_id.to_string()),
                //     ("Attach BTF ID", prog.attach_btf_id.to_string()),
                // ];

                let blocks: &[(&str, &[(&str, String)])] = &[
                    (
                        "Identity",
                        &[
                            ("ID", prog.id.to_string()),
                            (
                                "Type",
                                format!(
                                    "{} ({})",
                                    prog.type_,
                                    utils::programs::bpf_prog_type_to_str(prog.type_)
                                ),
                            ),
                            (
                                "Name",
                                utils::programs::cstring_from_i8_array(prog.name)
                                    .unwrap_or_else(|| "N/A".into()),
                            ),
                            ("Tag", format_tag(prog.tag)),
                        ],
                    ),
                    (
                        "Program Lengths",
                        &[
                            ("Xlated Len", format!("{}B", prog.xlated_prog_len)),
                            ("JITed Len", format!("{}B", prog.jited_prog_len)),
                            ("Xlated Prog", format!("{:#x}", prog.xlated_prog_insns)),
                            ("JITed Prog", format!("{:#x}", prog.jited_prog_insns)),
                        ],
                    ),
                    (
                        "Load & Creator",
                        &[
                            ("Load Time", format_ns(prog.load_time)),
                            ("Loaded At", {
                                let secs = (prog.load_time / 1_000_000_000) as i64;
                                let nsecs = (prog.load_time % 1_000_000_000) as u32;

                                chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nsecs)
                                    .map(|dt| dt.with_timezone(&chrono::Local).to_rfc3339())
                                    .unwrap_or_else(|| "Invalid timestamp".into())
                            }),
                            ("Created By UID", prog.created_by_uid.to_string()),
                        ],
                    ),
                    (
                        "Maps & Namespaces",
                        &[
                            ("Nr Map IDs", prog.nr_map_ids.to_string()),
                            (
                                "Map IDs",
                                format!("{:?}", helpers::programs::get_map_ids_by_prog(&prog)),
                            ),
                            ("IfIndex", prog.ifindex.to_string()),
                            ("Netns Dev", format!("{:#x}", prog.netns_dev)),
                            ("Netns Ino", prog.netns_ino.to_string()),
                        ],
                    ),
                    (
                        "JIT Symbols",
                        &[
                            ("Nr JITed Ksyms", prog.nr_jited_ksyms.to_string()),
                            ("JITed Ksyms", format!("{:#x}", prog.jited_ksyms)),
                            ("Nr JITed Func Lens", prog.nr_jited_func_lens.to_string()),
                            ("JITed Func Lens", format!("{:#x}", prog.jited_func_lens)),
                        ],
                    ),
                    (
                        "BTF & Func Info",
                        &[
                            ("BTF ID", prog.btf_id.to_string()),
                            ("Func Info Rec Size", prog.func_info_rec_size.to_string()),
                            ("Nr Func Info", prog.nr_func_info.to_string()),
                            ("Func Info", format!("{:#x}", prog.func_info)),
                        ],
                    ),
                    (
                        "Line Info",
                        &[
                            ("Nr Line Info", prog.nr_line_info.to_string()),
                            ("Line Info Rec Size", prog.line_info_rec_size.to_string()),
                            ("Line Info", format!("{:#x}", prog.line_info)),
                            ("Nr JITed Line Info", prog.nr_jited_line_info.to_string()),
                            (
                                "JITed Line Info Rec Size",
                                prog.jited_line_info_rec_size.to_string(),
                            ),
                            ("JITed Line Info", format!("{:#x}", prog.jited_line_info)),
                        ],
                    ),
                    (
                        "Tags & Stats",
                        &[
                            ("Nr Prog Tags", prog.nr_prog_tags.to_string()),
                            ("Prog Tags", format!("{:#x}", prog.prog_tags)),
                            ("Run Time (ns)", prog.run_time_ns.to_string()),
                            ("Run Count", prog.run_cnt.to_string()),
                            ("Recursion Misses", prog.recursion_misses.to_string()),
                            ("Verified Insns", prog.verified_insns.to_string()),
                            ("Attach BTF Obj ID", prog.attach_btf_obj_id.to_string()),
                            ("Attach BTF ID", prog.attach_btf_id.to_string()),
                        ],
                    ),
                ];

                let mid = (blocks.len() + 1) / 2;
                let (left_blocks, right_blocks) = blocks.split_at(mid);

                let cols = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(rects[1]);

                let left_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(1)
                    .constraints(
                        left_blocks
                            .iter()
                            .map(|_| Constraint::Length(7))
                            .collect::<Vec<_>>(),
                    )
                    .split(cols[0]);

                for (i, (title, fields)) in left_blocks.iter().enumerate() {
                    frame.render_widget(uis::block::render_kv_block(title, fields), left_chunks[i]);
                }

                let right_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(1)
                    .constraints(
                        right_blocks
                            .iter()
                            .map(|_| Constraint::Length(7))
                            .collect::<Vec<_>>(),
                    )
                    .split(cols[1]);

                for (i, (title, fields)) in right_blocks.iter().enumerate() {
                    frame
                        .render_widget(uis::block::render_kv_block(title, fields), right_chunks[i]);
                }

                uis::footer::render_footer(
                    &["(Esc/q/b) back | (↑/↓) n/a | (←/→) n/a"],
                    frame,
                    rects[2],
                );
            }
        }
    }
}

fn format_info(info: bpf_prog_info) -> bpf_prog_info {
    info
}

fn format_tag(tag: [u8; 8]) -> String {
    tag.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn format_ns(ns: u64) -> String {
    if ns > 1_000_000_000 {
        format!("{:.2}s", ns as f64 / 1e9)
    } else if ns > 1_000_000 {
        format!("{:.2}ms", ns as f64 / 1e6)
    } else if ns > 1_000 {
        format!("{:.2}μs", ns as f64 / 1e3)
    } else {
        format!("{ns}ns")
    }
}
