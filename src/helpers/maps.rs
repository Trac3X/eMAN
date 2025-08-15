use libbpf_sys::{bpf_map_get_fd_by_id, bpf_map_get_info_by_fd, bpf_map_get_next_id, bpf_map_info};
use ratatui::widgets::Cell;
use std::mem;

use crate::{uis::table::TableRow, utils};

impl TableRow for bpf_map_info {
    fn id(&self) -> u32 {
        self.id
    }

    fn cells(&self) -> Vec<Cell<'static>> {
        let name =
            utils::programs::cstring_from_i8_array(self.name).unwrap_or_else(|| "N/A".to_string());
        let max_entries = self.max_entries;
        let type_ = utils::maps::bpf_map_type_to_str(self.type_);
        vec![
            Cell::from(format!("{}", self.id)),
            Cell::from(name),
            Cell::from(format!("{}", max_entries)),
            Cell::from(type_),
        ]
    }
}

pub fn fetch_maps() -> Vec<bpf_map_info> {
    let mut maprams: Vec<bpf_map_info> = Vec::new();
    let mut id: u32 = 0;
    loop {
        let mut next: u32 = 0;
        if unsafe { bpf_map_get_next_id(id, &mut next) } != 0 {
            break;
        }
        let fd = unsafe { bpf_map_get_fd_by_id(next) };
        if fd < 0 {
            id = next;
            continue;
        }

        let mut info: bpf_map_info = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&info) as u32;

        if unsafe { bpf_map_get_info_by_fd(fd, &mut info, &mut len) } == 0 {
            maprams.push(info);
        }
        unsafe { libc::close(fd) };
        id = next;
    }
    maprams
}

pub fn fetch_map_by_id(id: u32) -> Option<bpf_map_info> {
    let fd = unsafe { bpf_map_get_fd_by_id(id) };
    if fd < 0 {
        return None;
    }

    let mut info: bpf_map_info = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&info) as u32;

    let ret = unsafe { bpf_map_get_info_by_fd(fd, &mut info, &mut len) };
    unsafe { libc::close(fd) };

    if ret == 0 { Some(info) } else { None }
}
