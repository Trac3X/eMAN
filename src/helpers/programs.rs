use std::mem;

use libbpf_sys::{
    bpf_prog_get_fd_by_id, bpf_prog_get_info_by_fd, bpf_prog_get_next_id, bpf_prog_info,
};
extern crate libc;

use crate::{uis::table::TableRow, utils};
use ratatui::widgets::Cell;

impl TableRow for bpf_prog_info {
    fn id(&self) -> u32 {
        self.id
    }

    fn cells(&self) -> Vec<Cell<'static>> {
        let name =
            utils::programs::cstring_from_i8_array(self.name).unwrap_or_else(|| "N/A".to_string());
        let tag = self
            .tag
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        let type_ = utils::programs::bpf_prog_type_to_str(self.type_);
        vec![
            Cell::from(format!("{}", self.id)),
            Cell::from(name),
            Cell::from(tag),
            Cell::from(type_),
        ]
    }
}

pub fn fetch_programs() -> Vec<bpf_prog_info> {
    let mut programs: Vec<bpf_prog_info> = Vec::new();
    let mut id: u32 = 0;
    loop {
        let mut next: u32 = 0;
        if unsafe { bpf_prog_get_next_id(id, &mut next) } != 0 {
            break;
        }
        let fd = unsafe { bpf_prog_get_fd_by_id(next) };
        if fd < 0 {
            id = next;
            continue;
        }

        let mut info: bpf_prog_info = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&info) as u32;

        if unsafe { bpf_prog_get_info_by_fd(fd, &mut info, &mut len) } == 0 {
            programs.push(info);
        }
        unsafe { libc::close(fd) };
        id = next;
    }
    programs
}

pub fn fetch_programs_by_id(id: u32) -> bpf_prog_info {
    let fd = unsafe { bpf_prog_get_fd_by_id(id) };

    let mut info: bpf_prog_info = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&info) as u32;

    if unsafe { bpf_prog_get_info_by_fd(fd, &mut info, &mut len) } != 0 {}
    unsafe { libc::close(fd) };
    info
}

pub fn get_map_ids_by_prog(info: &bpf_prog_info) -> Vec<u32> {
    let fd = unsafe { bpf_prog_get_fd_by_id(info.id) };
    if fd < 0 {
        return Vec::new();
    }

    let mut map_ids = vec![0u32; info.nr_map_ids as usize];
    let mut full_info: bpf_prog_info = unsafe { mem::zeroed() };
    full_info.nr_map_ids = info.nr_map_ids;
    full_info.map_ids = map_ids.as_mut_ptr() as u64;

    let mut len = mem::size_of_val(&full_info) as u32;
    if unsafe { bpf_prog_get_info_by_fd(fd, &mut full_info, &mut len) } != 0 {
        unsafe { libc::close(fd) };
        return Vec::new();
    }

    unsafe { libc::close(fd) };
    map_ids.truncate(full_info.nr_map_ids as usize);
    map_ids
}
