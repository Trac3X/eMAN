pub fn bpf_prog_type_to_str(t: u32) -> &'static str {
    match t {
        0 => "UNSPEC",
        1 => "SOCKET_FILTER",
        2 => "KPROBE",
        3 => "SCHED_CLS",
        4 => "SCHED_ACT",
        5 => "TRACEPOINT",
        6 => "XDP",
        7 => "PERF_EVENT",
        8 => "CGROUP_SKB",
        9 => "CGROUP_SOCK",
        10 => "LWT_IN",
        11 => "LWT_OUT",
        12 => "LWT_XMIT",
        13 => "SOCK_OPS",
        14 => "SK_SKB",
        15 => "CGROUP_DEVICE",
        16 => "SK_MSG",
        17 => "RAW_TRACEPOINT",
        18 => "CGROUP_SOCK_ADDR",
        19 => "LWT_SEG6LOCAL",
        20 => "LIRC_MODE2",
        21 => "SK_REUSEPORT",
        22 => "FLOW_DISSECTOR",
        23 => "CGROUP_SYSCTL",
        24 => "RAW_TRACEPOINT_WRITABLE",
        25 => "CGROUP_SOCKOPT",
        26 => "TRACING",
        27 => "STRUCT_OPS",
        28 => "EXT",
        29 => "LSM",
        30 => "SK_LOOKUP",
        31 => "SYSCALL",
        32 => "NETFILTER",
        _ => "UNKNOWN",
    }
}

pub fn cstring_from_i8_array(arr: [i8; 16]) -> Option<String> {
    let len = arr.iter().position(|&c| c == 0).unwrap_or(arr.len());
    let slice = &arr[..len];
    let u8_slice: &[u8] = unsafe { std::slice::from_raw_parts(slice.as_ptr() as *const u8, len) };
    std::str::from_utf8(u8_slice).map(|s| s.to_string()).ok()
}
