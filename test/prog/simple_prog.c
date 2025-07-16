#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int hello(struct bpf_raw_tracepoint_args *ctx) {
    char msg[] = "Hello, eBPF!";
    bpf_printk("%s\n", msg);
    return 0;
}

char _license[] SEC("license") = "GPL";
