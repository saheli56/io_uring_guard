#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct event {
    u64 timestamp;
    u32 pid;
    u32 tgid;
    u32 uid;
    char comm[16];
    u8 opcode;
    int fd;
    char filename[32]; 
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("raw_tracepoint/io_uring_file_get")
int handle_file_get(struct bpf_raw_tracepoint_args *ctx) {
    struct io_kiocb *req = (struct io_kiocb *)ctx->args[0];
    int fd = (int)ctx->args[1];

    u8 opcode = BPF_CORE_READ(req, opcode);


    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tgid = id & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    e->opcode = opcode;
    e->fd = fd;
    e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
