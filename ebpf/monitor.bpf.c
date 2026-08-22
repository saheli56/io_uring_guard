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
    u32 target_ip;
    u16 target_port;
    char filename[32]; 
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline void fill_base_event(struct event *e, u8 opcode) {
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tgid = id & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    e->opcode = opcode;
    e->fd = -1;
    e->target_ip = 0;
    e->target_port = 0;
    e->filename[0] = '\0';
}

SEC("tp/io_uring/io_uring_submit_req")
int handle_submit_req(struct trace_event_raw_io_uring_submit_req *ctx) {
    u8 opcode = ctx->opcode;
    
    // Skip file-descriptor based ops here, they will be handled by io_uring_file_get
    if (opcode == 1 || opcode == 2 || opcode == 4 || opcode == 5 || 
        opcode == 22 || opcode == 23 || opcode == 26 || opcode == 27) {
        return 0; 
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_base_event(e, opcode);

    struct io_kiocb *req = (struct io_kiocb *)ctx->req;

    if (opcode == 16) { // CONNECT
        struct io_connect *conn = (struct io_connect *)&req->cmd;
        struct sockaddr *uaddr;
        
        bpf_probe_read_kernel(&uaddr, sizeof(uaddr), (void *)conn + 8);
        
        struct sockaddr_in saddr = {0};
        if (bpf_probe_read_user(&saddr, sizeof(saddr), uaddr) == 0) {
            if (saddr.sin_family == 2) { // AF_INET
                e->target_ip = saddr.sin_addr.s_addr;
                e->target_port = saddr.sin_port;
            }
        }
    } else if (opcode == 18 || opcode == 28) { // OPENAT / OPENAT2
        struct io_open *open = (struct io_open *)&req->cmd;
        struct filename *fname = NULL;
        
        bpf_probe_read_kernel(&fname, sizeof(fname), (void *)open + 16);
        if (fname) {
            const char *name = NULL;
            bpf_probe_read_kernel(&name, sizeof(name), (void *)fname);
            bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("raw_tracepoint/io_uring_file_get")
int handle_file_get(struct bpf_raw_tracepoint_args *ctx) {
    struct io_kiocb *req = (struct io_kiocb *)ctx->args[0];
    int fd = (int)ctx->args[1];

    u8 opcode;
    bpf_probe_read_kernel(&opcode, sizeof(opcode), &req->opcode);

    // Only process the file-descriptor based opcodes here
    if (opcode == 1 || opcode == 2 || opcode == 4 || opcode == 5 || 
        opcode == 22 || opcode == 23 || opcode == 26 || opcode == 27) {
        
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) return 0;

        fill_base_event(e, opcode);
        e->fd = fd; // We successfully grab the real FD!

        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
