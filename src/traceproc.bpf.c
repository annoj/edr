#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "traceproc.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// int my_pid = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec /* vmlinux.h */ *ctx)
{
    pid_t pid;
    u64 ts;

    pid = bpf_get_current_pid_tgid() >> 32;
    ts = bpf_ktime_get_ns();

    bpf_printk("Hello from PID: %d (TS: %d).\n", pid, ts);

    return 0;
}