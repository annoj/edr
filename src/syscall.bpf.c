#include "syscall.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(int));
        __uint(value_size, sizeof(int));
} pb SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, int);
        __type(value, struct syscall_enter_event);
} heap SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_open(struct trace_event_raw_sys_enter *ctx)
{
        struct syscall_enter_event *e;
        struct task_struct *task;
        int zero = 0;

        // This should allocate/reserve memory for e
        e = bpf_map_lookup_elem(&heap, &zero);
        if (!e) {
                return 0;
        }

        task = (struct task_struct *)bpf_get_current_task();
        e->id = BPF_CORE_READ(ctx, id);
        e->pid = BPF_CORE_READ(task, pid);
        BPF_CORE_READ_INTO(&e->args, ctx, args);

        bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

        return 0;
}
