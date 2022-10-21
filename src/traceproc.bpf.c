#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "traceproc.h"

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
	__type(value, struct event);
} heap SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec /* vmlinux.h */ *ctx)
{
	struct task_struct *task;
	unsigned fname_off = ctx->__data_loc_filename & 0xffff;
	struct event *e;
	int zero = 0;

	// This should allocate/reserve memory for e
	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		return 0;
	}

	task = (struct task_struct *)bpf_get_current_task();

	e->pid = bpf_get_current_pid_tgid() >> 32; // Shift to only use pid
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	// TODO: Shouldn't it be possible to cast kuid_t to unsigned int?
	BPF_CORE_READ_INTO(&e->loginuid, task, loginuid);
	e->sessionid = BPF_CORE_READ(task, sessionid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_str(&e->filename, sizeof(e->filename),
					   (void *)ctx + fname_off);

	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

    return 0;
}