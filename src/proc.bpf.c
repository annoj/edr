#include "proc.h"
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
	__type(value, struct proc_exec_event);
} heap SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	struct proc_exec_event *e;
	int zero = 0;

	// This should allocate/reserve memory for e
	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		return 0;
	}

	task = (struct task_struct *)bpf_get_current_task();

	uint64_t uid_gid = bpf_get_current_uid_gid();
	e->uid = uid_gid >> 32;
	e->gid = uid_gid & 0xffffffff;
	e->pid = BPF_CORE_READ(task, pid);
	e->tgid = BPF_CORE_READ(task, tgid);
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->sessionid = BPF_CORE_READ(task, sessionid);
    BPF_CORE_READ_INTO(&e->loginuid, task, loginuid);
    BPF_CORE_READ_INTO(&e->comm, task, comm);

	// ctx->__data_loc_filename needs to be clamped to max range of 0x1ff
	// according to https://lists.iovisor.org/g/iovisor-dev/topic/30285987
	bpf_probe_read_str(&e->filename, sizeof(e->filename),
					   (void *)ctx + (ctx->__data_loc_filename & 0x1ff));

	// Read cmdline
	uint64_t arg_start = BPF_CORE_READ(task, mm, arg_start);
	uint64_t arg_end = BPF_CORE_READ(task, mm, arg_end);
	size_t arg_len = arg_end - arg_start;
	if (arg_len > MAX_PROC_CMDLINE_LEN - 1) {
        // TODO: Signal to userspace program that cmdline has been truncated
		arg_len = MAX_PROC_CMDLINE_LEN - 1;
	}

	int err = bpf_probe_read(&e->cmdline, arg_len, (void *)arg_start);
	if (err < 0) {
		arg_len = 0;
	}

	e->cmdline[arg_len] = '\0';
	e->cmdline_len = arg_len;

	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

    return 0;
}