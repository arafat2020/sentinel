// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
//go:build ignore

/*
 * Process lifecycle events for Sentinel.
 *
 * Three BTF-typed tracepoint programs report every process (not thread)
 * that is created, execs, or exits, through one ring buffer. Everything that
 * describes the process is read here, in the kernel, at the moment it
 * happens, so that a process which lives for a millisecond is still reported
 * in full.
 *
 * Requires Linux 5.8: BPF ring buffers and bpf_ktime_get_boot_ns().
 */

#include "kernel_types.h"

#include "bpf_helpers.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define COMM_LEN 16
/* The path given to execve. Longer paths are cut and flagged. */
#define FILENAME_MAX 512
/* The arguments as the kernel stores them: NUL-separated. Longer argument
 * lists are cut and flagged. */
#define ARGS_MAX 4096

enum event_kind {
	EVENT_FORK = 1,
	EVENT_EXEC = 2,
	EVENT_EXIT = 3,
};

#define FLAG_FILENAME_TRUNCATED 1
#define FLAG_ARGS_TRUNCATED 2
#define FLAG_ARGS_UNREADABLE 4

/*
 * A fork or exit record is a header alone. An exec record is a header, the
 * rest of the fixed part, and then args_len bytes of arguments, so a record
 * is only as long as what it holds. Userspace decodes this layout by hand;
 * keep record.go in step with it.
 */
struct header {
	__u64 ts;	/* bpf_ktime_get_boot_ns() when it happened */
	__u64 start;	/* the process's start_boottime: its identity */
	__u32 kind;
	__u32 pid;	/* thread group id */
	__u32 ppid;	/* real parent's thread group id */
	__u32 uid;	/* real uid */
	char comm[COMM_LEN];
};

struct exec_event {
	struct header h;
	__u32 flags;
	__u32 args_len;
	char filename[FILENAME_MAX];
	char args[ARGS_MAX];
};

#define EXEC_EVENT_FIXED (__builtin_offsetof(struct exec_event, args))

/* Sized by userspace before loading (see Options.RingBufferBytes). */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

/* An exec record is too large for the BPF stack; it is assembled here. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_event);
} scratch SEC(".maps");

/* Records that did not fit in the ring buffer, by kind (index kind - 1).
 * Per-CPU so counting never contends; userspace sums the CPUs. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

/*
 * How many threads signal->live says are left when the last thread of a
 * process reaches the exit tracepoint: 0 where the tracepoint comes after the
 * kernel has counted the thread out, 1 where it comes before. Learned from
 * the first single-threaded process to exit rather than assumed from the
 * kernel version. LIVE_UNKNOWN until then.
 */
#define LIVE_UNKNOWN 0x7fffffff
int live_at_last_exit = LIVE_UNKNOWN;

static __always_inline void count_drop(__u32 kind)
{
	__u32 key = kind - 1;
	__u64 *count = bpf_map_lookup_elem(&drops, &key);

	if (count)
		*count += 1;
}

static __always_inline void fill_header(struct header *e, __u32 kind, struct task_struct *task)
{
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);

	e->ts = bpf_ktime_get_boot_ns();
	e->kind = kind;
	e->pid = BPF_CORE_READ(task, tgid);
	/* /proc/<pid>/stat reports the start time of the thread group leader,
	 * and that is what identifies the process everywhere else. */
	e->start = BPF_CORE_READ(leader, start_boottime);
	e->ppid = BPF_CORE_READ(leader, real_parent, tgid);
	e->uid = BPF_CORE_READ(task, cred, uid.val);
	BPF_CORE_READ_STR_INTO(&e->comm, leader, comm);
}

SEC("tp_btf/sched_process_fork")
int on_fork(__u64 *ctx)
{
	/* TP_PROTO(struct task_struct *parent, struct task_struct *child) */
	struct task_struct *child = (struct task_struct *)ctx[1];
	struct header e = {};

	/* A new thread in an existing process is not a new process. */
	if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid))
		return 0;

	fill_header(&e, EVENT_FORK, child);

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		count_drop(EVENT_FORK);

	return 0;
}

SEC("tp_btf/sched_process_exec")
int on_exec(__u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
	 *
	 * By now the old program is gone: the task is the thread group
	 * leader, has its new name and credentials, and its new address space
	 * already holds the arguments. */
	struct task_struct *task = (struct task_struct *)ctx[0];
	struct linux_binprm *bprm = (struct linux_binprm *)ctx[2];
	unsigned long arg_start, arg_end;
	__u32 zero = 0;
	__u64 len, size;
	struct exec_event *e;
	long n;

	e = bpf_map_lookup_elem(&scratch, &zero);
	if (!e)
		return 0;

	fill_header(&e->h, EVENT_EXEC, task);
	e->flags = 0;
	e->args_len = 0;

	n = bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), BPF_CORE_READ(bprm, filename));
	if (n < 0)
		e->filename[0] = 0;
	else if (n == sizeof(e->filename))
		e->flags |= FLAG_FILENAME_TRUNCATED;

	arg_start = BPF_CORE_READ(task, mm, arg_start);
	arg_end = BPF_CORE_READ(task, mm, arg_end);

	len = arg_end > arg_start ? arg_end - arg_start : 0;
	if (len > ARGS_MAX) {
		len = ARGS_MAX;
		e->flags |= FLAG_ARGS_TRUNCATED;
	}

	/* The kernel has just copied the arguments onto the new stack, so the
	 * pages are present and this read does not fault. */
	if (len > 0) {
		if (bpf_probe_read_user(e->args, len, (void *)arg_start) == 0)
			e->args_len = len;
		else
			e->flags |= FLAG_ARGS_UNREADABLE;
	}

	size = EXEC_EVENT_FIXED + e->args_len;
	if (size > sizeof(*e))
		size = sizeof(*e);

	if (bpf_ringbuf_output(&events, e, size, 0))
		count_drop(EVENT_EXEC);

	return 0;
}

SEC("tp_btf/sched_process_exit")
int on_exit(__u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p)
	 *
	 * This fires for every thread. The process is gone when its last
	 * thread is, which need not be the leader. */
	struct task_struct *task = (struct task_struct *)ctx[0];
	int threads = BPF_CORE_READ(task, signal, nr_threads);
	int live = BPF_CORE_READ(task, signal, live.counter);
	struct header e = {};

	if (threads <= 1) {
		/* The only thread there is. */
		live_at_last_exit = live;
	} else if (live_at_last_exit != LIVE_UNKNOWN) {
		if (live != live_at_last_exit)
			return 0;
	} else if (BPF_CORE_READ(task, pid) != BPF_CORE_READ(task, tgid)) {
		/* Not yet known how to tell the last thread: take the leader. */
		return 0;
	}

	fill_header(&e, EVENT_EXIT, task);

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		count_drop(EVENT_EXIT);

	return 0;
}
