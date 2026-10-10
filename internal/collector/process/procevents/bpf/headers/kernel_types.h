/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * The few kernel types the process collector reads, declared by hand instead
 * of through a generated vmlinux.h. Every struct carries
 * preserve_access_index, so each field access is a CO-RE relocation: the
 * loader looks the field up by name in the running kernel's BTF and patches
 * in its real offset. Only the names and kinds here have to match the kernel;
 * the layout does not, and fields that are not listed do not matter.
 *
 * Keeping this by hand makes the build independent of the kernel it runs on
 * and of the architecture, and keeps a multi-megabyte generated header out of
 * the repository.
 */
#ifndef __SENTINEL_KERNEL_TYPES_H__
#define __SENTINEL_KERNEL_TYPES_H__

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef short __s16;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
typedef long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

typedef _Bool bool;
enum {
	false = 0,
	true = 1,
};

/* From include/uapi/linux/bpf.h: the map types used here. */
enum bpf_map_type {
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_RINGBUF = 27,
};

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	unsigned int val;
} kuid_t;

struct cred {
	kuid_t uid;
};

struct signal_struct {
	int nr_threads;
	atomic_t live;
};

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
};

struct task_struct {
	int pid;
	int tgid;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	const struct cred *cred;
	/* Nanoseconds since boot, including time suspended. Called
	 * real_start_time before Linux 5.5. */
	__u64 start_boottime;
	struct signal_struct *signal;
	struct mm_struct *mm;
	char comm[16];
};

struct linux_binprm {
	const char *filename;
};

#pragma clang attribute pop

#endif /* __SENTINEL_KERNEL_TYPES_H__ */
