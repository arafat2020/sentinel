// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
//go:build ignore

/*
 * Network connection events for Sentinel.
 *
 * TCP is followed through the socket state tracepoint. A connection is tied
 * to a process at the two moments the kernel runs on that process's behalf:
 * when it calls connect() (the socket enters SYN_SENT) and when accept()
 * returns a socket to it. Everything later, including the close and its byte
 * counts, happens in softirq context where "the current task" is whatever
 * was interrupted, so the owner is looked up by socket, never taken from the
 * current task.
 *
 * UDP has no states. The first send (or connect) on each socket is reported.
 *
 * Requires Linux 5.8 with BTF, and BPF trampolines (fentry/fexit) for the
 * accept and UDP hooks.
 */

#include "kernel_types.h"
#include "net_types.h"

#include "bpf_helpers.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define COMM_LEN 16

enum event_kind {
	EVENT_CONNECT = 1, /* a TCP connection attempt, with its outcome */
	EVENT_CLOSE = 2,   /* an established TCP connection closed */
	EVENT_LISTEN = 3,  /* a TCP socket started listening */
	EVENT_UNLISTEN = 4,
	EVENT_UDP = 5,     /* first send or connect on a UDP socket */
};

#define DIR_OUT 1
#define DIR_IN 2

/* Who a socket belongs to, recorded in process context. */
struct owner {
	__u64 start;  /* the process's start_boottime: its identity */
	__u64 opened; /* boot ns when the connection was opened */
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u8 direction;
	__u8 established;
	__u8 listening;
	__u8 pad;
	/* The local port, kept because the kernel clears it from the socket
	 * before the close is announced. */
	__u16 lport;
	__u16 pad2;
	char comm[COMM_LEN];
};

/* One record. Userspace decodes this layout by hand; keep record.go in step. */
struct event {
	__u64 ts;     /* boot ns of this event */
	__u64 opened; /* boot ns the connection was opened, or 0 */
	__u64 start;
	__u64 bytes_sent;
	__u64 bytes_received;
	__u32 kind;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 netns;
	__u32 err; /* sk_err when a connect failed */
	__u16 family;
	__u16 lport;
	__u16 rport;
	__u8 direction;
	__u8 protocol;
	__u8 laddr[16];
	__u8 raddr[16];
	char comm[COMM_LEN];
};

/* Sized by userspace before loading. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

/* TCP socket -> owner. LRU: when full, the least recently used socket is
 * forgotten, and its later events are counted as unowned. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct owner);
} socks SEC(".maps");

/* UDP sockets already reported, so that each is reported once. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u8);
} udp_seen SEC(".maps");

/* (network namespace, protocol, local port) -> owner, for attributing
 * packets seen on the wire (DNS) to the process that sent them. */
struct port_key {
	__u32 netns;
	__u16 port;
	__u8 protocol;
	__u8 pad;
};

struct port_owner {
	__u64 start;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	char comm[COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct port_key);
	__type(value, struct port_owner);
} ports SEC(".maps");

enum counter {
	COUNT_RING_DROPS = 0,   /* records that did not fit the ring buffer */
	COUNT_UNOWNED = 1,      /* TCP closes of sockets with no known owner */
	COUNT_SOCK_INSERTS = 2, /* sockets given an owner */
	COUNT_UDP_INSERTS = 3,  /* UDP sockets reported */
	COUNT_MAX = 4,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, COUNT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void count(__u32 which)
{
	__u64 *n = bpf_map_lookup_elem(&counters, &which);

	if (n)
		*n += 1;
}

/* Only valid in process context. */
static __always_inline void current_owner(struct owner *o, __u8 direction)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);

	o->start = BPF_CORE_READ(leader, start_boottime);
	o->opened = bpf_ktime_get_boot_ns();
	o->pid = bpf_get_current_pid_tgid() >> 32;
	o->ppid = BPF_CORE_READ(leader, real_parent, tgid);
	o->uid = (__u32)bpf_get_current_uid_gid();
	o->direction = direction;
	BPF_CORE_READ_STR_INTO(&o->comm, leader, comm);
}

static __always_inline __u32 netns_of(struct sock *sk)
{
	return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

/* Fills the addresses and ports of a socket. */
static __always_inline void fill_tuple(struct event *e, struct sock *sk)
{
	e->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	e->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->rport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	e->netns = netns_of(sk);

	if (e->family == AF_INET) {
		BPF_CORE_READ_INTO(&e->laddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&e->raddr, sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&e->laddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&e->raddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
}

static __always_inline void fill_owner(struct event *e, const struct owner *o)
{
	e->start = o->start;
	e->opened = o->opened;
	e->pid = o->pid;
	e->ppid = o->ppid;
	e->uid = o->uid;
	e->direction = o->direction;
	__builtin_memcpy(e->comm, o->comm, COMM_LEN);
}

static __always_inline void submit(struct event *e)
{
	if (bpf_ringbuf_output(&events, e, sizeof(*e), 0))
		count(COUNT_RING_DROPS);
}

static __always_inline void remember_port(struct sock *sk, __u8 protocol, const struct owner *o)
{
	struct port_key key = {};
	struct port_owner value = {};

	key.netns = netns_of(sk);
	key.port = BPF_CORE_READ(sk, __sk_common.skc_num);
	key.protocol = protocol;
	if (!key.port)
		return;

	value.start = o->start;
	value.pid = o->pid;
	value.ppid = o->ppid;
	value.uid = o->uid;
	__builtin_memcpy(value.comm, o->comm, COMM_LEN);

	bpf_map_update_elem(&ports, &key, &value, 0);
}

SEC("tp_btf/inet_sock_set_state")
int on_tcp_state(__u64 *ctx)
{
	/* TP_PROTO(const struct sock *sk, const int oldstate, const int newstate) */
	struct sock *sk = (struct sock *)ctx[0];
	int oldstate = (int)ctx[1];
	int newstate = (int)ctx[2];
	__u64 key = (__u64)sk;
	struct event e = {};
	struct owner *known;
	__u16 family;

	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
		return 0;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	/* connect() and listen() put the socket in these states on the
	 * calling process's own time: this is where it gets its owner. */
	if (newstate == TCP_SYN_SENT || newstate == TCP_LISTEN) {
		struct owner o = {};

		current_owner(&o, newstate == TCP_LISTEN ? DIR_IN : DIR_OUT);
		o.listening = newstate == TCP_LISTEN;
		o.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
		bpf_map_update_elem(&socks, &key, &o, 0);
		count(COUNT_SOCK_INSERTS);

		if (newstate == TCP_LISTEN) {
			e.ts = o.opened;
			e.kind = EVENT_LISTEN;
			e.protocol = IPPROTO_TCP;
			fill_owner(&e, &o);
			fill_tuple(&e, sk);
			submit(&e);
		}
		return 0;
	}

	if (newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE)
		return 0;

	known = bpf_map_lookup_elem(&socks, &key);
	if (!known) {
		/* An accepted socket is established before accept() returns
		 * it; that is not a loss. A close with no owner is: the socket
		 * predates the collector, or its entry was pushed out. */
		if (newstate == TCP_CLOSE && oldstate != TCP_SYN_SENT && oldstate != TCP_LISTEN)
			count(COUNT_UNOWNED);
		return 0;
	}

	e.ts = bpf_ktime_get_boot_ns();
	e.protocol = IPPROTO_TCP;
	fill_owner(&e, known);
	fill_tuple(&e, sk);

	if (newstate == TCP_ESTABLISHED) {
		if (known->direction != DIR_OUT || known->established)
			return 0;

		known->established = 1;
		known->lport = e.lport;
		remember_port(sk, IPPROTO_TCP, known);

		e.kind = EVENT_CONNECT;
		submit(&e);
		return 0;
	}

	/* TCP_CLOSE */
	if (!e.lport)
		e.lport = known->lport;

	if (known->listening) {
		e.kind = EVENT_UNLISTEN;
	} else if (!known->established) {
		/* The attempt to connect failed; sk_err says how. */
		e.kind = EVENT_CONNECT;
		e.err = BPF_CORE_READ(sk, sk_err);
		if (!e.err)
			e.err = ~0U;
	} else {
		struct tcp_sock *tp = (struct tcp_sock *)sk;

		e.kind = EVENT_CLOSE;
		e.bytes_sent = BPF_CORE_READ(tp, bytes_sent);
		e.bytes_received = BPF_CORE_READ(tp, bytes_received);
	}
	submit(&e);

	bpf_map_delete_elem(&socks, &key);
	return 0;
}

/* accept() hands the process a socket that the kernel established earlier,
 * in softirq context. This is the first moment it has an owner. */
static __always_inline int accepted(struct sock *sk)
{
	__u64 key = (__u64)sk;
	struct owner o = {};
	struct event e = {};

	if (!sk)
		return 0;

	current_owner(&o, DIR_IN);
	o.established = 1;
	o.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	bpf_map_update_elem(&socks, &key, &o, 0);
	count(COUNT_SOCK_INSERTS);

	e.ts = o.opened;
	e.kind = EVENT_CONNECT;
	e.protocol = IPPROTO_TCP;
	fill_owner(&e, &o);
	fill_tuple(&e, sk);
	submit(&e);

	return 0;
}

/* inet_csk_accept took four arguments up to Linux 6.9 and takes two from
 * 6.10; the return value follows the arguments. Userspace loads the variant
 * that fits the running kernel. */
SEC("fexit/inet_csk_accept")
int on_accept_4(__u64 *ctx)
{
	return accepted((struct sock *)ctx[4]);
}

SEC("fexit/inet_csk_accept")
int on_accept_2(__u64 *ctx)
{
	return accepted((struct sock *)ctx[2]);
}

/* Reports a UDP socket the first time it is used. remote, if not null, is the
 * destination given to sendto(); otherwise the socket is connected and has
 * one of its own. */
static __always_inline int udp_first_use(struct sock *sk, void *remote)
{
	__u64 key = (__u64)sk;
	struct owner o = {};
	struct event e = {};
	__u8 one = 1;
	__u16 family;

	if (bpf_map_lookup_elem(&udp_seen, &key))
		return 0;
	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_UDP)
		return 0;

	bpf_map_update_elem(&udp_seen, &key, &one, 0);
	count(COUNT_UDP_INSERTS);

	current_owner(&o, DIR_OUT);
	remember_port(sk, IPPROTO_UDP, &o);

	e.ts = o.opened;
	e.kind = EVENT_UDP;
	e.protocol = IPPROTO_UDP;
	fill_owner(&e, &o);
	fill_tuple(&e, sk);

	if (remote) {
		family = 0;
		bpf_probe_read_kernel(&family, sizeof(family), remote);

		if (family == AF_INET) {
			struct sockaddr_in in = {};

			bpf_probe_read_kernel(&in, sizeof(in), remote);
			__builtin_memset(e.raddr, 0, sizeof(e.raddr));
			__builtin_memcpy(e.raddr, &in.sin_addr, 4);
			e.rport = __builtin_bswap16(in.sin_port);
			/* A dual-stack socket sending to an IPv4 address. */
			if (e.family == AF_INET6) {
				e.family = AF_INET;
				__builtin_memcpy(e.laddr, e.laddr + 12, 4);
			}
		} else if (family == AF_INET6) {
			struct sockaddr_in6 in6 = {};

			bpf_probe_read_kernel(&in6, sizeof(in6), remote);
			__builtin_memcpy(e.raddr, &in6.sin6_addr, 16);
			e.rport = __builtin_bswap16(in6.sin6_port);
		}
	}

	submit(&e);
	return 0;
}

SEC("fexit/udp_sendmsg")
int on_udp_send(__u64 *ctx)
{
	/* int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len) */
	struct sock *sk = (struct sock *)ctx[0];
	struct msghdr *msg = (struct msghdr *)ctx[1];

	if ((long)ctx[3] < 0)
		return 0;
	return udp_first_use(sk, BPF_CORE_READ(msg, msg_name));
}

SEC("fexit/udpv6_sendmsg")
int on_udp6_send(__u64 *ctx)
{
	struct sock *sk = (struct sock *)ctx[0];
	struct msghdr *msg = (struct msghdr *)ctx[1];

	if ((long)ctx[3] < 0)
		return 0;
	return udp_first_use(sk, BPF_CORE_READ(msg, msg_name));
}

SEC("fexit/ip4_datagram_connect")
int on_udp_connect(__u64 *ctx)
{
	/* int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) */
	if ((int)ctx[3] != 0)
		return 0;
	return udp_first_use((struct sock *)ctx[0], 0);
}

SEC("fexit/ip6_datagram_connect")
int on_udp6_connect(__u64 *ctx)
{
	if ((int)ctx[3] != 0)
		return 0;
	return udp_first_use((struct sock *)ctx[0], 0);
}

/* A destroyed socket's address will be given to a new socket; forget it, or
 * the new one would look as if it had already been reported. */
SEC("fentry/udp_destroy_sock")
int on_udp_destroy(__u64 *ctx)
{
	__u64 key = ctx[0];

	bpf_map_delete_elem(&udp_seen, &key);
	return 0;
}

SEC("fentry/udpv6_destroy_sock")
int on_udp6_destroy(__u64 *ctx)
{
	__u64 key = ctx[0];

	bpf_map_delete_elem(&udp_seen, &key);
	return 0;
}
