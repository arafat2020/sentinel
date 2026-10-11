/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * The kernel socket types the network collector reads, declared by hand with
 * CO-RE attributes, as kernel_types.h does for tasks. Only names and kinds
 * have to match the running kernel; offsets are relocated at load time.
 */
#ifndef __SENTINEL_NET_TYPES_H__
#define __SENTINEL_NET_TYPES_H__

/* From include/uapi/linux/bpf.h. kernel_types.h declares the map types the
 * process collector uses; these are the two more used here. */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_LRU_HASH 9

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* enum in include/net/tcp_states.h */
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7
#define TCP_LISTEN 10

/* Socket addresses are user ABI: their layout is fixed, not relocated. */
struct in_addr {
	__be32 s_addr;
};

struct in6_addr_raw {
	__u8 bytes[16];
};

struct sockaddr_in {
	unsigned short sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
};

struct sockaddr_in6 {
	unsigned short sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr_raw sin6_addr;
};

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
};

struct ns_common {
	unsigned int inum;
};

struct net {
	struct ns_common ns;
};

typedef struct {
	struct net *net;
} possible_net_t;

struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	volatile unsigned char skc_state;
	possible_net_t skc_net;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
	int sk_err;
};

struct tcp_sock {
	__u64 bytes_received;
	__u64 bytes_sent;
};

struct msghdr {
	void *msg_name;
};

#pragma clang attribute pop

#endif /* __SENTINEL_NET_TYPES_H__ */
