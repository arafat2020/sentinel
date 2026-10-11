package netevents

// The eBPF programs are compiled ahead of time and committed, as the process
// collector's are. Regenerate with `make generate`; CI fails on a diff. The
// libbpf headers and the task types are the process collector's.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -tags linux -target amd64,arm64 -cc clang-18 -strip llvm-strip-18 -cflags "-O2 -g -Wall -Werror" -go-package netevents network bpf/net.bpf.c -- -Ibpf -I../../process/procevents/bpf/headers
