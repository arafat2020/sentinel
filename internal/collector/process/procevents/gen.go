package procevents

// The eBPF programs are compiled ahead of time and committed, so building
// Sentinel needs no clang. Regenerate with `make generate` after changing
// bpf/process.bpf.c or anything under bpf/headers; CI fails if the committed
// files differ from what the sources produce.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -tags linux -target amd64,arm64 -cc clang-18 -strip llvm-strip-18 -cflags "-O2 -g -Wall -Werror" -go-package procevents process bpf/process.bpf.c -- -Ibpf/headers
