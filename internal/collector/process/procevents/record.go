package procevents

import (
	"encoding/binary"
	"errors"
	"strings"
)

// The layout of a record from the eBPF programs; see struct header and struct
// exec_event in bpf/process.bpf.c.
const (
	recordHeaderSize   = 48
	recordFilenameSize = 512
	recordArgsOffset   = recordHeaderSize + 8 + recordFilenameSize
	recordArgsMax      = 4096

	recordKindFork = 1
	recordKindExec = 2
	recordKindExit = 3

	recordFilenameTruncated = 1
	recordArgsTruncated     = 2
	recordArgsUnreadable    = 4
)

// record is a decoded eBPF record, with kernel times still as the kernel
// gave them.
type record struct {
	kind       uint32
	bootNanos  uint64 // when it happened, on CLOCK_BOOTTIME
	startNanos uint64 // the process's start_boottime
	pid        int32
	ppid       int32
	uid        uint32
	comm       string

	// Exec only.
	filename string
	cmdline  string
	argv0    string
	flags    uint32
}

var errShortRecord = errors.New("record shorter than its layout")

func decodeRecord(sample []byte) (record, error) {
	if len(sample) < recordHeaderSize {
		return record{}, errShortRecord
	}

	r := record{
		bootNanos:  binary.LittleEndian.Uint64(sample[0:]),
		startNanos: binary.LittleEndian.Uint64(sample[8:]),
		kind:       binary.LittleEndian.Uint32(sample[16:]),
		pid:        int32(binary.LittleEndian.Uint32(sample[20:])),
		ppid:       int32(binary.LittleEndian.Uint32(sample[24:])),
		uid:        binary.LittleEndian.Uint32(sample[28:]),
		comm:       cString(sample[32:48]),
	}

	switch r.kind {
	case recordKindFork, recordKindExit:
		return r, nil
	case recordKindExec:
	default:
		return record{}, errors.New("unknown record kind")
	}

	if len(sample) < recordArgsOffset {
		return record{}, errShortRecord
	}

	r.flags = binary.LittleEndian.Uint32(sample[48:])
	argsLen := int(binary.LittleEndian.Uint32(sample[52:]))
	r.filename = cString(sample[56 : 56+recordFilenameSize])

	if argsLen > recordArgsMax || recordArgsOffset+argsLen > len(sample) {
		return record{}, errShortRecord
	}
	r.cmdline, r.argv0 = joinArgs(sample[recordArgsOffset : recordArgsOffset+argsLen])

	return r, nil
}

// joinArgs turns the kernel's NUL-separated argument block into the command
// line the polling collector reports: the arguments joined by single spaces,
// with empty ones left out. It also returns the first argument.
func joinArgs(block []byte) (cmdline, argv0 string) {
	args := strings.FieldsFunc(string(block), func(r rune) bool { return r == 0 })
	if len(args) == 0 {
		return "", ""
	}
	return strings.Join(args, " "), args[0]
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
