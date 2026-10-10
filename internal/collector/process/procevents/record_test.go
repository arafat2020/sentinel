package procevents

import (
	"encoding/binary"
	"testing"
)

func encodeRecord(kind uint32, args string, flags uint32) []byte {
	sample := make([]byte, recordHeaderSize)
	binary.LittleEndian.PutUint64(sample[0:], 1_000_000_123)
	binary.LittleEndian.PutUint64(sample[8:], 987_654_321)
	binary.LittleEndian.PutUint32(sample[16:], kind)
	binary.LittleEndian.PutUint32(sample[20:], 4242)
	binary.LittleEndian.PutUint32(sample[24:], 77)
	binary.LittleEndian.PutUint32(sample[28:], 1000)
	copy(sample[32:], "curl")

	if kind != recordKindExec {
		return sample
	}

	sample = append(sample, make([]byte, 8+recordFilenameSize)...)
	binary.LittleEndian.PutUint32(sample[48:], flags)
	binary.LittleEndian.PutUint32(sample[52:], uint32(len(args)))
	copy(sample[56:], "/usr/bin/curl")
	return append(sample, args...)
}

func TestDecodeRecord(t *testing.T) {
	fork, err := decodeRecord(encodeRecord(recordKindFork, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	want := record{kind: recordKindFork, bootNanos: 1_000_000_123, startNanos: 987_654_321, pid: 4242, ppid: 77, uid: 1000, comm: "curl"}
	if fork != want {
		t.Errorf("fork = %+v\nwant   %+v", fork, want)
	}

	exec, err := decodeRecord(encodeRecord(recordKindExec, "curl\x00-o\x00/tmp/x\x00\x00http://h/x\x00", recordArgsTruncated))
	if err != nil {
		t.Fatal(err)
	}
	// Empty arguments are dropped, as the polling collector drops them.
	if exec.cmdline != "curl -o /tmp/x http://h/x" || exec.argv0 != "curl" || exec.filename != "/usr/bin/curl" || exec.flags != recordArgsTruncated {
		t.Errorf("exec = %+v", exec)
	}

	// A name that fills the kernel's 16 bytes has no terminator.
	full := encodeRecord(recordKindExit, "", 0)
	copy(full[32:48], "0123456789abcdef")
	if exit, err := decodeRecord(full); err != nil || exit.comm != "0123456789abcdef" {
		t.Errorf("exit = %+v, %v", exit, err)
	}
}

func TestDecodeRecordRejectsDamage(t *testing.T) {
	exec := encodeRecord(recordKindExec, "a\x00b\x00", 0)

	cases := map[string][]byte{
		"empty":             nil,
		"short header":      exec[:recordHeaderSize-1],
		"exec without body": exec[:recordHeaderSize+10],
		"args cut off":      exec[:len(exec)-1],
		"unknown kind":      encodeRecord(9, "", 0),
	}
	for name, sample := range cases {
		if _, err := decodeRecord(sample); err == nil {
			t.Errorf("%s: decoded without error", name)
		}
	}

	oversized := encodeRecord(recordKindExec, "", 0)
	binary.LittleEndian.PutUint32(oversized[52:], recordArgsMax+1)
	if _, err := decodeRecord(oversized); err == nil {
		t.Error("an argument length beyond the limit was accepted")
	}
}

func TestUserCacheIsBounded(t *testing.T) {
	cache := newUserCache()
	lookups := 0
	cache.lookup = func(uid uint32) string {
		lookups++
		return "user"
	}

	for uid := uint32(0); uid < maxCachedUsers; uid++ {
		cache.name(uid)
	}
	cache.name(5)
	if lookups != maxCachedUsers {
		t.Fatalf("%d lookups for %d users; a cached name was looked up again", lookups, maxCachedUsers)
	}

	cache.name(maxCachedUsers + 1)
	if got := cache.size.Load(); got != 1 {
		t.Errorf("cache holds %d names after overflowing, want 1", got)
	}
	if cache.resets.Load() != 1 {
		t.Errorf("resets = %d", cache.resets.Load())
	}
}
