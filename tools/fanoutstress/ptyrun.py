#!/usr/bin/env python3
"""Run a command on a pseudo-terminal, answer its password prompts, and stop
it after a number of seconds.

usage: ptyrun.py <seconds> <command> [args...]

Sentinel asks for its password when started from a terminal, which a test
harness has to answer. (Started without a terminal, as a service, headless
mode does not ask.)
"""
import os, pty, select, signal, sys, time

seconds = float(sys.argv[1])
argv = sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)

deadline = time.time() + seconds
buf = b""
stopped = False
while True:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        buf += data
        if buf.rstrip().endswith(b"assword:"):
            os.write(fd, b"sentinel-test\n")
            buf = b""
    if not stopped and time.time() > deadline:
        os.kill(pid, signal.SIGTERM)
        stopped = True
        deadline = time.time() + 10
    elif stopped and time.time() > deadline:
        os.kill(pid, signal.SIGKILL)
        break
try:
    os.waitpid(pid, 0)
except ChildProcessError:
    pass
