# Behavioral Patterns — Definition Guide

Sentinel detects suspicious behavior by matching **behavioral patterns** against
the live stream of telemetry events. Patterns are stored in
`configs/patterns.yaml` and can be edited directly in that file. The **Patterns
tab** (key `6`) in the TUI and the desktop app can edit the basic parts of a
pattern; everything described here as *advanced* is edited in the YAML file.

This guide describes pattern schema **v2**. Files written for the original
schema keep working unchanged; see [Compatibility with v1](#compatibility-with-v1).

---

## Concepts

### Pattern

A pattern is a named rule that produces a finding when a specific combination
of processes, their properties, their activity and their relationships is
observed within the correlation window (5 minutes).

### Role

Each pattern defines one or more **roles** (for example `parent` and `child`).
A role is a slot filled by one real process. A process can fill a role if:

- it satisfies the role's `match` block (and v1 `conditions`, if any),
- it is not barred by one of the pattern's `exclude` entries, and
- it has produced every event the role requires, inside the correlation
  window.

Each role is filled by a different process.

### Relationship

A relationship links two roles.

| Type | Meaning |
|---|---|
| `SPAWNED` | The process filling `parent` directly spawned the process filling `child` |
| `DESCENDANT` | The process filling `child` is a descendant of the one filling `parent`: its child, grandchild, and so on, up to `max_depth` generations |

```yaml
relationships:
  - { type: SPAWNED, parent: web, child: worker }
  - { type: DESCENDANT, parent: web, child: shell, max_depth: 4 }
```

`max_depth` defaults to 5 and may be 1 to 16. `SPAWNED` is the same as
`DESCENDANT` with `max_depth: 1`, and takes no `max_depth` of its own.

A `DESCENDANT` relationship holds only if Sentinel knows every process in
between. An intermediate process that has exited still counts for one
correlation window after its exit; one Sentinel never saw breaks the chain,
because nothing then proves the ancestry. Every link is checked against PID
reuse, as for `SPAWNED`.

**Every** relationship in the pattern must hold, and a role that appears in
more than one relationship is the same process in each. In a chain `a → b → c`,
`b` must be one process that is both a child of `a` and the parent of `c`.

### Finding

When every role is filled and every relationship holds, the pattern produces a
finding. The finding records the processes that matched, in the order the
pattern lists its roles.

---

## YAML format

A patterns file has two top-level keys: `patterns`, and optionally
`exclusions`.

```yaml
patterns:
  - name: my-rule                 # required; unique name of the rule
    severity: HIGH                # INFO | LOW | MEDIUM | HIGH | CRITICAL
    title: Short title
    description: Longer explanation.
    max_findings_per_window: 20   # optional; see "Rate limit"

    processes:                    # the roles
      - id: parent
        match:                    # optional; which processes can fill the role
          name: nginx
        events:                   # optional; what the process must have done
          - type: NETWORK_CONNECT

      - id: child
        match:
          name: { regex: '^(ba|da|z)?sh$' }
          user: { not: root }
        events:
          - type: NETWORK_CONNECT
            where:                # optional; which events of this type count
              remote_port: { not: { in: [80, 443] } }

    relationships:
      - type: SPAWNED
        parent: parent
        child: child

    exclude:                      # optional; see "Exclusions"
      - role: child
        match:
          cmdline: { contains: healthcheck }

exclusions:                       # optional; see "Exclusions"
  - rules: ["*"]
    match:
      exe: { prefix: /opt/monitoring/ }
    description: Monitoring agent
```

---

## Matching a process: `match`

A `match` block lists process fields and what each must look like. **All
fields listed must match** (AND).

| Field | Meaning |
|---|---|
| `name` | The process's short name, e.g. `python3`, `bash` |
| `exe` | Full path of the executable |
| `cmdline` | The full command line, as one string |
| `user` | The user the process runs as |

```yaml
match:
  name: { regex: '^python[0-9.]*$' }
  user: { not: { eq: root } }
  cmdline: { contains: "-c" }
```

A role with no `match` block (and no `conditions`) can be filled by any
process.

### Alternatives: `any_of`

`any_of` is a list of match blocks, of which **at least one** must match. It
is combined with the block's own fields by AND, and blocks may nest.

```yaml
match:
  name: python3            # must be python3 ...
  any_of:                  # ... and run from one of these places
    - exe: { prefix: /tmp/ }
    - exe: { prefix: /dev/shm/ }
```

---

## Required events: `events` and `where`

Each entry under `events` is a requirement: the process must have produced
**at least one event of that type inside the correlation window**. Requirements
are independent, and their order does not matter.

Adding `where` narrows the requirement: at least one in-window event of that
type must satisfy **every** field in the `where` block. One event has to pass
the whole block; two events passing half each do not count.

```yaml
events:
  - type: NETWORK_CONNECT
    where:
      remote_port: { not: { in: [80, 443, 53] } }
      remote_addr: { not: { cidr: [10.0.0.0/8, 127.0.0.0/8, "::1/128"] } }
  - type: DNS_QUERY          # any DNS query at all
```

`where` blocks accept `any_of` exactly as `match` blocks do.

### Event types and their fields

| Event type | When it fires | `where` fields |
|---|---|---|
| `NETWORK_CONNECT` | A connection was opened | `remote_addr`, `remote_port`, `local_port`, `protocol`, `state` |
| `NETWORK_CLOSE` | A connection was closed | same as `NETWORK_CONNECT` |
| `DNS_QUERY` | A process made a DNS lookup | `domain`, `query_type`, `resolver` |
| `FILE_CREATE` | A file was created | `path`, `old_path` |
| `FILE_MODIFY` | A file was written to | `path`, `old_path` |
| `FILE_DELETE` | A file was deleted | `path`, `old_path` |
| `FILE_RENAME` | A file was renamed or moved | `path`, `old_path` |
| `PROCESS_START` | A new process was created | `name`, `exe`, `cmdline`, `user` (of the process) |
| `PROCESS_EXEC` | A running process replaced its program with `execve` | `name`, `exe`, `cmdline`, `user` (of the new program) |
| `PROCESS_EXIT` | A process terminated | `name`, `exe`, `cmdline`, `user` (of the process) |
| `PERSISTENCE_CHANGE` | (planned) | none |
| `SCRIPT_EXECUTION` | (planned) | none |

Field kinds decide which operators apply:

| Kind | Fields |
|---|---|
| String | `name`, `exe`, `cmdline`, `user`, `protocol`, `state`, `domain`, `query_type`, `path`, `old_path` |
| String holding a path | `exe`, `path`, `old_path` (compared after cleaning when matched against a [capture](#captures)) |
| Address | `remote_addr`, `resolver` |
| Numeric | `remote_port`, `local_port` |

Using a field that does not belong to the event type, or `where` on an event
type with no fields, is an error.

---

## Thresholds: `count`, `within`, `distinct`

An event requirement can ask for more than one event.

```yaml
events:
  - type: DNS_QUERY
    count: 100          # at least this many; default 1
    within: 60s         # inside a span this long; default: the whole window
    distinct: domain    # count different values of this field, not events
    where:
      domain: { suffix: .example }
```

| Key | Meaning |
|---|---|
| `count` | How many matching events are needed (1 to 1000). With `distinct`, how many different values. |
| `within` | The events must fall inside some span of this length. It must be more than 0 and no longer than the correlation window, and needs `count` above 1 or `distinct`. |
| `distinct` | A `where` field of the event type. Events are counted by the number of different values it takes; an event where the field is missing is not counted. |

Only events passing `where` are counted. The requirement is met when `count`
matching events (or values) fall inside any `within`-long span that ends in the
correlation window: the span slides, so a burst counts wherever it happens. A
span covers events strictly less than `within` apart. Once met, the requirement
stays met until the end of that span leaves the window.

For `distinct`, each value counts from the last time it was seen: 100 distinct
domains in 60s means 100 different domains each looked up during those 60
seconds.

Counting is exact and does not depend on how many events Sentinel retains per
process (see [Limitations](#limitations)). Durations are written like `30s`,
`5m` or `1m30s`.

---

## Sequences

Event requirements say what a process did; a `sequence` says in what order
things happened, across one or more roles.

```yaml
sequence:
  within: 60s            # first and last step at most this far apart; default: the window
  order_tolerance: 3s    # see "Why a tolerance"; default 3s
  steps:
    - { role: dropper, type: NETWORK_CONNECT }
    - role: dropper
      type: FILE_CREATE
      where: { path: { glob: "/tmp/**" } }
      capture: dropped
    - role: payload
      type: PROCESS_START
      where: { exe: { eq: $dropped.path } }
```

- Each step is satisfied by **one** in-window event of its `type`, produced by
  the process bound to its `role`, that passes its `where`.
- The steps' events must be in timestamp order, subject to `order_tolerance`.
- The first and last steps' events must be no more than `within` apart.
- One event cannot satisfy two steps: two `NETWORK_CONNECT` steps need two
  connections.
- Every `role` must be a role of the pattern. The roles are bound as usual, so
  the pattern's `match` blocks, event requirements and relationships all still
  apply. A sequence may have up to 8 steps.

A sequence is checked against the events Sentinel has stored for the bound
processes, each time one of those processes does something. It does not matter
in what order the events reached Sentinel, only what their timestamps say.

### Why a tolerance

For some events the timestamp is the moment **Sentinel observed** it, not the
moment it happened:

| Events | How Sentinel learns of them | Timestamp is | Lag behind the action |
|---|---|---|---|
| `PROCESS_*` on Linux with the `ebpf` or `proc-connector` collector | The kernel reports each fork, exec and exit | When the kernel says it happened | None (the conversion is accurate to well under a microsecond) |
| `PROCESS_START`, `PROCESS_EXIT` with the `poll` collector (the only one on macOS and Windows) | Polling the process table every 2 seconds | When the poll noticed the change | Up to 2 s, plus the time the poll takes |
| `NETWORK_CONNECT`, `NETWORK_CLOSE` | Polling open connections every 2 seconds | When the poll noticed the change | Up to 2 s, plus the time the poll takes |
| `DNS_QUERY` | Packet capture (all platforms) | When the packet was decoded | Milliseconds |
| `FILE_*` on Linux | fanotify | When the event was read | Milliseconds |
| `FILE_*` on Windows | Directory change notifications | When the notification arrived | Milliseconds |
| `FILE_*` on macOS | Not active yet | — | — |

So when a process connects out and then writes a file, the file event can be
stamped up to a couple of seconds *before* the connection that preceded it.
`order_tolerance` allows for that: an earlier step's event may be stamped later
than a following step's, by at most the tolerance. The default of **3 seconds**
covers the 2-second polling interval and the time a poll takes.

The tolerance applies between every earlier and later step, not just
neighbours, so it cannot be chained to walk a sequence backwards. Set
`order_tolerance: 0s` to require strict timestamp order, which is appropriate
when every step is a DNS or file event, or a process event from the `ebpf`
collector. A wider tolerance accepts more out-of-order cases: with the default,
two events really 2 seconds apart in the "wrong" order can still satisfy a
sequence.

The default stays at 3 seconds even with event-driven process collection,
because connections are still found by polling.

### How processes are collected

On Linux, Sentinel can be told about processes by the kernel as they start,
exec and exit, instead of comparing the process table every two seconds. This
changes what a pattern can see:

| | `ebpf` | `proc-connector` | `poll` |
|---|---|---|---|
| A process that runs for a few milliseconds | Reported, with its full command line | Reported, often without its command line | Not seen |
| `PROCESS_START` timestamp | When it happened | When it happened | Up to 2 s late |
| `PROCESS_EXEC` | Reported | Reported | Never reported |

Sequence patterns that end in a short-lived process, like
[download and execute](#4-download-and-execute), depend on this: with `poll`
they fire only if the payload is still running at the next poll.

A new process is a fork followed, usually at once, by an exec. Sentinel reports
that as one `PROCESS_START` describing the program that was exec'd. A process
that execs again later, or that did not exec within 50 ms of being forked, gets
a `PROCESS_EXEC` for the later exec: it is the same process, with the same
identity and history, running a different program. Roles match a process by
the program it is running **now**; `where` on a `PROCESS_START` or
`PROCESS_EXEC` event matches the program that event announced.

Which collector is in use is shown in the Health view (TUI tab 9, the desktop
Settings tab, and the headless log) and is chosen with `--process-collector`.
The details are in [Linux Process Collection](linux-process-collector.md).

### Captures

`capture: <name>` on a step names the event that satisfied it. **Later** steps
can then compare a field of their own event with a field of that one, by
writing `$<name>.<field>` as the value of `eq`, `in` (with exactly one
element), `prefix`, `suffix` or `contains`:

```yaml
- role: payload
  type: PROCESS_START
  where: { exe: { eq: $dropped.path } }     # the program started is the file that was created
```

- `<field>` must be a `where` field of the captured event's type.
- The two fields must be of the same kind: string with string, address with
  address, numeric with numeric.
- When both are paths (`exe`, `path`, `old_path`) they are compared after
  cleaning, so `/tmp//a/../x` and `/tmp/x` are the same file.
- `nocase: true` applies as usual, and a reference can be wrapped in `not`.
- If either value is missing the comparison is false.

`$name.field` is only a reference inside a sequence step. Anywhere else it is
ordinary text.

---

## Operators

A field's value is an **operator object**: one or more operators in braces.
Several operators in one object must all hold (AND).

| Operator | Applies to | Meaning |
|---|---|---|
| `eq` | string, address, numeric | Equals the value |
| `in` | string, address, numeric | Equals one of a list of values |
| `contains` | string, address | Contains the text |
| `prefix` | string, address | Starts with the text |
| `suffix` | string, address | Ends with the text |
| `glob` | string, address | Matches a glob (see below) |
| `regex` | string, address | Matches an RE2 regular expression, anywhere in the value unless anchored with `^` and `$` |
| `cidr` | address | Lies in a network, or in any of a list of networks; IPv4 and IPv6 may be mixed |
| `gt`, `gte`, `lt`, `lte` | numeric | Greater than, at least, less than, at most |
| `not` | any | Inverts the operator object it wraps |
| `nocase: true` | string, address | Makes the string operators of that object ignore case |

```yaml
name: { eq: bash }
name: { in: [bash, sh, zsh] }
exe: { prefix: /tmp/, suffix: .sh }          # both must hold
cmdline: { contains: powershell, nocase: true }
remote_port: { gte: 8000, lte: 8999 }
remote_addr: { cidr: [10.0.0.0/8, "fd00::/8"] }
user: { not: { in: [root, admin] } }
```

### Shorthand

A bare value means `eq`, and a bare list means `in`:

```yaml
name: bash                 # same as { eq: bash }
remote_port: [80, 443]     # same as { in: [80, 443] }
user: { not: root }        # shorthand works inside not, too
```

### Globs

| Syntax | Matches |
|---|---|
| `*` | Any run of characters except `/` |
| `**` | Any run of characters, `/` included. `**/` also matches nothing, so `/a/**/b` matches `/a/b` |
| `?` | One character except `/` |
| `[abc]`, `[a-z]`, `[!0-9]` | One of (or, with `!`, none of) the listed characters |
| `\x` | The character `x` literally |

A glob must match the whole value. Because `\` escapes, write Windows paths
with a regex, or use `prefix`/`suffix`/`contains`, which take text literally.

### Missing values

A value is **missing** when it is empty, or when the event does not carry that
part at all (for example a `NETWORK_CONNECT` with no connection details).

- Among the positive operators only `eq: ""` matches a missing value.
- Every other operator is false for a missing value, so wrapping one in `not`
  makes it **true**. `user: { not: root }` matches a process whose user is
  unknown.
- To require that a value is present, use `{ not: { eq: "" } }`.
- A port of `0` on an event that has connection details is a real value, not a
  missing one.

### YAML quoting

Quote values that YAML would otherwise read as syntax: IPv6 networks
(`"::1/128"`), a lone `*` (`"*"`), and regexes or globs beginning with a
special character. Single quotes are safest for regexes: `'^\d+$'`.

---

## Exclusions

Exclusions suppress known-good activity without weakening the rule itself.

### Per pattern: `exclude`

A process matching an `exclude` entry **cannot fill the named role** in that
pattern. Other roles, and other patterns, are unaffected.

```yaml
exclude:
  - role: parent
    match:
      name: { in: [sshd, tmux] }
```

Because the role cannot be filled, no finding is formed and nothing is counted.

### Global: `exclusions`

A top-level exclusion **drops a finding** if any of the processes in it matches.
`rules` names the rules it applies to; `"*"` means every rule.

```yaml
exclusions:
  - rules: ["*"]
    match:
      exe: { prefix: /opt/monitoring/ }
    description: Monitoring agent
  - rules: [webshell-outbound, tmp-exec-network]
    match:
      user: deploy
```

Sentinel counts the findings each rule loses to global exclusions. `match` is a
process match block, as described above; an exclusion must have one, and must
list at least one rule.

---

## Rate limit

`max_findings_per_window` caps how many findings one rule produces in one
correlation window. The default is **20**.

A rule's window starts with its first finding. Once the rule reaches its limit,
further findings in that window are held back and counted. When the window
ends, Sentinel reports them as a single `INFO` finding:

```
rule webshell-outbound: 6 additional findings suppressed
```

Findings dropped by exclusions do not count towards the limit.

---

## Correlation window

The engine has a single correlation window of 5 minutes. It is not configurable
per pattern.

An event is **in the window** if it is strictly less than one window old. A
pattern matches only if every event it requires, for every role, is in the
window at the same moment. Consequently all events contributing to a finding
lie within one window of each other, and an event older than the window can
never contribute to one.

Timestamps are handled defensively: an event with no timestamp, or one dated
in the future, is treated as happening when Sentinel received it; an event
that is already a full window old when it arrives is ignored; and if the system
clock steps backwards, expired events are not revived.

### Processes and relationships

- Processes are identified by PID **and** start time. When a PID is reused, the
  new process does not inherit the previous one's events or children.
- An event that names a PID but carries no start time (the OS would not report
  one at that moment) is attributed to the process known to hold that PID.
- Sentinel learns about a process from any event that mentions it, and at
  startup from a list of the processes already running.
- The holder of a child's parent PID is accepted as its parent only if it
  started no later than the child and had not exited before the child started.
- An exited process stays available for one window after it exits, so a
  pattern through a parent that has already exited can still match.

Memory is bounded: only in-window events are kept, at most 64 events of each
type per process (the newest are kept).

---

## Suppression / deduplication

A finding is identified by its rule **and the set of processes involved**.
Once it has been reported, the same finding is not reported again until one
full correlation window has elapsed. A different set of processes matching the
same rule is a different finding and is reported straight away (subject to the
rate limit).

After the window, a finding is reported again only if the behavior is still
going on or has happened again.

Saving a pattern from an editor clears the suppression cache and the rate-limit
counters, so an updated pattern can fire immediately.

---

## Evidence

Every finding records what it is based on:

- **Roles:** which process filled each role of the rule, described as it was
  when the rule matched.
- **Previous images:** for a role whose process has replaced its program with
  `exec`, the programs it ran before (name, executable, command line, and when
  each was replaced), oldest first. The last four are kept.
- **Events:** the events of the rule's sequence, in step order; then one
  example of each event requirement; then up to 10 of the most recent events
  counted towards each threshold. At most 50 events are kept per finding, so
  this is a sample, not a full record.

The finding line in the Findings tab, the desktop app and the headless log
names the process in each role, for example
`(dropper=sh(4120) payload=x(4131))`. The full evidence is stored with the
finding in `sentinel.db`, in the `evidence` column of the `events` table, as
JSON. Findings stored by earlier versions have no evidence.

The JSON uses fixed snake_case keys:

```json
{
  "process": { "pid": 4131, "ppid": 4120, "start_time": "2026-10-10T15:30:42.67Z", "name": "x", "executable": "/tmp/x", "command_line": "/tmp/x", "user": "www-data" },
  "roles": { "payload": { "pid": 4131, "…": "…" } },
  "previous_images": { "payload": [ { "name": "sh", "executable": "/bin/dash", "command_line": "sh -c …", "replaced_at": "2026-10-10T15:30:42.67Z" } ] },
  "events": [ { "timestamp": "2026-10-10T15:30:37.098Z", "type": "FILE_CREATE", "process": { "…": "…" }, "file": { "pid": 4125, "path": "/tmp/x", "operation": "CREATE" } } ]
}
```

Evidence written before these keys were fixed used the Go field names
(`StartTime`, `CommandLine`, `RemoteAddress`, …). Those rows are still read
correctly; new rows are always written with the keys above.

---

## Limitations

- **Short-lived processes can be missed.** Processes and connections are found
  by polling every 2 seconds. A process that starts and exits between two
  polls is never seen, and neither is a connection opened and closed between
  two polls. A pattern cannot match on what Sentinel did not observe.
- **Events per process are capped.** Sentinel keeps the newest 64 events of
  each type per process inside the window. Thresholds are counted separately
  and are not affected. A **sequence** can be missed if a process produced
  more than 64 events of one type in the window and the event a step needed
  was among those discarded. Sentinel counts the evaluations where that may
  have happened.
- **Counters are capped.** At most 4096 threshold counters exist at once, one
  per requirement per process that could fill its role. Beyond that, further
  processes are not counted until idle counters are released, which happens
  one window after a counter's last matching event.
- **Walks down the process tree are capped.** Looking for descendants of one
  process visits at most 4096 processes. The search also works upwards from
  each candidate descendant, which has no such limit, so this matters only
  for a pattern whose ancestor role matches a process with a very large tree
  below it.
- **Ancestry needs every link.** `DESCENDANT` does not hold across a process
  Sentinel never saw, or one that exited more than a window ago.
- **Sequences use observation time.** See [Why a tolerance](#why-a-tolerance).
- **`within` and `count` have upper bounds:** the correlation window, and 1000.
- **Changing patterns resets counters.** A threshold starts counting when its
  pattern is loaded or saved.

Each cap that is hit is counted; the counts are available to the application
through the engine's metrics.

---

## Validation and errors

Sentinel checks every pattern when it loads the file.

**Unknown keys are errors.** A key that is not part of the schema, at any level
of a pattern or exclusion, rejects that entry and is reported with its path, so
a misspelling cannot silently change what a pattern means:

```
pattern[0] "webshell": processes[1].mach: unknown key (valid keys here: conditions, events, id, match)
```

An unknown key at the top level of the file (beside `patterns` and
`exclusions`) is reported as a warning and otherwise ignored.

**One bad pattern does not discard the file.** The valid patterns and
exclusions are loaded, and each rejected entry is reported with the pattern,
the role and the field at fault:

```
pattern[1] "webshell-outbound": role "shell": match.name: bad regex "(": error parsing regexp: missing closing ): `(`
pattern[2] "tmp-exec": role "proc": events[0] (NETWORK_CONNECT): where.domain: unknown field (valid fields: local_port, protocol, remote_addr, remote_port, state)
exclusions[0]: match.name: operator "cidr" is not valid for a string field
```

Where the errors appear:

- **Terminal UI:** printed at startup, and listed in a panel at the bottom of
  the Patterns tab.
- **Desktop app:** listed in the Patterns tab.
- **Headless:** logged as `PATTERN ERROR` lines at startup.

A rejected pattern is not active. It stays in the file exactly as written,
including when you save other patterns from an editor, so you can fix it.

If the file cannot be read at all, or is not valid YAML, Sentinel reports that
and runs with the built-in default pattern.

### What is rejected

| Problem | Example message |
|---|---|
| Unknown field | `match.colour: unknown field (valid fields: cmdline, exe, name, user)` |
| Field not valid for the event type | `events[0] (DNS_QUERY): where.remote_port: unknown field (valid fields: domain, query_type, resolver)` |
| `where` on an event type with no fields | `events[0] (SCRIPT_EXECUTION): where: SCRIPT_EXECUTION events have no fields to filter on` |
| Unknown operator | `match.name: unknown operator "like"` |
| Operator not valid for the field | `match.name: operator "cidr" is not valid for a string field` |
| Bad regex, glob or CIDR | `match.exe: bad glob "/tmp/[abc": unclosed character class` |
| Text where a number is needed | `where.remote_port: "eq" needs an integer, got "https"` |
| Empty `in` list or `any_of` | `match.name: "in" needs at least one value` |
| Empty operator object | `match.name: no operator given` |
| Unknown event type | `role "shell": events[1]: unknown event type "NETWORK_CONECT" (valid types: DNS_QUERY, FILE_CREATE, …)` |
| Unknown event type in a sequence | `sequence: steps[1]: unknown event type "PROCESS_RUN" (valid types: …)` |
| Duplicate role IDs | `duplicate role id "a"` |
| Relationship naming an unknown role | `relationship references unknown role "ghost"` |
| Two or more roles not all related | `role "c" is not part of any relationship` |
| `exclude` naming an unknown role | `exclude[0]: unknown role "ghost"` |
| Negative rate limit | `max_findings_per_window: must not be negative, got -3` |
| Unknown key | `processes[1].mach: unknown key (valid keys here: conditions, events, id, match)` |
| `max_depth` out of range, or on `SPAWNED` | `relationships[0]: max_depth must be between 1 and 16, got 17` |
| Bad `count` | `events[0] (DNS_QUERY): count must be at least 1, got -2` |
| `within` too long, or not a duration | `events[0] (DNS_QUERY): within must be more than 0 and at most the correlation window (5m0s), got 10m0s` |
| `within` with nothing to count | `events[0] (DNS_QUERY): within needs a count above 1 or distinct: one event is always within any span` |
| `distinct` on a field the event lacks | `events[0] (DNS_QUERY): distinct: "remote_port" is not a field of DNS_QUERY events (valid fields: domain, query_type, resolver)` |
| Sequence step with an unknown role | `sequence: steps[0]: unknown role "ghost"` |
| Unknown capture | `sequence: steps[1] (PROCESS_START): where.exe: reference $missing.path: unknown capture "missing"` |
| Capture used before it is defined | `sequence: steps[0] (PROCESS_START): where.exe: reference $dropped.path: capture "dropped" is defined by steps[1], after this step` |
| Field the captured event lacks | `sequence: steps[1] (PROCESS_START): where.exe: reference $dropped.domain: "domain" is not a field of the captured FILE_CREATE event (valid fields: old_path, path)` |
| Reference between different kinds | `sequence: steps[1] (PROCESS_START): where.exe: reference $conn.remote_port: a string field cannot be compared with a numeric field` |
| Duplicate capture name | `sequence: steps[1]: capture "f" is already defined by steps[0]` |
| Reference with an operator that cannot take one | `reference $dropped.path: "regex" cannot take a captured value; use eq, in, prefix, suffix or contains` |

A pattern with exactly one role and no relationships is valid and matches a
single process. A pattern with no roles (a new draft from an editor) loads, is
skipped by the engine, and never fires.

---

## Compatibility with v1

The original schema described a role with exact-match `conditions`:

```yaml
- id: child
  conditions:
    - type: PROCESS_NAME      # or PROCESS_USER
      value: python
  events:
    - type: NETWORK_CONNECT
```

This still loads and behaves exactly as before. Each condition is equivalent
to an `eq` predicate in a `match` block:

| v1 | v2 equivalent |
|---|---|
| `{ type: PROCESS_NAME, value: X }` | `name: { eq: X }` |
| `{ type: PROCESS_USER, value: X }` | `user: { eq: X }` |

A role may use `conditions` and `match` together; both must hold. A v1 file is
saved back byte for byte: nothing is rewritten into v2 form.

The built-in default pattern now uses a `match` block, so that it also catches
`python3`, `python3.12` and so on:

```yaml
- id: child
  match:
    name: { regex: '^python[0-9.]*$' }
```

If you already have a `configs/patterns.yaml`, it is left as it is; this change
only affects a file created fresh.

---

## Worked examples

These are illustrations, not shipped defaults. Tune the names, ports and lists
to your environment before relying on them.

### 1. Web server descendant shell with an outbound connection to a non-standard port

A shell whose parent is a web server or an application runtime under it,
connecting out to something other than web or DNS ports, to a public address.

```yaml
- name: webshell-outbound
  severity: HIGH
  title: Shell under a web server made an unusual outbound connection
  description: >-
    A shell spawned by a web server process connected to a public address on
    a port other than 80, 443 or 53.
  processes:
    - id: server
      match:
        name: { in: [nginx, apache2, httpd, php-fpm, node, java], nocase: true }
    - id: shell
      match:
        name: { regex: '^(ba|da|z|k)?sh$' }
      events:
        - type: NETWORK_CONNECT
          where:
            remote_port: { not: { in: [80, 443, 53] } }
            remote_addr:
              not:
                cidr: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, "::1/128", "fc00::/7"]
  relationships:
    - type: SPAWNED
      parent: server
      child: shell
  exclude:
    - role: shell
      match:
        cmdline: { contains: healthcheck }
```

`SPAWNED` is a direct parent–child link. To catch a shell two levels down
(`nginx → php-fpm → sh`), add a middle role and a second relationship.

### 2. A process running from `/tmp` or `/dev/shm` that makes a network connection

A single-role pattern: no relationship is needed.

```yaml
- name: tmp-exec-network
  severity: HIGH
  title: Program in a temporary directory made a network connection
  description: >-
    An executable located under /tmp, /var/tmp or /dev/shm opened a network
    connection.
  processes:
    - id: proc
      match:
        any_of:
          - exe: { glob: "/tmp/**" }
          - exe: { glob: "/var/tmp/**" }
          - exe: { prefix: /dev/shm/ }
      events:
        - type: NETWORK_CONNECT
          where:
            remote_addr: { not: { cidr: [127.0.0.0/8, "::1/128"] } }
  max_findings_per_window: 10
```

A process whose executable path could not be read has a missing `exe`; it
matches none of these alternatives, so it is not reported.

### 3. An interpreter querying a domain under a suspicious TLD list

```yaml
- name: interpreter-suspicious-tld
  severity: MEDIUM
  title: Script interpreter looked up a domain under a suspicious TLD
  description: >-
    A script interpreter resolved a domain whose top-level domain is on the
    watch list.
  processes:
    - id: interpreter
      match:
        name: { regex: '^(python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|php[0-9.]*|pwsh|powershell)$', nocase: true }
      events:
        - type: DNS_QUERY
          where:
            domain: { regex: '\.(top|xyz|click|zip|mov|tk|gq)\.?$', nocase: true }
```

The trailing `\.?` allows for a fully-qualified name ending in a dot. Paired
with a global exclusion, a known-good tool can be let through without touching
the rule:

```yaml
exclusions:
  - rules: [interpreter-suspicious-tld]
    match:
      cmdline: { contains: /opt/ci/runner.py }
    description: CI runner resolves customer test domains
```

---

### 4. Download and execute

Something downloads a file into `/tmp`, and the process that started the
download then runs exactly that file. This is what
`curl -o /tmp/x http://… ; chmod +x /tmp/x ; /tmp/x` looks like: the shell
(`launcher`) starts `curl` (`downloader`), which connects out and creates the
file, and then starts the file itself (`payload`).

```yaml
- name: download-and-execute
  severity: CRITICAL
  title: Downloaded file executed
  description: >-
    A process made a network connection and created a file under /tmp, and
    the process that started it then ran that file.
  processes:
    - id: launcher
    - id: downloader
    - id: payload
  relationships:
    - { type: SPAWNED, parent: launcher, child: downloader }
    - { type: SPAWNED, parent: launcher, child: payload }
  sequence:
    within: 60s
    steps:
      - { role: downloader, type: NETWORK_CONNECT }
      - role: downloader
        type: FILE_CREATE
        where: { path: { glob: "/tmp/**" } }
        capture: dropped
      - role: payload
        type: PROCESS_START
        where: { exe: { eq: $dropped.path } }
```

The capture is what makes this specific: a second child running `/usr/bin/id`
does not match, only one whose executable is the file just created. The
default `order_tolerance` matters here, because the connection is noticed by
polling, up to two seconds after it was made, and the file event is not.

Whether this fires on a real attack depends on how processes are collected.
A downloaded payload often runs for a few milliseconds. With the `ebpf`
process collector its `PROCESS_START` is reported whatever its lifetime; with
`poll` it is seen only if it is still running at the next two-second poll. See
[How processes are collected](#how-processes-are-collected).

Two variations are worth knowing:

- A program that downloads the file and runs it itself (a script using an HTTP
  library, say) has no separate downloader. Drop the `launcher` role, relate
  `downloader` to `payload` directly, and keep the same sequence.
- A shell given a list of commands may run the last one without forking, by
  exec'ing it in place. The payload is then the shell process itself, and
  what is reported is a `PROCESS_EXEC` on the `launcher`, not a
  `PROCESS_START` of a child. To cover that as well, add a second pattern
  whose last step is `{ role: launcher, type: PROCESS_EXEC, where: { exe: { eq: $dropped.path } } }`.

### 5. Shell at any depth below a web server, connecting to a non-standard port

Example 1 with `DESCENDANT`, so that `nginx → php-fpm → sh` is caught as well
as `nginx → sh`.

```yaml
- name: webshell-outbound-any-depth
  severity: HIGH
  title: Shell below a web server made an unusual outbound connection
  description: >-
    A shell up to four generations below a web server connected to a public
    address on a port other than 80, 443 or 53.
  processes:
    - id: web
      match:
        name: { in: [nginx, apache2, httpd, caddy], nocase: true }
    - id: shell
      match:
        name: { regex: '^(ba|da|z|k)?sh$' }
      events:
        - type: NETWORK_CONNECT
          where:
            remote_port: { not: { in: [80, 443, 53] } }
            remote_addr:
              not:
                cidr: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, "::1/128", "fc00::/7"]
  relationships:
    - { type: DESCENDANT, parent: web, child: shell, max_depth: 4 }
```

### 6. DNS tunnelling

One process looking up at least 100 different names under one parent domain
within a minute.

```yaml
- name: dns-tunnelling
  severity: HIGH
  title: Many distinct subdomains of one domain queried
  description: >-
    A single process looked up 100 or more different names under
    tunnel.example within 60 seconds.
  processes:
    - id: client
      events:
        - type: DNS_QUERY
          count: 100
          within: 60s
          distinct: domain
          where:
            domain: { suffix: .tunnel.example }
  max_findings_per_window: 5
```

The parent domain has to be named in `where`: a threshold counts distinct
values for one process, and does not group them by parent domain on its own.
Without the `where`, the rule becomes "100 distinct domains of any kind in a
minute", which a browser can reach; pair that form with an exclusion.

### 7. Interpreter writes to a persistence path soon after connecting out

```yaml
- name: interpreter-persistence-after-connect
  severity: HIGH
  title: Interpreter wrote a persistence file after a network connection
  description: >-
    A script interpreter created a file in a location used for persistence
    within 30 seconds of making a network connection.
  processes:
    - id: interp
      match:
        name: { regex: '^(python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|php[0-9.]*)$' }
  sequence:
    within: 30s
    steps:
      - role: interp
        type: NETWORK_CONNECT
        where:
          remote_addr: { not: { cidr: [127.0.0.0/8, "::1/128"] } }
      - role: interp
        type: FILE_CREATE
        where:
          any_of:
            - path: { prefix: /etc/cron }
            - path: { glob: "/etc/systemd/system/**" }
            - path: { glob: "/home/*/.config/autostart/**" }
            - path: { suffix: /.bashrc }
            - path: { glob: "/Library/LaunchDaemons/**" }
```

A step has one event type, so this covers files being created. For files being
changed, add a second pattern with `FILE_MODIFY`. The sequence asks for *a*
connection followed within 30 seconds by the write; it cannot ask for the
process's first connection specifically.

---

## Using the TUI pattern editor (tab 6)

Press `6` (or `→` to cycle to the Patterns tab).

```
┌── Pattern List ─────────┐  ┌── Edit Pattern ──────────────────────────┐
│> network-active-parent  │  │ Name:        [________________________]  │
│  my-custom-rule         │  │ Severity:    [MEDIUM ▾]                   │
│                         │  │ Title:       [________________________]  │
│                         │  │ Description: [________________________]  │
│  [N]ew  [D]elete        │  │ Processes:   parent, child    [Edit]     │
│                         │  │ Relationships: parent→child   [Edit]     │
│                         │  │ [Save]  [Cancel]                         │
└─────────────────────────┘  └──────────────────────────────────────────┘
```

### Creating a new pattern

1. Press `N` with focus on the list → a blank pattern named `new-pattern` is
   added and selected.
2. Fill in **Name**, **Severity**, **Title**, and **Description** in the right
   form. Use `Tab` to move between fields.
3. Press **Edit Processes** to define the process roles.
4. Press **Edit Relationships** to wire the roles together.
5. Press **Save** — the file is written atomically and the correlation engine
   picks up the new pattern immediately (no restart needed).

### Editing processes

Inside the process editor, each row shows a role ID with its conditions and
event requirements summarised.

| Key | Action |
|---|---|
| `A` | Add a new role |
| `E` | Edit the selected role (opens the role detail form) |
| `D` | Delete the selected role |
| `Esc` | Return to the pattern form |

In the role detail form you can:
- Change the **ID** (must be unique within the pattern).
- **Add Condition** — opens a small form to pick the condition type and value.
- **Remove Last Condition** — deletes the most recently added condition.
- Pick an event type from the dropdown and press **Add Event** to add a
  required event type.
- **Remove Last Event** — deletes the most recently added event requirement.
- Press **Done** or `Esc` to return.

### Editing relationships

Inside the relationship editor each row shows `TYPE  parent → child`.

| Key | Action |
|---|---|
| `A` | Add a new relationship |
| `E` | Edit the selected relationship |
| `D` | Delete the selected relationship |
| `Esc` | Return to the pattern form |

In the relationship detail form, use the **Parent** and **Child** dropdowns —
they are populated from the role IDs you defined in the process editor.

### Deleting a pattern

Select the pattern in the list, press `D`, confirm with **OK**. The file is
saved automatically.

### Navigation summary

| Key | Scope | Action |
|---|---|---|
| `1`–`6` | Global | Switch to that tab |
| `←` / `→` | Global | Cycle tabs |
| `↑` / `↓` | List | Move selection |
| `N` | List focused | New pattern |
| `D` | List focused | Delete selected pattern |
| `Tab` | Pattern form | Move between fields |
| `Esc` | Sub-editor | Return to parent screen |
| `A` / `E` / `D` | Sub-editor list | Add / Edit / Delete |

### Advanced fields in the editors

The TUI and desktop editors edit the basic parts of a pattern: name, severity,
title, description, roles with v1 conditions and bare event types, and
`SPAWNED` relationships. They do **not** edit `match` blocks, `where` filters,
thresholds (`count`, `within`, `distinct`), `DESCENDANT` relationships and
`max_depth`, `sequence`, `exclude`, `max_findings_per_window` or the top-level
`exclusions`.

A pattern or role that uses any of these is marked with `⚙` and the note
"advanced fields — edit in YAML". Saving such a pattern from an editor keeps
those parts exactly as they are; so are the top-level exclusions and any
pattern that failed to load. Removing an event in the TUI process editor
removes that event's `where` filter with it.

