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

A relationship links two roles. Only `SPAWNED` is supported: the process
filling `parent` directly spawned the process filling `child`.

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
| `PROCESS_START` | A new process was created | none |
| `PROCESS_EXIT` | A process terminated | none |
| `PERSISTENCE_CHANGE` | (planned) | none |
| `SCRIPT_EXECUTION` | (planned) | none |

Field kinds decide which operators apply:

| Kind | Fields |
|---|---|
| String | `name`, `exe`, `cmdline`, `user`, `protocol`, `state`, `domain`, `query_type`, `path`, `old_path` |
| Address | `remote_addr`, `resolver` |
| Numeric | `remote_port`, `local_port` |

Using a field that does not belong to the event type, or `where` on an event
type with no fields, is an error.

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

## Validation and errors

Sentinel checks every pattern when it loads the file.

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
| `where` on an event type with no fields | `events[0] (PROCESS_START): where: PROCESS_START events have no fields to filter on` |
| Unknown operator | `match.name: unknown operator "like"` |
| Operator not valid for the field | `match.name: operator "cidr" is not valid for a string field` |
| Bad regex, glob or CIDR | `match.exe: bad glob "/tmp/[abc": unclosed character class` |
| Text where a number is needed | `where.remote_port: "eq" needs an integer, got "https"` |
| Empty `in` list or `any_of` | `match.name: "in" needs at least one value` |
| Empty operator object | `match.name: no operator given` |
| Duplicate role IDs | `duplicate role id "a"` |
| Relationship naming an unknown role | `relationship references unknown role "ghost"` |
| Two or more roles not all related | `role "c" is not part of any relationship` |
| `exclude` naming an unknown role | `exclude[0]: unknown role "ghost"` |
| Negative rate limit | `max_findings_per_window: must not be negative, got -3` |

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
relationships. They do **not** edit `match` blocks, `where` filters, `exclude`,
`max_findings_per_window` or the top-level `exclusions`.

A pattern or role that uses any of these is marked with `⚙` and the note
"advanced fields — edit in YAML". Saving such a pattern from an editor keeps
those parts exactly as they are; so are the top-level exclusions and any
pattern that failed to load. Removing an event in the TUI process editor
removes that event's `where` filter with it.

