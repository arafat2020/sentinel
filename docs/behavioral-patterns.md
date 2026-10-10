# Behavioral Patterns — Definition Guide

Sentinel detects suspicious behavior by matching **behavioral patterns** against
the live stream of telemetry events. Patterns are stored in
`configs/patterns.yaml` and can be edited either directly in that file or
interactively through the **Patterns tab** (key `6`) in the TUI.

---

## Concepts

### Pattern

A pattern is a named rule that fires a finding when a specific combination of
processes, conditions, and relationships is observed within the correlation
window (default: 5 minutes).

### Process role

Each pattern defines one or more **process roles** (e.g. `parent`, `child`).
A role is an abstract slot that matches a real running process if all of its
conditions are satisfied and all of its required event types have been seen in
that process's event chain **inside the correlation window** (see
[Correlation window](#correlation-window)). Each role is filled by a different
process.

### Condition

A condition narrows which real processes can fill a role. Currently two
condition types are supported:

| Type | Meaning |
|---|---|
| `PROCESS_NAME` | The process's short name (e.g. `python`, `bash`, `node`) |
| `PROCESS_USER` | The username that owns the process (e.g. `root`, `www-data`) |

A role with **no conditions** matches any process.

### Event requirement

An event requirement says "this role can only be filled by a process that has
produced at least one event of this type". Available event types:

| Event type | When it fires |
|---|---|
| `PROCESS_START` | A new process was created |
| `PROCESS_EXIT` | A process terminated |
| `NETWORK_CONNECT` | A process opened a new outbound/inbound connection |
| `NETWORK_CLOSE` | A network connection was closed |
| `FILE_CREATE` | A file was created |
| `FILE_MODIFY` | A file was written to |
| `FILE_DELETE` | A file was deleted |
| `FILE_RENAME` | A file was renamed or moved |
| `DNS_QUERY` | A process made a DNS lookup |
| `PERSISTENCE_CHANGE` | A persistence mechanism changed (planned) |
| `SCRIPT_EXECUTION` | A script was executed (planned) |

### Relationship

A relationship links two roles. Currently only `SPAWNED` is supported — it
means "the process filling `parent` must have directly spawned the process
filling `child`".

---

## YAML format

`configs/patterns.yaml` has a single top-level key `patterns` that holds a
list of pattern definitions.

```yaml
patterns:
  - name: unique-kebab-case-id     # required, unique across all patterns
    severity: MEDIUM               # INFO | LOW | MEDIUM | HIGH | CRITICAL
    title: Short human title
    description: Longer explanation shown in the Findings tab.
    processes:
      - id: parent                 # role name, referenced by relationships
        conditions:                # empty list = match any process
          - type: PROCESS_NAME
            value: node
        events:
          - type: NETWORK_CONNECT  # parent must have had at least one NETWORK_CONNECT
      - id: child
        conditions:
          - type: PROCESS_NAME
            value: python
          - type: PROCESS_USER
            value: root
        events:
          - type: NETWORK_CONNECT
          - type: DNS_QUERY        # child must have had NETWORK_CONNECT AND DNS_QUERY
    relationships:
      - type: SPAWNED
        parent: parent             # references processes[].id
        child: child
```

### Severity levels

`INFO` → `LOW` → `MEDIUM` → `HIGH` → `CRITICAL` (shown in the Findings tab
color-coded in red).

### Multiple conditions on one role

All conditions on a role must be satisfied simultaneously (AND logic). There
is currently no OR within a role — to express OR, define two separate patterns.

### Multiple event requirements on one role

All required event types must appear in the process's event chain inside the
correlation window (AND logic). The events do not need to appear in any
particular order. A role with no event requirements places no demand on
activity.

### Multiple relationships

A pattern can have more than one relationship entry, allowing three-process or
deeper chain matching:

```yaml
processes:
  - id: a
    conditions: []
    events: [{ type: NETWORK_CONNECT }]
  - id: b
    conditions:
      - { type: PROCESS_NAME, value: python }
    events: [{ type: PROCESS_START }]
  - id: c
    conditions:
      - { type: PROCESS_NAME, value: bash }
    events: [{ type: FILE_CREATE }]
relationships:
  - { type: SPAWNED, parent: a, child: b }
  - { type: SPAWNED, parent: b, child: c }
```

This fires when `a` spawns `b` which in turn spawns `c`.

**Every** relationship in the pattern must hold, and a role that appears in
more than one relationship is the same process in each: here `b` must be one
process that is both a child of `a` and the parent of `c`. `a` spawning one
python while a different python spawns bash does not match.

### Structural rules

Sentinel refuses to load a patterns file containing a pattern that breaks any
of these rules, and reports which pattern and why:

- Role IDs must be unique within a pattern.
- A relationship may only reference role IDs defined in the same pattern.
- A pattern with two or more roles must relate them: every role has to appear
  in at least one relationship. Unrelated roles would match any combination of
  processes.
- A role cannot be its own parent.

A pattern with exactly one role and no relationships is valid and matches a
single process. A pattern with no roles yet (a new draft from the editor) loads
but never fires.

If the file fails to load at startup, Sentinel prints the error and runs with
the built-in default pattern; the file itself is left untouched.

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

---

## Correlation window

The engine has a single correlation window, 5 minutes in the shipped
configuration. It is not configurable per pattern.

An event is **in the window** if it is strictly less than one window old. A
pattern matches only if every event it requires, for every role, is in the
window at the same moment. Consequences:

- All events contributing to a finding lie within one window of each other.
- An event older than the window can never contribute to a finding, however
  long Sentinel has been running.

Timestamps are handled defensively: an event with no timestamp, or one dated
in the future, is treated as happening when Sentinel received it; an event
that is already a full window old when it arrives is ignored; and if the system
clock steps backwards, expired events are not revived.

### Processes and relationships

- Processes are identified by PID **and** start time. When a PID is reused, the
  new process does not inherit the previous one's events or children.
- Sentinel learns about a process from any event that mentions it, and at
  startup from a list of the processes already running. A process that was
  running before Sentinel started can therefore be recognised as a parent.
- The holder of a child's parent PID is accepted as its parent only if it
  started no later than the child and had not exited before the child started.
- An exited process stays available for one window after it exits, so a
  pattern through a parent that has already exited can still match. After
  that it is forgotten along with its events and relationships.

Memory is bounded: only in-window events are kept, at most 64 events of each
type per process (the newest are kept).

---

## Suppression / deduplication

A finding is identified by its rule **and the set of processes involved**.
Once it has been reported, the same finding is not reported again until one
full **correlation window** (5 minutes by default) has elapsed. This prevents
a single sustained behaviour from flooding the Findings tab.

A different set of processes matching the same rule is a different finding and
is reported straight away. A broad pattern (few conditions) can therefore
produce one finding per matching set of processes.

After the window, a finding is reported again only if the behaviour is still
going on or has happened again.

Each finding records the processes that matched, in the order the pattern
lists its roles.

Editing and saving a pattern via the TUI clears the suppression cache, so the
updated pattern can fire immediately.

---

## Example patterns

### Any process spawning a shell

```yaml
- name: any-process-spawns-shell
  severity: HIGH
  title: Process spawned an interactive shell
  description: A process spawned bash or sh, which may indicate command injection.
  processes:
    - id: parent
      conditions: []
      events: []
    - id: child
      conditions:
        - type: PROCESS_NAME
          value: bash
      events: []
  relationships:
    - type: SPAWNED
      parent: parent
      child: child
```

### Root process making DNS queries

```yaml
- name: root-dns-lookup
  severity: LOW
  title: Root process made a DNS query
  description: A process running as root resolved a domain name.
  processes:
    - id: proc
      conditions:
        - type: PROCESS_USER
          value: root
      events:
        - type: DNS_QUERY
  relationships: []
```

### Web server spawning a script interpreter

```yaml
- name: webserver-spawns-interpreter
  severity: HIGH
  title: Web server spawned a script interpreter
  description: nginx or apache spawned Python or Perl, a classic web shell indicator.
  processes:
    - id: server
      conditions:
        - type: PROCESS_NAME
          value: nginx
      events:
        - type: NETWORK_CONNECT
    - id: interpreter
      conditions:
        - type: PROCESS_NAME
          value: python
      events: []
  relationships:
    - type: SPAWNED
      parent: server
      child: interpreter
```
