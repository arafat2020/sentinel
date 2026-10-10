// Package correlation matches behavioral patterns against recent process
// activity.
//
// # Matching
//
// A pattern names roles and the relationships between them. A match is an
// assignment of one process to each role such that:
//
//   - every role is bound to a different process;
//   - each process meets its role's conditions and has produced every event
//     type the role requires, inside the window;
//   - every relationship in the pattern holds between the bound processes.
//
// All of a pattern's relationships must hold at once, and a role that
// appears in several relationships is the same process in each of them: the
// chain a→b→c needs one b that is both a child of a and the parent of c.
//
// A pattern with one role and no relationships matches a single process. A
// pattern with several roles must relate every one of them; see
// [BehaviorPattern.Validate]. A pattern that fails validation never matches.
//
// A role that lists no events places no requirement on activity.
//
// # Time
//
// The engine reads the time from a clock, the wall clock unless [WithClock]
// says otherwise. Engine time never moves backwards: a reading earlier than
// one already seen is treated as that later time, so a clock step cannot
// revive expired state.
//
// Each event is stored with an effective timestamp:
//
//   - a missing (zero) timestamp becomes the time the event was received;
//   - a timestamp later than the time it was received is clamped to that
//     time, because an event cannot be observed before it happens;
//   - an event that is already a full window old on arrival is not stored.
//
// Events of one process are kept in timestamp order; events with equal
// timestamps keep their arrival order.
//
// # Window
//
// The engine has one window W, given to [NewEngine]. At time T an event is
// in the window when its effective timestamp ts satisfies
//
//	T - W < ts <= T
//
// that is, it is strictly less than W old. Only in-window events can satisfy
// a role, so all the events behind a match lie within W of each other. A
// non-positive window contains nothing.
//
// # Processes and identity
//
// A process is identified by PID and start time, never by PID alone. The
// engine learns of a process from any event that names it, or from
// [Engine.Seed], which registers processes that were already running.
//
// When a process is first seen it is linked to its parent if the parent is
// known, and any already-known processes waiting for a parent with its PID
// are linked to it. The holder of the parent PID is accepted as the parent
// only if it started no later than the child and had not exited before the
// child started. A process therefore has at most one parent, and a reused
// PID does not connect a child to an earlier or later holder.
//
// Seeing a second process with a PID means the first has ended, whether or
// not its exit event has arrived. Children that started after the new holder
// are attributed to it.
//
// # Retention
//
// An exited process is kept as a tombstone for one window after its exit, so
// patterns that pass through it can still match; then it is evicted together
// with its events and relationships. State is bounded as follows:
//
//   - events: only in-window events, and at most [MaxEventsPerType] of each
//     event type per process (the newest win);
//   - processes: those running, plus tombstones less than one window old;
//   - relationships: at most one per process, removed with either end;
//   - suppression records: one per finding, for one window.
//
// A sweep releases expired state periodically, by elapsed time or event
// count. Matching never depends on a sweep having run.
//
// # Findings and suppression
//
// A finding is identified by its rule and the set of processes bound to the
// rule's roles, and carries those processes as evidence in role order. The
// same finding is not emitted again until one window after it was last
// emitted. A different set of processes matching the same rule is a
// different finding.
//
// # Evaluation
//
// [Engine.DetectBehaviors] looks only for matches that include a process
// that has changed since the previous call, or whose finding has just come
// out of suppression. Nothing else can have become reportable: time passing
// only removes events from the window. The result is the same as evaluating
// every pattern against every process each time.
package correlation
