// Package correlation matches behavioral patterns against recent process
// activity.
//
// # Time model
//
// The engine works on an explicit evaluation time, supplied to
// [Engine.ProcessAt] and [Engine.DetectBehaviorsAt] ([Engine.Process] and
// [Engine.DetectBehaviors] use the wall clock). Evaluation time never moves
// backwards: a time earlier than one already seen is treated as that later
// time, so a clock step cannot resurrect expired state.
//
// Each event is stored with an effective timestamp:
//
//   - a missing (zero) timestamp becomes the time the event was received;
//   - a timestamp later than the time it was received is clamped to that
//     time, because an event cannot be observed before it happens;
//   - an event that is already a full window old on arrival is not stored.
//
// Events of one process are kept in timestamp order; events with equal
// timestamps keep their arrival order. Late-arriving events are inserted in
// their proper place.
//
// # Window
//
// The engine has one window W, given to [NewEngine]. At evaluation time T an
// event is "in the window" when its effective timestamp ts satisfies
//
//	T - W < ts <= T
//
// that is, it is strictly less than W old. A pattern matches at T only if
// every event it requires, for every process it names, is in the window at T.
// All required events are therefore within W of each other, and an event
// outside the window can never contribute to a match. A non-positive window
// contains nothing, so nothing matches.
//
// # Event requirements
//
// By default a process pattern's event list is a set of requirements: each
// listed type must occur at least once in the window, in any order, and
// listing a type twice is the same as listing it once.
//
// A process pattern with Ordered set requires its events as a sequence: the
// in-window events of that process must contain the listed types in the
// listed order, not necessarily adjacently, each matched by a distinct event.
// Ordering is evaluated per process; it says nothing about the order of
// events between a parent and its child.
//
// A process pattern that lists no events places no requirement on activity
// and is satisfied by any process meeting its conditions.
//
// # Relationships and process identity
//
// A SPAWNED relationship is recorded when a process start event arrives and
// its parent PID belongs to a process the engine has seen start and not yet
// exit. Processes are identified by PID and start time, never by PID alone:
//
//   - a process exit removes that process, and only that process, from the
//     table used to resolve parents;
//   - a start event for a PID held by a different process means the earlier
//     holder is gone, and any child that started after the new holder is
//     re-attributed to it;
//   - a candidate parent that started after the child is rejected.
//
// A relationship is structural: it does not expire while the child is alive,
// however long ago the spawn happened. It is dropped one window after the
// child exits, once none of the child's events can still be in the window.
//
// # Retention
//
// State is bounded as follows:
//
//   - events: only in-window events are kept, and at most
//     [MaxEventsPerType] of each event type per process (the newest win);
//   - processes: only those seen starting and not yet exited;
//   - relationships: one per child, for live children and children that
//     exited less than one window ago;
//   - suppression records: one per rule, dropped after one window.
//
// # Suppression
//
// A rule that produced a finding at time T produces no further finding until
// T + W, whichever processes match. With the window semantics above, the
// events behind a finding have all left the window by then, so a rule fires
// again only if the behaviour continues or recurs.
package correlation
