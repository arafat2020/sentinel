# Sentinel Event Bus Architecture

## Overview

Sentinel uses an **asynchronous, bounded Event Bus** to decouple telemetry producers from telemetry consumers.

The Event Bus sits between OS/telemetry collectors and the rest of Sentinel:

```text
                 SENTINEL
                     │
        ┌────────────┴────────────┐
        │     Telemetry Sources   │
        └────────────┬────────────┘
                     │
              normalized events
                     │
                     ▼
              ┌─────────────┐
              │  Event Bus  │
              │             │
              │ bounded     │
              │ queue       │
              │     │       │
              │     ▼       │
              │   worker    │
              └─────┬───────┘
                    │
          ┌─────────┼──────────┐
          ▼         ▼          ▼
      Detection   Storage   Logging/API
```

The primary goals are:

- Decouple producers and consumers
- Prevent producers from being tied to handler execution time
- Provide bounded memory usage
- Apply backpressure instead of silently losing telemetry
- Support graceful shutdown
- Prevent blocked publishers from hanging forever during shutdown
- Provide predictable and testable concurrency semantics

---

# 1. Why Sentinel Needs an Event Bus

Without an Event Bus, a process monitor might directly call detection logic:

```text
Process Monitor
      │
      ▼
Detection
```

This creates tight coupling.

If detection becomes slow, the monitor becomes slow too.

With the Event Bus:

```text
Process Monitor
      │
      ▼
   Publish()
      │
      ▼
 ┌───────────┐
 │ Event Bus │
 └─────┬─────┘
       │
       ▼
   Detection
```

The producer only needs to know how to publish an event.

It does not need to know:

- how many consumers exist
- how expensive detection is
- where events are stored
- whether another consumer is logging them
- whether future consumers are added

The Event Bus therefore becomes a **decoupling boundary**.

---

# 2. Current Bus Structure

The current conceptual structure is:

```go
type Bus struct {
    events   chan core.Event
    handlers []Handler

    mu     sync.RWMutex
    closed bool
    done   chan struct{}
}
```

Each field has a specific responsibility.

## `events`

```go
events chan core.Event
```

This is the bounded event queue.

For example:

```go
bus := New(1000)
```

means the queue can contain up to 1000 events waiting to be processed.

The queue is deliberately bounded.

An unbounded queue could allow a producer to continuously generate events and consume unlimited memory.

---

# 3. Why the Queue Is Bounded

Suppose Sentinel receives telemetry faster than consumers can process it.

```text
Producer rate:
1000 events/sec

Consumer rate:
100 events/sec
```

With an unbounded queue:

```text
1000 events/sec in
100 events/sec out

queue:
10
20
30
40
...
100000
...
```

Memory usage can eventually become dangerous.

With a bounded queue:

```text
Producer
   │
   ▼
┌───────────────┐
│ [event][event]│
└───────────────┘
        │
        ▼
     Worker
```

Once the queue is full, producers experience **backpressure**.

For Sentinel's security telemetry, the initial policy is:

> Block the producer rather than silently dropping telemetry.

This is preferable to silently losing potentially important security evidence.

---

# 4. Asynchronous Processing

The Event Bus has a worker goroutine.

Conceptually:

```text
Publish()
   │
   ▼
events channel
   │
   ▼
worker goroutine
   │
   ▼
handlers
```

`Publish()` does not execute handlers directly.

Instead, it places the event into the queue.

The worker later receives it and executes the handlers.

This separates:

```text
Producer execution
```

from:

```text
Consumer execution
```

---

# 5. Why Not Start a Goroutine Per Event?

A tempting implementation is:

```go
go handler(event)
```

for every event.

This looks asynchronous, but it creates an unbounded concurrency problem.

If Sentinel receives:

```text
100,000 events
```

it could potentially create:

```text
100,000 goroutines
```

That can cause:

- Memory pressure
- Scheduler overhead
- Unpredictable execution
- Difficult shutdown behavior
- Loss of ordering guarantees
- Harder resource management

The bounded queue + worker architecture gives us controlled concurrency:

```text
Many producers
      │
      ▼
 bounded queue
      │
      ▼
 controlled worker(s)
      │
      ▼
 consumers
```

---

# 6. Subscription Model

The Event Bus supports multiple handlers:

```go
bus.Subscribe(handler1)
bus.Subscribe(handler2)
bus.Subscribe(handler3)
```

When an event is processed:

```text
                  Event
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
       Handler1  Handler2  Handler3
```

Each handler receives the same event.

This allows Sentinel to eventually have consumers such as:

```text
Event Bus
   │
   ├── Detection Engine
   ├── Event Storage
   ├── Audit Logger
   ├── Metrics
   └── API/WebSocket publisher
```

The producer does not need to know any of these consumers exist.

---

# 7. Backpressure

Backpressure is one of the most important properties of this architecture.

Suppose:

```text
Queue capacity = 1
```

The worker is currently processing event 1:

```text
Worker → Event 1
          │
          ▼
       Handler
       BLOCKED
```

The queue can now contain event 2:

```text
queue:
[event2]
```

A producer attempting to publish event 3 has nowhere to put it:

```text
Publish(event3)
      │
      ▼
    BLOCKED
```

This is intentional.

The system is effectively saying:

> "The consumer is falling behind. Slow down the producer instead of silently losing data."

This is called **backpressure**.

---

# 8. Why Sentinel Initially Blocks Instead of Dropping

There are several possible policies when the queue is full.

### Drop newest

```text
queue full
   │
   └── discard new event
```

### Drop oldest

```text
queue full
   │
   └── discard old event
```

### Overwrite

```text
queue full
   │
   └── replace existing event
```

### Block producer

```text
queue full
   │
   └── producer waits
```

Sentinel currently chooses:

```text
BLOCK PRODUCER
```

because security telemetry can be evidence.

For example, losing:

```text
PROCESS_START
```

could make a later:

```text
NETWORK_CONNECT
```

much harder to correlate.

A future Sentinel implementation may introduce priority-aware policies:

```text
Critical security event
        ↓
must not drop

Normal telemetry
        ↓
may be sampled/dropped under pressure
```

But this should be introduced deliberately rather than prematurely.

---

# 9. Graceful Shutdown

Shutdown is more complicated than simply stopping the worker.

Consider:

```text
Queue:
[event1][event2][event3]
```

If shutdown immediately terminates the worker:

```text
Shutdown
   │
   ▼
worker stops

event1
event2
event3
```

those events are lost.

Instead, Sentinel should drain already accepted events:

```text
Shutdown
   │
   ▼
stop accepting new work
   │
   ▼
process queued events
   │
   ▼
queue empty
   │
   ▼
worker exits
```

This is called **graceful draining**.

---

# 10. The `done` Channel

The Bus contains:

```go
done chan struct{}
```

This channel represents the shutdown signal.

When shutdown begins:

```go
close(b.done)
```

Closing the channel wakes goroutines waiting on:

```go
case <-b.done:
```

This is particularly important for blocked publishers.

---

# 11. The Critical Shutdown Deadlock

The first implementation had a subtle concurrency bug:

```go
func (b *Bus) Publish(event core.Event) bool {
    b.mu.RLock()
    defer b.mu.RUnlock()

    if b.closed {
        return false
    }

    b.events <- event
    return true
}
```

This looks reasonable but is dangerous.

Imagine:

```text
Queue full
```

Then:

```text
Publish()
   │
   ├── acquires RLock
   │
   └── blocks sending to queue
```

Now another goroutine calls:

```text
Shutdown()
   │
   └── wants Lock
```

But the publisher still owns the read lock.

Therefore:

```text
Publish
  waits for queue space

Shutdown
  waits for Publish to release RLock

Neither can progress
```

This is a **deadlock**.

---

# 12. The Important Mutex Rule

The lesson is:

> **Never hold a mutex while performing a potentially blocking operation unless the design explicitly requires it.**

A channel send can block.

Therefore the mutex must not remain held during:

```go
b.events <- event
```

The improved structure is:

```go
b.mu.RLock()

if b.closed {
    b.mu.RUnlock()
    return false
}

b.mu.RUnlock()

select {
case b.events <- event:
    return true

case <-b.done:
    return false
}
```

Now the potentially blocking operation happens after the mutex has been released.

---

# 13. Why `select` Matters

This is the critical part:

```go
select {
case b.events <- event:
    return true

case <-b.done:
    return false
}
```

There are two possible outcomes.

### Queue becomes available

```text
events channel ready
       ↓
Publish succeeds
       ↓
true
```

### Shutdown occurs

```text
done channel closes
       ↓
Publish wakes up
       ↓
false
```

Therefore a publisher waiting because the queue is full does not remain blocked forever.

---

# 14. Publish Contract

The API is:

```go
func (b *Bus) Publish(event core.Event) bool
```

The return value means:

```text
true
    Event was accepted.

false
    Bus has been shut down or shutdown won the race.
```

This is better than:

```go
func (b *Bus) Publish(event core.Event)
```

because callers can know whether their event was accepted.

For Sentinel:

```go
if !bus.Publish(event) {
    // Bus is shutting down.
}
```

---

# 15. Shutdown Idempotency

Shutdown should be safe to call multiple times:

```go
bus.Shutdown()
bus.Shutdown()
bus.Shutdown()
```

Only the first call should transition the bus.

The `closed` state protects this:

```go
if b.closed {
    b.mu.Unlock()
    return
}

b.closed = true
close(b.done)
```

This property is called **idempotency**.

It is important because shutdown can sometimes be triggered by multiple paths:

```text
OS signal
   │
   ├── main shutdown path
   │
   └── error recovery path
```

Neither should cause:

```text
close of closed channel
```

or another lifecycle failure.

---

# 16. Concurrent Publish and Shutdown

There is an unavoidable concurrency question:

```text
Publish()              Shutdown()
    │                      │
    ├──────────────────────┤
             race
```

Sentinel defines the behavior as:

> A publisher racing with shutdown may either be accepted or rejected, but it must never remain blocked forever.

Therefore:

```text
Publish starts before shutdown
        ↓
may return true

Publish starts after shutdown
        ↓
must return false
```

For a publish that overlaps exactly with shutdown, either outcome can be valid depending on which operation wins the race.

The important properties are:

```text
NO DEADLOCK
NO PERMANENT BLOCK
```

---

# 17. Current State Model

Conceptually the Event Bus has these states:

```text
                 New()
                   │
                   ▼
               RUNNING
                   │
                   │ Shutdown()
                   ▼
              SHUTTING DOWN
                   │
                   │ drain queue
                   ▼
                STOPPED
```

The important transition is:

```text
RUNNING → SHUTTING DOWN
```

After this transition:

```text
new Publish()
     ↓
rejected
```

while already accepted events can continue being processed.

---

# 18. Current Event Flow

For Sentinel today:

```text
macOS Process Collector
          │
          ▼
    Process Snapshot
          │
          ▼
  Lifecycle Detector
          │
          ▼
   PROCESS_START /
   PROCESS_EXIT
          │
          ▼
       Publish()
          │
          ▼
   ┌──────────────┐
   │  Event Bus   │
   │              │
   │ bounded      │
   │ queue        │
   └──────┬───────┘
          │
          ▼
       Worker
          │
          ▼
      Handlers
```

Later:

```text
Process Collector ─────┐
                       │
Network Collector ─────┤
                       │
DNS Collector ─────────┤
                       │
Filesystem Collector ──┤
                       │
Persistence Collector ─┤
                       │
                       ▼
                  Event Bus
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
      Detection     Storage      Logging
```

---

# 19. Why This Architecture Is Useful for Security Detection

The Event Bus provides the stream on which behavioral correlation can operate.

For example:

```text
PROCESS_START
      │
      ▼
node
      │
      ▼
NETWORK_CONNECT
      │
      ▼
DNS_QUERY
      │
      ▼
SCRIPT_EXECUTION
```

The Detection Engine can eventually correlate these events.

Instead of asking:

> "Is this process malware?"

Sentinel can ask:

> "Does this sequence of behaviors represent suspicious activity?"

That is much closer to the behavioral detection model Sentinel is designed to use.

---

# 20. Testing Strategy

The Event Bus has tests for several important properties.

## Basic publishing

Verify that an event reaches a handler.

```text
Publish
   ↓
Handler receives event
```

## Multiple handlers

Verify that one event reaches all subscribed handlers.

```text
Event
 ├── Handler 1
 ├── Handler 2
 └── Handler 3
```

## Backpressure

Verify that a publisher blocks when the queue is full.

```text
queue full
   ↓
Publish blocks
```

## Graceful drain

Verify that queued events are processed before shutdown completes.

```text
queued events
      ↓
shutdown
      ↓
events processed
```

## Publish after shutdown

Verify:

```go
Publish(event) == false
```

after shutdown.

## Blocked publish during shutdown

Verify:

```text
blocked Publish()
       ↓
Shutdown()
       ↓
Publish() eventually returns
```

rather than hanging forever.

## Idempotent shutdown

Verify:

```go
Shutdown()
Shutdown()
Shutdown()
```

does not panic.

## Concurrent publish and shutdown

Verify that concurrent operations don't deadlock.

---

# 21. What the Event Bus Does NOT Do

The Event Bus should remain focused.

It should not become responsible for:

- Detecting malware
- Applying MITRE ATT&CK rules
- Storing long-term telemetry
- Querying databases
- Collecting processes
- Collecting network information
- Parsing OS-specific APIs
- Performing expensive analytics

Those belong elsewhere.

A clean separation is:

```text
Collector
   │
   ▼
Normalizer
   │
   ▼
Event
   │
   ▼
Event Bus
   │
   ▼
Detection / Storage / Other Consumers
```

This keeps the Event Bus infrastructure simple and reusable.

---

# 22. Representation for an Interview or Presentation

A concise explanation:

> Sentinel uses a bounded asynchronous Event Bus to decouple telemetry producers from consumers. Producers publish normalized events into a bounded channel, and worker goroutines process those events through subscribed handlers. The bounded queue provides backpressure so the system doesn't grow memory without limit, while the initial policy favors blocking over silently dropping security telemetry. The bus also has an explicit lifecycle with graceful draining and shutdown signaling, so queued events can finish processing and blocked publishers can be released when shutdown begins. Concurrency is protected with synchronization primitives, and the behavior is verified through tests covering backpressure, graceful shutdown, blocked publishers, idempotency, and concurrent publish/shutdown.

---

# 23. One-Sentence Mental Model

Remember the Event Bus as:

> **"An asynchronous, bounded, backpressure-aware queue that decouples Sentinel's event producers from its consumers and provides controlled concurrency and graceful shutdown."**

---

# 24. Future Improvements

The current implementation is intentionally simple.

Potential future improvements include:

- Multiple worker goroutines
- Event priority
- Priority-aware queues
- Event persistence
- Metrics for queue depth
- Dropped-event counters if dropping is ever introduced
- Consumer isolation
- Handler-specific queues
- Batching
- Rate limiting
- Event replay
- Stronger lifecycle state modeling

These should be added only when Sentinel actually needs them.

The current architecture provides a strong foundation without prematurely introducing distributed infrastructure such as Kafka, Redis Streams, or NATS.

---

# Final Architecture

```text
                    SENTINEL
                       │
          ┌────────────┴────────────┐
          │     OS Collectors       │
          │                         │
          │ Process / Network / DNS │
          │ Filesystem / Persistence│
          └────────────┬────────────┘
                       │
                       ▼
                Normalized Events
                       │
                       ▼
              ┌─────────────────┐
              │    EVENT BUS     │
              │                 │
              │ bounded queue   │
              │ backpressure    │
              │ worker          │
              │ shutdown signal │
              └────────┬────────┘
                       │
            ┌──────────┼──────────┐
            ▼          ▼          ▼
       Detection    Storage    Logging
            │
            ▼
      Correlation /
      Risk Engine
            │
            ▼
       Security Finding
```

## Key architectural statement

**The Event Bus is Sentinel's concurrency and decoupling boundary between telemetry collection and security intelligence.**