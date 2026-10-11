// Package netevents reports network connections as the kernel makes and
// breaks them, instead of by comparing the socket table every two seconds.
//
// A connection that opens and closes between two polls is invisible to a
// poller. Here every TCP connection attempt is reported with its outcome,
// every accepted connection with the process that accepted it, every close
// with what the connection carried, and the first use of every UDP socket.
//
// # Identity
//
// The process on a network event is identified exactly as the process
// collector identifies it: the kernel's start_boottime of the thread group
// leader, converted by procevents.StartTimes. Nothing here derives a start
// time of its own.
//
// # What the events mean
//
// The fields the poll collector fills keep their meaning: protocol, the local
// and remote address and port, and state, which is ESTABLISHED for a
// connection, LISTEN for a listening socket and NONE for UDP, as the poller
// reports them. Direction, result and the transfer figures are additional.
package netevents
