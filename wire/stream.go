package wire

import (
	"net/netip"
	"slices"
	"time"
)

const (
	maxStreams    = 64          // streams a decoder holds at once
	maxHeld       = 64          // segments held past a gap
	maxEarly      = 64          // frames a stream keeps while hunting since the game locks within 30
	maxHeldBytes  = 256 << 10   // bytes held past a gap
	maxEarlyBytes = 256 << 10   // their payload bytes
	maxGapWait    = time.Second // how long a segment waits behind a gap

	closeGrace = 2 * time.Second // how long a closed stream is kept
)

// key identifies one direction of a connection.
type key struct {
	src, dst netip.AddrPort
	ifIndex  int
}

func (k key) reverse() key { return key{k.dst, k.src, k.ifIndex} }

// stream is one direction of one TCP connection.
type stream struct {
	key    key
	dir    Flags     // FromServer, FromClient, or 0 while hunting
	last   time.Time // the time of its newest bytes
	at     time.Time // the capture time of the bytes being parsed
	closed time.Time // the time of its FIN or RST, zero while open
	fr     framer
	born   uint64 // its number among the decoder's streams, for a stable order
	frames int    // frames counted toward the lock

	// Reassembly, for FeedSegment.
	synced    bool   // next is set
	next      uint32 // the sequence number of the next byte in order
	syn       uint32 // the sequence number after its SYN, if one was seen
	heldBytes int
	held      []piece

	early      []Frame
	earlyBytes int
}

// wait keeps f until the lock, the oldest giving way when there are too many.
func (st *stream) wait(f Frame) {
	st.early = append(st.early, f)
	st.earlyBytes += len(f.Payload)
	for len(st.early) > maxEarly || st.earlyBytes > maxEarlyBytes {
		st.earlyBytes -= len(st.early[0].Payload)
		st.early[0] = Frame{}
		st.early = st.early[1:]
	}
}

// piece is a segment held past a gap.
type piece struct {
	seq  uint32
	t    time.Time
	data []byte
}

// after reports whether sequence number a comes after b, allowing for wraparound.
func after(a, b uint32) bool { return int32(a-b) > 0 }

// stale reports whether a held segment has waited maxGapWait.
func (st *stream) stale(t time.Time) bool {
	return slices.ContainsFunc(st.held, func(pc piece) bool { return t.Sub(pc.t) >= maxGapWait })
}

// tlsLike reports whether p starts like a TLS record: a type from 20 to 23, then version 3.0 to 3.4.
func tlsLike(p []byte) bool {
	return len(p) >= 5 && p[0] >= 0x14 && p[0] <= 0x17 && p[1] == 0x03 && p[2] <= 0x04
}
