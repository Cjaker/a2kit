package wire

import (
	"encoding/binary"
)

// The lengths an envelope header may give.
const (
	minEnvelope = 8
	maxEnvelope = 1000000
)

// envelopes strips the u32le length headers from a stream whose frames come in envelopes.
type envelopes struct {
	on   bool    // the stream is in envelopes
	lost bool    // a gap took a header, and nothing is stripped until the next is found
	left int     // body bytes left in the current envelope
	have int     // header bytes received so far
	head [4]byte // a header split across writes

	search scan // for the headers in the raw bytes since the gap, while lost
}

// believable reports whether n is a length an envelope header may give.
func believable(n uint32) bool { return n >= minEnvelope && n <= maxEnvelope }

// skip accounts for n lost bytes. Within the current body the position is still known; past it,
// a header was lost.
func (e *envelopes) skip(n int) {
	if !e.lost && n <= e.left {
		e.left -= n
		return
	}
	e.lost, e.left, e.have = true, 0, 0
	e.search.reset()
}

// strip removes the headers from p in place. A header with a length that is not believable ends
// the envelopes: its bytes are kept with the rest, and over is true. The result may be longer
// than p when that header began in an earlier write.
func (e *envelopes) strip(p []byte) (out []byte, over bool) {
	out = p[:0]
	for len(p) > 0 {
		if e.left > 0 {
			n := min(len(p), e.left)
			out = append(out, p[:n]...)
			p = p[n:]
			e.left -= n
			continue
		}

		e.head[e.have] = p[0]
		e.have++
		p = p[1:]
		if e.have < len(e.head) {
			continue
		}
		e.have = 0
		if n := binary.LittleEndian.Uint32(e.head[:]); believable(n) {
			e.left = int(n)
			continue
		}

		e.on = false
		tail := append(e.head[:], p...) // a copy: e.head has no spare capacity
		return append(out, tail...), true
	}
	return out, false
}

// chain reports whether the header at h is followed by two more believable headers, one envelope
// apart, reading no further than far.
func chain(p []byte, h, far int) verdict {
	for range 2 {
		h += 4 + int(binary.LittleEndian.Uint32(p[h:]))
		switch {
		case h+4 > far:
			return no
		case h+4 > len(p):
			return maybe
		case !believable(binary.LittleEndian.Uint32(p[h:])):
			return no
		}
	}
	return yes
}
