package a2kit

import (
	"cmp"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/nuriland/a2kit/capture"
	"github.com/nuriland/a2kit/wire"
)

const (
	detailBytes = 32                     // how many positions of a payload Detail counts
	burstGap    = 250 * time.Millisecond // the silence that ends one of the player's actions, honestly just eyeballed a number
)

// Analysis is a recording read for what its message types are, and what answered the player.
type Analysis struct {
	Server, Client netip.AddrPort

	Pairs       int           // server and client pairs the decoder locked on
	Start       time.Time     // the pair's first message, which a2k show counts from
	First, Last time.Time     // the pair's first and last message or client packet
	Messages    []Message     // the server's, by time
	Packets     int           // the client's packets that carried data
	Usual       []int         // the sizes the client sends every second or so, in order
	Background  []wire.Opcode // what the server sends whether the player acts or not, in order
	Summary     Summary       // of the whole recording

	sent []packet // the client's packets, in order
}

type packet struct {
	t    time.Time
	size int
}

func Analyze(name string, cfg Config) (*Analysis, error) {
	f, err := capture.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		t      = &tee{File: f, ends: make(map[flow]uint32)}
		r      = New(cfg.decoder(), t)
		all    = make([]Message, 0, 1_000)
		locked = make(map[flow]int)
	)
	for m, err := range r.Messages() {
		if err != nil {
			return nil, err
		}
		all = append(all, m)
		if m.Flags&wire.FromServer != 0 {
			locked[flow{m.Src, m.Dst, m.IfIndex}]++
		}
	}
	if len(locked) == 0 {
		return nil, errors.New("a2kit: no game connection found")
	}

	var srv flow
	for _, m := range all {
		if k := (flow{m.Src, m.Dst, m.IfIndex}); locked[k] > locked[srv] {
			srv = k
		}
	}

	var a = &Analysis{Server: srv.src, Client: srv.dst, Pairs: len(locked), Summary: r.Summary()}
	for _, m := range all {
		if (flow{m.Src, m.Dst, m.IfIndex}) == srv {
			a.Messages = append(a.Messages, m)
		}
	}
	a.Start = a.Messages[0].Time // before sorting: the first message, as a2k show counts from it
	slices.SortStableFunc(a.Messages, func(x, y Message) int { return x.Time.Compare(y.Time) })

	var back = flow{srv.dst, srv.src, srv.ifIndex}
	for _, s := range t.segs {
		if s.flow == back {
			a.sent = append(a.sent, s.packet)
		}
	}
	a.Packets = len(a.sent)
	a.First, a.Last = a.Messages[0].Time, a.Messages[len(a.Messages)-1].Time
	for _, p := range a.sent {
		if p.t.Before(a.First) {
			a.First = p.t
		}
		if p.t.After(a.Last) {
			a.Last = p.t
		}
	}
	a.Usual = usualSizes(a.sent)
	a.Background = a.ambient()
	return a, nil
}

// usualSizes picks the sizes the client sends in more than half the seconds it sends anything.
func usualSizes(sent []packet) []int {
	var (
		secs = make(map[int64]bool)
		by   = make(map[int]map[int64]bool)
	)
	for _, p := range sent {
		secs[p.t.Unix()] = true
		if by[p.size] == nil {
			by[p.size] = make(map[int64]bool)
		}
		by[p.size][p.t.Unix()] = true
	}

	var usual []int
	for size, in := range by {
		if 2*len(in) > len(secs) {
			usual = append(usual, size)
		}
	}
	slices.Sort(usual)
	return usual
}

// ambient picks what the server sends whether the player acts or not
func (a *Analysis) ambient() []wire.Opcode {
	var acting = make(map[int64]bool)
	for _, p := range a.sent {
		if !slices.Contains(a.Usual, p.size) {
			acting[p.t.Unix()] = true
		}
	}
	if len(acting) == 0 {
		return nil
	}

	quiet := a.Last.Unix() - a.First.Unix() + 1 - int64(len(acting))
	inQuiet, inActing := make(map[wire.Opcode]int64), make(map[wire.Opcode]int64)
	for _, m := range a.Messages {
		if acting[m.Time.Unix()] {
			inActing[m.Opcode]++
		} else {
			inQuiet[m.Opcode]++
		}
	}

	var ambient []wire.Opcode
	for op, n := range inQuiet {
		if 2*n >= quiet && 2*n*int64(len(acting)) >= inActing[op]*quiet {
			ambient = append(ambient, op)
		}
	}
	slices.Sort(ambient)
	return ambient
}

// between returns the messages from t0 up to t1.
func (a *Analysis) between(t0, t1 time.Time) []Message {
	byTime := func(m Message, t time.Time) int { return m.Time.Compare(t) }
	i, _ := slices.BinarySearchFunc(a.Messages, t0, byTime)
	j, _ := slices.BinarySearchFunc(a.Messages, t1, byTime)
	return a.Messages[i:j]
}

// TypeStat is what the messages of one type add up to.
type TypeStat struct {
	Type wire.Opcode

	Sizes      map[int]int // payload size to messages
	Count      int         // the total number of messages of this type
	Decoded    int         // those game reads
	Failed     int         // those off the layout game reads
	Background bool        // it comes whether the player acts or not

	// with marks
	Marks  int     // the marks it followed within the window
	Within int     // its messages inside a mark's window
	Idle   float64 // its messages a second outside the windows, NaN if they cover the session
}

// Types adds up each type the server sent, most first. With marks, moments the player acted, it also counts how each type followed them within window, and sorts by that.
func (a *Analysis) Types(marks []time.Time, window time.Duration) []TypeStat {
	stats := make(map[wire.Opcode]*TypeStat)
	for _, m := range a.Messages {
		st := stats[m.Opcode]
		if st == nil {
			st = &TypeStat{Type: m.Opcode, Sizes: make(map[int]int), Background: slices.Contains(a.Background, m.Opcode)}
			stats[m.Opcode] = st
		}
		st.Count++
		st.Sizes[len(m.Payload)]++
		switch {
		case m.Err == nil:
			st.Decoded++
		case m.Failed():
			st.Failed++
		}
	}

	for _, t := range marks {
		followed := make(map[wire.Opcode]bool)
		for _, m := range a.between(t, t.Add(window)) {
			followed[m.Opcode] = true
		}
		for op := range followed {
			stats[op].Marks++
		}
	}
	var covered time.Duration
	for _, iv := range windows(marks, window) {
		for _, m := range a.between(iv[0], iv[1]) {
			stats[m.Opcode].Within++
		}

		// Only what the window covers of the session is time that was not idle.
		lo, hi := iv[0], iv[1]
		if lo.Before(a.First) {
			lo = a.First
		}
		if hi.After(a.Last) {
			hi = a.Last
		}
		if hi.After(lo) {
			covered += hi.Sub(lo)
		}
	}
	if len(marks) > 0 {
		idle := a.Last.Sub(a.First) - covered
		for _, st := range stats {
			st.Idle = math.NaN()
			if idle > 0 {
				st.Idle = float64(st.Count-st.Within) / idle.Seconds()
			}
		}
	}

	rows := make([]TypeStat, 0, len(stats))
	for _, st := range stats {
		rows = append(rows, *st)
	}
	slices.SortFunc(rows, func(x, y TypeStat) int {
		if len(marks) > 0 {
			return cmp.Or(cmp.Compare(y.Marks, x.Marks), cmp.Compare(x.Count-x.Within, y.Count-y.Within),
				cmp.Compare(y.Count, x.Count), cmp.Compare(x.Type, y.Type))
		}
		return cmp.Or(cmp.Compare(y.Count, x.Count), cmp.Compare(x.Type, y.Type))
	})
	return rows
}

// windows merges the marks' windows where they overlap, so that a message counts once.
func windows(marks []time.Time, window time.Duration) [][2]time.Time {
	var out [][2]time.Time
	for _, m := range marks {
		if n := len(out); n > 0 && !m.After(out[n-1][1]) {
			out[n-1][1] = m.Add(window)
			continue
		}
		out = append(out, [2]time.Time{m, m.Add(window)})
	}
	return out
}

// Action is a moment the player acted, as the client's packets show it.
type Action struct {
	At       time.Time
	Sent     []int   // the sizes of the client's packets
	Answered []Count // the types the server sent after
}

type Count struct {
	Type wire.Opcode
	N    int
}

// Actions finds when the client sent packets of a size it does not send all the time, one within
// burstGap of the last joining its action, and what the server sent within window after, or until
// the next action.
func (a *Analysis) Actions(window time.Duration) []Action {
	var bursts [][]packet
	for _, p := range a.sent {
		if slices.Contains(a.Usual, p.size) {
			continue
		}
		if n := len(bursts); n > 0 && p.t.Sub(bursts[n-1][len(bursts[n-1])-1].t) <= burstGap {
			bursts[n-1] = append(bursts[n-1], p)
			continue
		}
		bursts = append(bursts, []packet{p})
	}

	var out []Action
	for i, b := range bursts {
		act := Action{At: b[0].t}
		for _, p := range b {
			act.Sent = append(act.Sent, p.size)
		}
		to := act.At.Add(window)
		if i+1 < len(bursts) && bursts[i+1][0].t.Before(to) { // what follows the next action is its answer
			to = bursts[i+1][0].t
		}
		for _, m := range a.between(act.At, to) {
			if slices.Contains(a.Background, m.Opcode) {
				continue
			}
			j := slices.IndexFunc(act.Answered, func(c Count) bool { return c.Type == m.Opcode })
			if j < 0 {
				act.Answered = append(act.Answered, Count{m.Opcode, 0})
				j = len(act.Answered) - 1
			}
			act.Answered[j].N++
		}
		out = append(out, act)
	}
	return out
}

// Detail is one type's messages, position by position.
type Detail struct {
	Messages []Message      // the type's, by time
	Sizes    map[int]int    // payload size to messages
	Longest  int            // the longest payload
	Bytes    []map[byte]int // for each of the first positions, how often it took each value
	Values   int            // the values the first varint of a payload takes
	Shared   []Count        // other types that begin with some of those values, and how many, most first
}

// Type is op's messages, position by position.
func (a *Analysis) Type(op wire.Opcode) Detail {
	var d = Detail{Sizes: make(map[int]int)}
	for _, m := range a.Messages {
		if m.Opcode == op {
			d.Messages = append(d.Messages, m)
			d.Sizes[len(m.Payload)]++
			d.Longest = max(d.Longest, len(m.Payload))
		}
	}

	for p := range min(d.Longest, detailBytes) {
		counts := make(map[byte]int)
		for _, m := range d.Messages {
			if p < len(m.Payload) {
				counts[m.Payload[p]]++
			}
		}
		d.Bytes = append(d.Bytes, counts)
	}

	begins := make(map[wire.Opcode]map[uint64]bool)
	for _, m := range a.Messages {
		v, n := binary.Uvarint(m.Payload)
		if n <= 0 {
			continue
		}
		if begins[m.Opcode] == nil {
			begins[m.Opcode] = make(map[uint64]bool)
		}
		begins[m.Opcode][v] = true
	}

	ids := begins[op]
	d.Values = len(ids)
	for o, theirs := range begins {
		n := 0
		for v := range theirs {
			if ids[v] {
				n++
			}
		}
		if o != op && n > 0 {
			d.Shared = append(d.Shared, Count{o, n})
		}
	}
	slices.SortFunc(d.Shared, func(x, y Count) int { return cmp.Or(cmp.Compare(y.N, x.N), cmp.Compare(x.Type, y.Type)) })
	return d
}

// flow is one direction of a connection, as the decoder keys its streams.
type flow struct {
	src, dst netip.AddrPort
	ifIndex  int
}

// segment is a data segment's flow, time and size.
type segment struct {
	flow
	packet
}

// tee reads a recording's segments for the decoder, and keeps the headers of those that carry new bytes.
type tee struct {
	*capture.File
	segs []segment
	ends map[flow]uint32 // the furthest byte each flow has sent
}

func (t *tee) ReadSegment() (wire.Segment, error) {
	s, err := t.File.ReadSegment()
	if err != nil || len(s.Payload) == 0 {
		return s, err
	}

	var (
		k   = flow{s.Src, s.Dst, s.IfIndex}
		end = s.Seq + uint32(len(s.Payload))
	)
	if seen, ok := t.ends[k]; !ok || int32(end-seen) > 0 { // a retransmit is not a send
		t.ends[k] = end
		t.segs = append(t.segs, segment{k, packet{s.Time, len(s.Payload)}})
	}
	return s, nil
}
