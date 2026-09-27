package wire

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nuriland/a2kit/internal/wiretest"
)

// @TODO: rewrite

// bounded fails t if d holds more than its limits allow, or if what it counts is not what it holds.
func bounded(t *testing.T, d *Decoder) {
	t.Helper()

	var held, closing int
	for _, st := range d.streams {
		size := 0
		for _, pc := range st.held {
			size += len(pc.data)
			if !after(pc.seq, st.next) {
				t.Fatalf("%v holds seq %d, not past next, %d", st.key, pc.seq, st.next)
			}
		}
		if len(st.held) > maxHeld || size > maxHeldBytes || size != st.heldBytes {
			t.Fatalf("%v holds %d segments of %d bytes, counted as %d", st.key, len(st.held), size, st.heldBytes)
		}

		if len(st.fr.buf) > maxBuf+3 || len(st.fr.plain) != 0 {
			t.Fatalf("%v buffers %d bytes, %d of plaintext", st.key, len(st.fr.buf), len(st.fr.plain))
		}

		early := 0
		for _, f := range st.early {
			early += len(f.Payload)
		}
		if len(st.early) > maxEarly || early > maxEarlyBytes || early != st.earlyBytes || len(st.early) > 0 && st.dir != 0 {
			t.Fatalf("%v, direction %v, keeps %d early frames of %d bytes, counted as %d", st.key, st.dir, len(st.early), early, st.earlyBytes)
		}
		held += len(st.held)
		if !st.closed.IsZero() {
			closing++
		}
	}
	switch {
	case len(d.streams) > maxStreams:
		t.Fatalf("%d streams", len(d.streams))
	case held != d.held:
		t.Fatalf("%d segments held, counted as %d", held, d.held)
	case closing != d.closing:
		t.Fatalf("%d streams closed, counted as %d", closing, d.closing)
	case d.last != nil && d.streams[d.last.key] != d.last:
		t.Fatalf("the last stream, %v, was dropped", d.last.key)
	case d.srv != nil && d.streams[d.srv.key] != d.srv:
		t.Fatalf("the locked stream, %v, was dropped", d.srv.key)
	}
}

func drain(t *testing.T, d *Decoder) {
	t.Helper()

	for fr := range d.Frames() {
		if len(fr.Payload) > maxFrame {
			t.Fatalf("a payload of %d bytes", len(fr.Payload))
		}
	}
}

func FuzzFeed(f *testing.F) {
	paths, _ := filepath.Glob("testdata/*.bin")
	for _, path := range paths {
		p, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(p, uint8(7))
	}

	var (
		corrupt = wiretest.AppendBundle(nil, three())
		_, w    = binary.Uvarint(corrupt)
	)
	corrupt[len(corrupt)-1] ^= 0xFF
	corrupt[w+2]++ // the size, which the block no longer fills
	f.Add(corrupt, uint8(7))
	f.Add([]byte{0x0D, 0xFF, 0xFF, 0x00, 0x00, 0x7A, 0x00, 1, 2, 3, 4, 5, 6}, uint8(7)) // 8 MB, from a 3-byte block

	f.Fuzz(func(t *testing.T, p []byte, piece uint8) {
		var (
			d = NewDecoder(Config{})
			n = 1 + int(piece)
		)
		for len(p) > 0 {
			k := min(len(p), n)
			feed(d, p[:k])
			p = p[k:]
		}
		bounded(t, d)
		drain(t, d)
	})
}

type segSpec struct {
	port    byte
	up      bool
	ifIndex int
	flags   TCPFlags
	step    time.Duration
	jump    int8
	ack     int8
	n       uint16
}

var steps = [8]time.Duration{-time.Millisecond, 0, time.Millisecond, 10 * time.Millisecond, 100 * time.Millisecond, time.Second, 2 * time.Second, 61 * time.Second}

func readSpec(b []byte) segSpec {
	return segSpec{
		port:    b[0],
		up:      b[1]&1 != 0,
		ifIndex: int(b[1] >> 1 & 1),
		flags:   TCPFlags(b[2]) & (FIN | SYN | RST | PSH | ACK),
		step:    steps[b[3]%8],
		jump:    int8(b[4]),
		ack:     int8(b[5]),
		n:       binary.LittleEndian.Uint16(b[6:]) >> 2,
	}
}

func specs(ss ...segSpec) []byte {
	var b []byte
	for _, s := range ss {
		side := byte(s.ifIndex << 1)
		if s.up {
			side |= 1
		}
		b = append(b, s.port, side, byte(s.flags), byte(slices.Index(steps[:], s.step)), byte(s.jump), byte(s.ack))
		b = binary.LittleEndian.AppendUint16(b, s.n<<2)
	}
	return b
}

func FuzzSegments(f *testing.F) {
	const ms = time.Millisecond
	one := []segSpec{
		{flags: SYN, step: ms},
		{flags: ACK, step: ms, n: 40},
		{flags: ACK, step: ms, jump: 1, n: 40},
		{flags: ACK, step: ms, jump: -2, n: 40},
		{flags: ACK, step: ms, n: 40},
		{up: true, flags: ACK, step: ms, ack: 2},
		{flags: FIN | ACK, step: ms, n: 40},
		{up: true, flags: ACK, step: 2 * time.Second},
	}

	var many []segSpec
	for i := range maxStreams + 6 {
		many = append(many, segSpec{port: byte(i), flags: SYN, step: ms})
	}

	held := []segSpec{{flags: SYN}, {flags: ACK, step: ms, jump: 1, n: 100}}
	for range maxHeld + 5 {
		held = append(held, segSpec{flags: ACK, step: ms, n: 100})
	}
	held = append(held, segSpec{up: true, flags: SYN}, segSpec{up: true, flags: ACK, step: ms, jump: 1, n: 16000})
	for range maxHeldBytes/16000 + 3 {
		held = append(held, segSpec{up: true, flags: ACK, step: ms, n: 16000})
	}

	for _, name := range []string{"hit", "bundle"} {
		p, err := os.ReadFile("testdata/" + name + ".bin")
		if err != nil {
			f.Fatal(err)
		}
		for _, isn := range []uint32{1000, 0xFFFFFFF0} {
			for _, ss := range [][]segSpec{one, many, held} {
				f.Add(p, specs(ss...), isn)
			}
		}
	}

	f.Fuzz(func(t *testing.T, stream, ctl []byte, isn uint32) {
		if len(stream) == 0 {
			return
		}

		var (
			d   = NewDecoder(Config{})
			at  = map[key]uint32{} // where each direction left off, past isn
			now = epoch
			buf []byte
		)
		for ; len(ctl) >= 8; ctl = ctl[8:] {
			var (
				s   = readSpec(ctl)
				k   = key{srv, netip.AddrPortFrom(cli.Addr(), 10000+uint16(s.port)), s.ifIndex}
				now = now.Add(s.step)
				buf = buf[:0]
			)
			if s.up {
				k = k.reverse()
			}

			pos := at[k] + uint32(int32(s.jump)*64)
			for i := range uint32(s.n) {
				buf = append(buf, stream[(pos+i)%uint32(len(stream))])
			}
			seg := Segment{
				Time:    now,
				Src:     k.src,
				Dst:     k.dst,
				IfIndex: k.ifIndex,
				Flags:   s.flags,
				Seq:     isn + pos,
				Ack:     isn + at[k.reverse()] + uint32(int32(s.ack)*64),
				Payload: buf,
			}
			if s.flags&SYN != 0 {
				seg.Seq-- // the SYN takes the number before its first byte
			}
			d.FeedSegment(seg)
			at[k] = pos + uint32(s.n)
			drain(t, d)
			bounded(t, d)
		}

		d.Flush()
		drain(t, d)
		bounded(t, d)
		if d.held != 0 {
			t.Fatalf("%d segments held after Flush", d.held)
		}
		for _, st := range d.streams {
			if len(st.early) > 0 {
				t.Fatalf("%v keeps %d early frames after Flush", st.key, len(st.early))
			}
		}
	})
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte{0x05, 0x04, 0x38, 0x13, 0x33, 0x36, 0x02, 0, 0, 0x27, 0x05, 0x38}, uint8(7), false)
	f.Add([]byte{0xFF, 0x2A, 0x38, 0x01, 0x12, 0x34, 0x83, 0x00, 0x92, 0x10, 0xF2, 0xFF}, uint8(200), true)
	f.Fuzz(func(t *testing.T, spec []byte, piece uint8, inEnvelopes bool) {
		var (
			stream = slices.Concat(wiretest.AppendFrame(nil, 0x00, 0x36, 0), wiretest.AppendFrame(nil, 0x00, 0x36, 0))
			want   = []string{"00 36 ", "00 36 "}
		)
		frame := func(b []byte, op0, op1 byte, size int) []byte {
			f := wiretest.AppendFrame(nil, op0, op1, size)
			want = append(want, fmt.Sprintf("%02X %02X %x", op0, op1, f[len(f)-size:]))
			return append(b, f...)
		}
		for ; len(spec) >= 3; spec = spec[3:] {
			kind, op0, op1 := spec[0], spec[1], spec[2]
			if op1 == 0xFF || op1 <= 0x0F {
				op1 = 0x38 // FF begins a bundle, and a family of 0F or less reads as an envelope header
			}
			if op0 == 0 && !inFamily(op1) {
				op0 = 1 // so does an opcode of 00 outside the families, after padding
			}
			size := int(kind>>2) * 37
			switch kind & 3 {
			case 0, 1:
				stream = frame(stream, op0, op1, size)
			case 2:
				stream = append(stream, make([]byte, 1+int(op0)%3)...) // padding
			case 3:
				var plain []byte
				for j := range 1 + int(op0)%3 {
					plain = frame(plain, op0+byte(j), op1, size/(j+1))
				}
				stream = wiretest.AppendBundle(stream, plain)
			}
		}
		if inEnvelopes { // a tick bare, and the rest in envelopes behind another, as a real stream has them
			size := 8 + int(piece)*13
			rest := stream[3:]
			if r := len(rest) % size; r > 0 && r < minEnvelope {
				rest = append(rest, make([]byte, minEnvelope-r)...) // padding, so no envelope is too short to believe
			}
			stream = slices.Concat(stream[:3], enveloped(rest, size))
		}

		d := NewDecoder(Config{ParseTLS: true, EmitUnlocked: true}) // TLS is judged per segment, and these are not segments
		x := uint32(piece)
		for p := stream; len(p) > 0; {
			x = x*1664525 + 1013904223
			n := 1 + int(x>>16)%8
			if x&(1<<31) != 0 {
				n = 1 + int(x>>16)%1500
			}
			n = min(n, len(p))
			feed(d, p[:n])
			p = p[n:]
		}
		d.Flush()
		var got []string
		for f := range d.Frames() {
			op := f.Opcode.Bytes()
			got = append(got, fmt.Sprintf("%02X %02X %x", op[0], op[1], f.Payload))
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%d frames out, %d in; first difference at %d", len(got), len(want), firstDiff(got, want))
		}
	})
}

func firstDiff(a, b []string) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}
