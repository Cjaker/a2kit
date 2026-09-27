// Package a2log is the fight log: a Header line, then one Frame a line, each a JSON object.
// It keeps the game's frames raw, so that a newer game package reads more of an old log.
// NewWriter writes one, and NewReader reads one back, as wire.Frames for game.Parse.
package a2log

import (
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"

	"github.com/nuriland/a2kit/wire"
)

// Schema names the layout: a Header line, then a Frame a line.
// A reader ignores keys it does not know.
const Schema = "a2log/v0.1"

// Header is the first line of a log.
type Header struct {
	Schema  string    `json:"schema"`
	Decoder string    `json:"decoder"` // the module and version that wrote it
	Source  Source    `json:"source"`
	T0      time.Time `json:"t0,omitzero"` // the first frame's time, UTC; absent with no frames
}

// Source is where the frames came from.
type Source struct {
	Kind string `json:"kind"`           // pcap, feed or live
	Path string `json:"path,omitempty"` // the file, or the device; empty for the default device
}

// Frame is one line after the header.
type Frame struct {
	T       int64          `json:"t"`       // milliseconds after Header.T0; negative when a capture is out of order
	Opcode  wire.Opcode    `json:"opcode"`  // in wire order, "04 38"
	Flags   wire.Flags     `json:"flags"`   // ["server","lz4"], [] for none
	Src     netip.AddrPort `json:"src"`     // "10.0.0.2:13328"
	Dst     netip.AddrPort `json:"dst"`     // "10.0.0.3:13328"
	Payload []byte         `json:"payload"` // the bytes after the opcode, base64; "" when empty, never null
}

// NewFrame is f as a line of a log that begins at t0.
func NewFrame(f wire.Frame, t0 time.Time) Frame {
	p := f.Payload
	if p == nil {
		p = []byte{}
	}
	return Frame{f.Time.Sub(t0).Milliseconds(), f.Opcode, f.Flags, f.Src, f.Dst, p}
}

// Wire is the frame of a line of a log that begins at t0, for game.Parse. Its time is to the millisecond.
func (f Frame) Wire(t0 time.Time) wire.Frame {
	return wire.Frame{
		Time:    t0.Add(time.Duration(f.T) * time.Millisecond),
		Src:     f.Src,
		Dst:     f.Dst,
		Opcode:  f.Opcode,
		Flags:   f.Flags,
		Payload: f.Payload,
	}
}

type Writer struct {
	w     io.Writer
	hdr   Header
	begun bool
}

func NewWriter(w io.Writer, src Source) *Writer {
	return &Writer{w: w, hdr: Header{Schema: Schema, Decoder: module(), Source: src}}
}

func (w *Writer) Write(f wire.Frame) error {
	if !w.begun {
		w.hdr.T0 = f.Time.UTC()
		if err := w.line(w.hdr); err != nil {
			return err
		}
		w.begun = true
	}
	return w.line(NewFrame(f, w.hdr.T0))
}

func (w *Writer) Close() error {
	if w.begun {
		return nil
	}
	w.begun = true
	return w.line(w.hdr)
}

func (w *Writer) line(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.w.Write(append(b, '\n'))
	return err
}

// module is the a2kit module and version this build holds: the main module's, or, in a program
// that imports a2kit, the dependency's.
//
// @REVIEW: added for UX, but I doubt it's useful.
func module() string {
	const path = "github.com/nuriland/a2kit"
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return path + "@(unknown)"
	}
	if bi.Main.Path == path {
		return path + "@" + bi.Main.Version
	}
	for _, m := range bi.Deps {
		if m.Path == path {
			return path + "@" + m.Version
		}
	}
	return path + "@(unknown)"
}

type Reader struct {
	dec *json.Decoder
	hdr Header
}

func NewReader(r io.Reader) (*Reader, error) {
	var (
		hdr Header
		dec = json.NewDecoder(r)
	)
	if err := dec.Decode(&hdr); err != nil {
		return nil, fmt.Errorf("a2log: not a log: %w", err)
	}
	if !strings.HasPrefix(hdr.Schema, "a2log/") {
		return nil, fmt.Errorf("a2log: not a log: its schema is %q", hdr.Schema)
	}
	return &Reader{dec: dec, hdr: hdr}, nil
}

func (r *Reader) Header() Header { return r.hdr }

func (r *Reader) Frames() iter.Seq2[wire.Frame, error] {
	return func(yield func(wire.Frame, error) bool) {
		for r.dec.More() {
			var f Frame
			if err := r.dec.Decode(&f); err != nil {
				yield(wire.Frame{}, fmt.Errorf("a2log: %w", err))
				return
			}
			if !yield(f.Wire(r.hdr.T0), nil) {
				return
			}
		}
	}
}
