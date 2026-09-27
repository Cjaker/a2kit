package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/nuriland/a2kit/game"
	"github.com/nuriland/a2kit/wire"
)

var showCommand = command{
	name:  "show",
	args:  "[flags] FILE",
	short: "what happened in a recording",
	long: `Show prints what happened in FILE, a message a line. A recording (pcap or pcapng), a log
from a2k export, or with -stream a bare stream. FILE - reads stdin.

  a2k show fight.pcap
  a2k show -json fight.pcap | jq -c 'select(.name == "Hit")'

A line is the seconds since the first message, the message's name, and what a2k decodes of it.
a2k help types says where the fields are documented. -json writes a JSON line each instead, for scripts, and -wire writes the protocol's view.`,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		p := printing(fs)
		o.decoding(fs)
		o.file(fs)
		o.output(fs)
		return func(args []string) error {
			name, err := one(args, "FILE")
			if err != nil {
				return err
			}
			if err := p.check(); err != nil {
				return err
			}
			return show(o, p, func() (*source, error) { return o.openFile(name) })
		}
	},
}

var watchCommand = command{
	name:  "watch",
	args:  "[flags]",
	short: "what happens in the game, live",
	long: `Watch prints what happens in the game as it happens, until Ctrl-C or -for. 
It finds the game's connection by itself, among all the traffic of the adapter, and shows only its messages. Needs admin (root) privileges.

  a2k watch
  a2k watch -log fight.jsonl -for 10m `,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		p := printing(fs)
		o.live(fs)
		fs.StringVar(&o.pcap, "pcap", "", "also record all the adapter's traffic to `file`, a pcap")
		fs.StringVar(&o.log, "log", "", "also write the game's messages to `file`, a log")
		o.decoding(fs)
		o.output(fs)
		return func(args []string) error {
			if err := cmp.Or(none(args), p.check(), o.checkLive()); err != nil {
				return err
			}
			return show(o, p, o.openLive)
		}
	},
}

func show(o *options, p *printer, open func() (*source, error)) error {
	s, err := open()
	if err != nil {
		return err
	}
	out, err := o.openOutput(s.kind == "live")
	if err != nil {
		s.Close()
		return err
	}
	p.w = out
	emit := p.print
	if o.log != "" {
		lg, err := o.openLog(s)
		if err != nil {
			s.Close()
			return err
		}
		emit = func(r reading) error { return cmp.Or(lg.Write(r.Frame), p.print(r)) }
	}
	var behind *lag
	if o.verbose && s.kind == "live" {
		behind = newLag(slog.New(o.records()), time.Now)
		next := emit
		emit = func(r reading) error {
			behind.note(r.Frame)
			return next(r)
		}
	}
	t, err := drain(s, emit)
	if behind != nil {
		behind.report()
	}
	return finish(o, s, out, t, err)
}

// A printer writes messages a line each: readable, or -json, or -wire.
type printer struct {
	json, wire bool
	w          *output
	t0         time.Time // the first message's
}

func printing(fs *flag.FlagSet) *printer {
	p := new(printer)
	fs.BoolVar(&p.json, "json", false, "write a JSON line a message, for scripts; a2k help types says what is in it")
	fs.BoolVar(&p.wire, "wire", false, "write the protocol's view of each message: its type, size, flags and endpoints")
	return p
}

func (p *printer) check() error {
	if p.json && p.wire {
		return usagef("-json and -wire are two ways to write a line; take one")
	}
	return nil
}

func (p *printer) print(r reading) error {
	if p.t0.IsZero() {
		p.t0 = r.Time
	}
	switch {
	case p.json:
		p.w.Write(marshal(r, p.t0))
		p.w.WriteByte('\n')
	case p.wire:
		fmt.Fprintf(p.w, "t=%d ts=%s type=%q name=%s len=%d flags=%v src=%v dst=%v\n",
			r.Time.Sub(p.t0).Milliseconds(), r.Time.UTC().Format(time.RFC3339Nano), r.Opcode.String(),
			cmp.Or(typeName(r), "-"), len(r.Payload), r.Flags, r.Src, r.Dst)
	default:
		label := cmp.Or(typeName(r), r.Opcode.String())
		if r.Flags&wire.FromClient != 0 {
			label = "client"
		}
		fmt.Fprintf(p.w, "%9.3f  %-9s  %s\n", float64(r.Time.Sub(p.t0).Milliseconds())/1000, label, readable(r))
	}
	return p.w.flushLive()
}

func typeName(r reading) string {
	if r.Flags&wire.FromClient != 0 {
		return ""
	}
	return game.Name(r.Opcode)
}

func readable(r reading) string {
	switch {
	case r.Flags&wire.FromClient != 0:
		return fmt.Sprintf("(encrypted, %s)", size(r.Payload))
	case r.err == nil:
		return fields(r.event)
	case errors.Is(r.err, game.ErrLayout):
		return fmt.Sprintf("(failed: %s; %s)", strings.TrimPrefix(r.err.Error(), "game: "), size(r.Payload))
	case game.Name(r.Opcode) == "":
		return fmt.Sprintf("(unknown type, %s)", size(r.Payload))
	}
	return fmt.Sprintf("(not decoded, %s)", size(r.Payload))
}

func size(p []byte) string {
	if len(p) == 1 {
		return "1 byte"
	}
	return fmt.Sprintf("%d bytes", len(p))
}

// fields writes e's fields as key=value, the keys in lower case, leaving out those that are zero. Clocks are in local time, as -at takes them.
func fields(e game.Event) string {
	var b strings.Builder
	var add func(v reflect.Value)
	add = func(v reflect.Value) {
		for i := range v.NumField() {
			f, sf := v.Field(i), v.Type().Field(i)
			if sf.Anonymous {
				add(f) // Pos, as x, y and z
				continue
			}
			if f.IsZero() {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(strings.ToLower(sf.Name) + "=")
			switch x := f.Interface().(type) {
			case float32:
				fmt.Fprintf(&b, "%.1f", x)
			case time.Time:
				b.WriteString(x.Local().Format("15:04:05.000"))
			case string:
				if strings.ContainsAny(x, " \"=") {
					x = fmt.Sprintf("%q", x)
				}
				b.WriteString(x)
			default:
				fmt.Fprint(&b, x)
			}
		}
	}
	add(reflect.ValueOf(e))
	return b.String()
}

type jsonLine struct {
	T       int64       `json:"t"`                 // milliseconds after the first message
	TS      time.Time   `json:"ts"`                // when the packet that completed the message came, UTC
	Type    wire.Opcode `json:"type"`              // the message type, two bytes in wire order
	Flags   wire.Flags  `json:"flags"`             // server or client, then lz4, bundled, resynced. Only with -stream can a message have neither: a2k had too few to be sure the stream is the game's
	Name    string      `json:"name,omitempty"`    // what a2k calls the type, if anything
	Event   game.Event  `json:"event,omitempty"`   // the fields of the type, when decoded
	Payload string      `json:"payload,omitempty"` // the message's bytes in hex, when not decoded or failed
	Error   string      `json:"error,omitempty"`   // why it failed: "game: ...", or "json: ..." for a position JSON cannot hold
}

func marshal(r reading, t0 time.Time) []byte {
	l := jsonLine{T: r.Time.Sub(t0).Milliseconds(), TS: r.Time.UTC(), Type: r.Opcode, Flags: r.Flags, Name: typeName(r)}
	err := r.err
	if err == nil {
		l.Event = r.event
		b, jerr := json.Marshal(l)
		if jerr == nil {
			return b
		}
		l.Event, err = nil, jerr // a position that is NaN or infinite, which JSON cannot hold
	}
	l.Payload = fmt.Sprintf("% x", r.Payload)
	if !errors.Is(err, game.ErrUnread) {
		l.Error = err.Error()
	}
	b, _ := json.Marshal(l) // numbers and strings only
	return b
}
