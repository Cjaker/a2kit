package main

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/nuriland/a2kit/wire"
)

var statsCommand = command{
	name:  "stats",
	args:  "[flags] FILE",
	short: "which message types came, how often, and which a2k decodes",
	long: `Stats reads FILE, a recording, and lists the message types the game server sent. How many of
each, their sizes, and how many a2k decodes. It is the first thing to run on a new recording,
and how new types get decoded. Act in the game at noted moments, then see what answered.

  a2k stats fight.pcap
  a2k stats -at 21.05s,1m13s fight.pcap     how the types followed the moments you acted
  a2k stats -actions fight.pcap             when you acted, as your client's packets show it
  a2k stats -type "01 38" fight.pcap        one type, byte by byte

-at takes offsets from the first message, as a2k show counts them, or clock times like
10:53:41, in this computer's local time, as a2k show writes clocks. A note of "known" means a2k
uses the type to find the game's connection. "background" means the server sends it whether the
player acts or not.`,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		var v views
		fs.StringVar(&v.at, "at", "", "the `moments` you acted, comma-separated: offsets like 21.05s, or clock times like 10:53:41")
		fs.DurationVar(&v.window, "window", time.Second, "how long after a moment the server's messages count as its answer")
		fs.BoolVar(&v.actions, "actions", false, "list when your client sent something unusual, and what the server answered")
		fs.StringVar(&v.typ, "type", "", "show one message `type` byte by byte, in wire order: \"01 38\" or 0138")
		fs.BoolVar(&o.verbose, "v", false, "log what the decoder does to stderr")
		o.output(fs)
		return func(args []string) error {
			name, err := one(args, "FILE")
			if err != nil {
				return err
			}
			if err := v.check(); err != nil {
				return err
			}
			return stats(o, name, v)
		}
	},
}

func clock(t time.Time) string { return t.Local().Format("15:04:05 MST") }

// views are the flags that choose what stats shows.
type views struct {
	at      string
	actions bool
	typ     string
	window  time.Duration
	op      wire.Opcode
}

// check takes one view, -at only with the table, a window to look into, and a type to show.
func (v *views) check() (err error) {
	switch {
	case v.window <= 0:
		return usagef("-window %v: the window must be positive", v.window)
	case v.typ != "" && v.actions:
		return usagef("-type and -actions are different views; take one")
	case v.at != "" && (v.typ != "" || v.actions):
		return usagef("-at marks the table; drop -type or -actions")
	case v.at != "":
		if _, err := parseMarks(v.at, time.Now()); err != nil {
			return usageError{err}
		}
	case v.typ != "":
		if v.op, err = parseOpcode(v.typ); err != nil {
			return usageError{err}
		}
	}
	return nil
}

func stats(o *options, name string, v views) error {
	s, err := o.openFile(name)
	if err != nil {
		return err
	}

	if s.recording == nil {
		s.Close()
		return errors.New("stats reads a recording, pcap or pcapng, whose client packets say when the player acted")
	}

	out, err := o.openOutput(false)
	if err != nil {
		s.Close()
		return err
	}

	var t tally
	err = func() error {
		ses, err := read(s.recording, s.decoder)
		if err != nil {
			return err
		}
		for _, f := range ses.frames {
			t.add(interpret(f))
		}
		if ses.locks > 1 {
			fmt.Fprintf(o.stderr, "a2k: the game's connection was found %d times; showing %v to %v, the one with the most messages\n", ses.locks, ses.server, ses.client)
		}
		switch {
		case v.typ != "":
			writeType(out, ses, v.op)
		case v.actions:
			writeActions(out, ses, v.window)
		default:
			marks, err := parseMarks(v.at, ses.start)
			if err != nil {
				return err
			}
			for _, m := range marks {
				if m.Before(ses.first) || m.After(ses.last) {
					fmt.Fprintf(o.stderr, "a2k: the mark at %s, %s, is outside the session, %s to %s, %s to %s\n",
						ses.since(m), clock(m), ses.since(ses.first), ses.since(ses.last), clock(ses.first), clock(ses.last))
				}
			}
			writeTable(out, ses, marks, v.window)
		}
		return nil
	}()
	return finish(o, s, out, t, err)
}
