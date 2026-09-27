package main

import (
	"cmp"
	"flag"
	"log/slog"
	"time"

	"github.com/nuriland/a2kit"
	"github.com/nuriland/a2kit/a2log"
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
		o.clientFlag(fs)
		o.verboseFlag(fs)
		o.streamFlag(fs)
		o.outputFlag(fs)
		return func(args []string) error {
			name, err := one(args, "FILE")
			if err != nil {
				return err
			}
			if err := p.check(); err != nil {
				return err
			}
			return show(o, p, func() (*a2kit.Reader, error) { return o.open(name) })
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
  a2k watch -log fight.jsonl -for 10m`,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		p := printing(fs)
		o.liveFlags(fs)
		fs.StringVar(&o.pcap, "pcap", "", "also record all the adapter's traffic to `file`, a pcap")
		fs.StringVar(&o.log, "log", "", "also write the game's messages to `file`, a log")
		o.clientFlag(fs)
		o.verboseFlag(fs)
		o.outputFlag(fs)
		return func(args []string) error {
			if err := cmp.Or(none(args), p.check(), o.checkLive()); err != nil {
				return err
			}
			return show(o, p, o.capture)
		}
	},
}

// show prints every message of the Reader open opens
func show(o *options, p *printer, open func() (*a2kit.Reader, error)) error {
	r, err := open()
	if err != nil {
		return err
	}
	live := r.Source.Kind == "live" && !r.Log
	out, err := o.openOutput(live)
	if err != nil {
		return finish(o, r, nil, err)
	}
	p.w = out
	var lg *a2log.Writer
	if o.log != "" {
		if lg, err = o.openLog(r.Source); err != nil {
			return finish(o, r, out, err)
		}
	}
	var behind *lag
	if o.verbose && live {
		behind = newLag(slog.New(o.records()), time.Now)
	}
	err = func() error {
		for m, err := range r.Messages() {
			if err != nil {
				return err
			}
			if behind != nil {
				behind.note(m.Frame)
			}
			if lg != nil {
				if err := lg.Write(m.Frame); err != nil {
					return err
				}
			}
			if err := p.print(m); err != nil {
				return err
			}
		}
		return nil
	}()
	if behind != nil {
		behind.report()
	}
	return finish(o, r, out, err)
}
