package main

import (
	"flag"

	"github.com/nuriland/a2kit"
)

var timelineCommand = command{
	name:  "timeline",
	args:  "[flags] FILE",
	short: "a timeline, for ui.perfetto.dev",
	long: `Timeline writes FILE, a recording or an exported log, as a trace to open in ui.perfetto.dev:
a track a message type, and a track an entity, with its hits, casts, spawn and death.

  a2k timeline fight.pcap -o fight.trace.json`,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		o.clientFlag(fs)
		o.verboseFlag(fs)
		o.streamFlag(fs)
		o.outputFlag(fs)

		return func(args []string) error {
			name, err := one(args, "FILE")
			if err != nil {
				return err
			}

			r, err := o.open(name)
			if err != nil {
				return err
			}
			out, err := o.openOutput(false)
			if err != nil {
				return finish(o, r, nil, err)
			}
			return finish(o, r, out, a2kit.WriteTrace(out, r.Messages()))
		}
	},
}
