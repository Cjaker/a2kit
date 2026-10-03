package main

import (
	"flag"
	"path/filepath"

	"github.com/nuriland/a2kit/a2log"
)

var exportCommand = command{
	name:  "export",
	args:  "[flags] FILE",
	short: "a log to share, a JSON line a message",
	long: `Export writes the game's messages in FILE, a recording, as an a2log/v0.1 log: a header line,
then a JSON line a message, with its raw bytes. It holds only the game's traffic, so it is what
to share, and a newer a2k decodes more of it. It leaves out Login, Account and Characters,
which name the account, unless -account is passed. a2k show reads it back.

  a2k export fight.pcap -o fight.jsonl`,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		o.clientFlag(fs)
		o.accountFlag(fs)
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
			// The log names the file, not where it is, since it is what gets shared.
			lg := a2log.NewWriter(out, a2log.Source{Kind: r.Source.Kind, Path: filepath.Base(r.Source.Path)})
			err = func() error {
				for m, err := range r.Messages() {
					if err != nil {
						return err
					}
					if err := o.logWrite(lg, m.Frame); err != nil {
						return err
					}
				}
				return lg.Close()
			}()
			return finish(o, r, out, err)
		}
	},
}
