package main

import (
	"errors"
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
to share, and a newer a2k decodes more of it. a2k show reads it back.

  a2k export fight.pcap -o fight.jsonl`,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		o.decoding(fs)
		o.file(fs)
		o.output(fs)
		return func(args []string) error {
			name, err := one(args, "FILE")
			if err != nil {
				return err
			}
			s, err := o.openFile(name)
			if err != nil {
				return err
			}
			if s.kind == "log" {
				s.Close()
				return errors.New(name + " is an exported log already")
			}
			out, err := o.openOutput(false)
			if err != nil {
				s.Close()
				return err
			}
			// The log names the file, not where it is, since it is what gets shared.
			lg := a2log.NewWriter(out, a2log.Source{Kind: s.kind, Path: filepath.Base(s.path)})
			t, err := drain(s, func(r reading) error { return lg.Write(r.Frame) })
			if err == nil {
				err = lg.Close()
			}
			return finish(o, s, out, t, err)
		}
	},
}
