package main

import (
	"flag"
	"fmt"
	"net/netip"
	"strings"

	"github.com/nuriland/a2kit/a2log"
	"github.com/nuriland/a2kit/wire"
)

var recordCommand = command{
	name:  "record",
	args:  "[flags] [FILE]",
	short: "save the game's session",
	long: `Record saves the session until Ctrl-C or -for. It says when it finds the game's connection. Needs admin (root)privileges.

  a2k record fight.pcap                              a recording: all the adapter's TCP traffic
  a2k record -log fight.jsonl                        a log: the game's messages only
  a2k record -log fight.jsonl -for 30m fight.pcap    a log for 30 minutes and a recording`,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		o.live(fs)
		fs.StringVar(&o.log, "log", "", "write the game's messages to `file`, a log; - is stdout")
		fs.BoolVar(&o.client, "client", false, "include the game client's messages in the log, which are encrypted")
		fs.BoolVar(&o.verbose, "v", false, "log what the decoder does to stderr")
		return func(args []string) error {
			switch {
			case len(args) > 1:
				return usagef("one FILE, not %d", len(args))
			case len(args) == 1:
				o.pcap = args[0]
			case o.log == "":
				return usagef("no FILE and no -log: nothing to record to")
			}
			if err := o.checkLive(); err != nil {
				return err
			}
			return record(o)
		}
	},
}

func record(o *options) error {
	s, err := o.openLive()
	if err != nil {
		return err
	}
	var lg *a2log.Writer
	if o.log != "" {
		if lg, err = o.openLog(s); err != nil {
			s.Close()
			return err
		}
	}
	var to []string
	if o.pcap != "" {
		to = append(to, o.pcap)
	}
	switch o.log {
	case "":
	case "-":
		to = append(to, "stdout")
	default:
		to = append(to, o.log)
	}
	fmt.Fprintf(o.stderr, "a2k: recording to %s %s\n", strings.Join(to, " and "), until(o))
	var server netip.AddrPort
	t, err := drain(s, func(r reading) error {
		if r.Flags&wire.FromServer != 0 && r.Src != server { // the first message of a lock
			server = r.Src
			fmt.Fprintln(o.stderr, "a2k: found the game at", server)
		}
		if lg == nil {
			return nil
		}
		return lg.Write(r.Frame)
	})
	return finish(o, s, nil, t, err)
}

func until(o *options) string {
	if o.dur > 0 {
		return fmt.Sprint("for ", o.dur)
	}
	return "until Ctrl-C"
}
