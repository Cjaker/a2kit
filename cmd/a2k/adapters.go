package main

import (
	"flag"
	"fmt"

	"github.com/nuriland/a2kit/capture"
)

var adaptersCommand = command{
	name:  "adapters",
	short: "what watch and record can capture",
	long: `Adapters lists the network adapters a2k can capture, by the name their -adapter takes.
The one marked * is the default. On Windows, nics is every adapter at once, including a VPN tunnel.`,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		return func(args []string) error {
			if err := none(args); err != nil {
				return err
			}
			devs, err := capture.Devices()
			if err != nil {
				return err
			}
			for _, d := range devs {
				mark := " "
				if d.Default {
					mark = "*"
				}
				if d.Description == "" {
					fmt.Fprintf(o.stdout, "%s %s\n", mark, d.Name)
					continue
				}
				fmt.Fprintf(o.stdout, "%s %s  (%s)\n", mark, d.Name, d.Description)
			}
			return nil
		}
	},
}
