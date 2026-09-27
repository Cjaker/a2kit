package main

import (
	"flag"
	"fmt"
	"runtime"
	"runtime/debug"
)

var versionCommand = command{
	name:  "version",
	short: "this build",
	long:  `Version prints the module and version a2k was built from, and the Go it was built with.`,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		return func(args []string) error {
			if err := none(args); err != nil {
				return err
			}
			fmt.Fprintln(o.stdout, module(), runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH)
			return nil
		}
	},
}

func module() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "github.com/nuriland/a2kit@(unknown)"
	}
	return bi.Main.Path + "@" + bi.Main.Version
}
