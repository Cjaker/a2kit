# a2kit

Passive AION 2 protocol decoder. No injection. No Npcap/WinPcap required.

## CLI
Download `a2k` for your system from the [releases](https://github.com/nuriland/a2kit/releases), or install it as a CLI tool:

```
go install github.com/nuriland/a2kit/cmd/a2k@latest
```

On Linux, a2k needs libpcap to capture live , and `libpcap-dev` to build. A build without cgo reads recordings, but cannot capture.

### Use

```bash
a2k help                                      # list all available commands
a2k watch                                     # what happens in the game, live
a2k record -log fight.jsonl                   # save the game's session
a2k show fight.pcap                           # read the saved game session
a2k export fight.pcap -o fight.jsonl          # a log to share
a2k timeline fight.pcap -o fight.trace.json   # a timeline reconstruction via ui.perfetto.dev
a2k stats fight.pcap                          # which message types came, and which a2k decodes
```

Example usage of `a2k show`:
```
   21.050  Hit        actor=37365 target=15943 skill=11020000 damage=36 type=2 scalar=10000
```

## Live capture

`watch` and `record` find the game's connection by themselves. Needs priviledged access to run on all platforms (Win, Linux, MacOS).

### Windows
  - Doesn't require Npcap or WinPcap installed, it runs on native pktmon monitor.
  - It captures on every adapter at once (`nics`), a VPN's tunnel included, by default. `a2k adapters` lists the adapters.
  - A capture that is killed, rather than stopped, leaves pktmon running. `pktmon stop` ends it
    - Running a2k with the `-for` flag closes the pktmon session automatically

## Recording and sharing

`a2k record` saves a session two ways, and can do both at once:
- `-log fight.jsonl`, a log of the game's messages only, with their raw bytes
- `fight.pcap`, a recording of all the adapter's TCP traffic. DO NOT SHARE THESE PUBLICLY.

## As a library

```
go get github.com/nuriland/a2kit
```

- `capture` reads recordings, or captures live
- `wire` turns the packets into the game's messages
- `game` reads what a message means
- `a2log` writes and reads logs

```go
l, err := capture.OpenLive("") // or capture.Open("fight.pcap")
if err != nil {
	return err
}
context.AfterFunc(ctx, func() { l.Close() })

d := wire.NewDecoder(wire.Config{})
for f, err := range d.Decode(l) {
	if err != nil {
		return err
	}
	switch e, err := game.Parse(f); {
	case errors.Is(err, game.ErrUnread): // not yet decoded type
	case err != nil: // bytes off the layout (can happen on game patches if there's changes to the protocol)
	default:
		if hit, ok := e.(game.Hit); ok {
			fmt.Println(hit.Actor, hit.Target, hit.Skill, hit.Damage)
		}
	}
}
fmt.Printf("%+v\n", d.Stats()) // the game's connection, and how the decoding went
```

To read a log, which `a2k export` writes:

```go
r, err := a2log.NewReader(file)
if err != nil {
	return err
}
for f, err := range r.Frames() {
	...
}
```

Live capture needs cgo and libpcap on macOS and Linux.

Work in progress.