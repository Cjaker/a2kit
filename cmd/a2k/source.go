package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nuriland/a2kit/a2log"
	"github.com/nuriland/a2kit/capture"
	"github.com/nuriland/a2kit/wire"
)

// options are the flags the commands share, each defining those it takes, and where they write.
//
// @TODO: cleanup, maybe decide on a CLI lib
type options struct {
	stdout, stderr io.Writer

	out     string // -o
	client  bool
	verbose bool
	stream  bool          // the file is a bare server to client stream
	adapter string        // live
	pcap    string        // live: record all the adapter's traffic to this file
	log     string        // live: write the game's messages to this log, "-" for stdout
	dur     time.Duration // live: stop after this long
}

func (o *options) output(fs *flag.FlagSet) {
	fs.StringVar(&o.out, "o", "", "write to `file` instead of stdout; on Windows, use it rather than >, which writes UTF-16")
}

func (o *options) decoding(fs *flag.FlagSet) {
	fs.BoolVar(&o.client, "client", false, "include the game client's messages too, which are encrypted")
	fs.BoolVar(&o.verbose, "v", false, "log what the decoder does to stderr")
}

func (o *options) file(fs *flag.FlagSet) {
	fs.BoolVar(&o.stream, "stream", false, "FILE is the bare stream the game server sends, as the test fixtures are, not a recording")
}

func (o *options) live(fs *flag.FlagSet) {
	fs.StringVar(&o.adapter, "adapter", "", "capture this `adapter`, a name a2k adapters lists; the one it marks if none")
	fs.DurationVar(&o.dur, "for", 0, "stop after this `long`, like 2m; until Ctrl-C if none")
}

// The endpoints of a -stream file.
//
// @TODO: make them optional flags
var (
	streamServer = netip.MustParseAddrPort("10.0.0.2:13328")
	streamClient = netip.MustParseAddrPort("10.0.0.1:10000")
)

// A source is where messages come from, either a recording, an exported log, a bare stream, or a live capture.
type source struct {
	kind, path string                       // for an export's header: pcap, feed, live or log, and the file or adapter
	messages   iter.Seq2[wire.Frame, error] // the messages from the source
	recording  *capture.Reader              // a recording's packets, which stats reads too; nil otherwise
	decoder    *wire.Decoder                // nil for an exported log
	lost       func() error                 // what a live capture lost without failing, once closed
	closers    []func() error               // run in order
}

func (s *source) Close() error {
	var errs []error
	for _, c := range s.closers {
		errs = append(errs, c())
	}
	return errors.Join(errs...)
}

func (o *options) decoder(s *source) *wire.Decoder {
	cfg := wire.Config{EmitClient: o.client, EmitUnlocked: o.stream}
	if o.verbose {
		cfg.Logger = slog.New(o.records())
	}
	s.decoder = wire.NewDecoder(cfg)
	return s.decoder
}

func (o *options) records() slog.Handler {
	untimed := func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey && len(groups) == 0 {
			return slog.Attr{}
		}
		return a
	}
	return slog.NewTextHandler(o.stderr, &slog.HandlerOptions{ReplaceAttr: untimed})
}

func (o *options) openFile(name string) (*source, error) {
	s := &source{kind: "pcap", path: name}
	var r io.Reader = os.Stdin
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		r = f
		s.closers = append(s.closers, f.Close)
	}
	br := bufio.NewReaderSize(r, 1<<16) // capture.NewReader takes a reader this size as it is
	if o.stream {
		if b, _ := br.Peek(4); knownFormat(b) {
			s.Close()
			return nil, fmt.Errorf("%s is a recording or a log, not a bare stream; drop -stream", name)
		}
		s.kind = "feed"
		s.messages = streamed(o.decoder(s), br)
		return s, nil
	}
	if b, err := br.Peek(1); err == nil && b[0] == '{' {
		lg, err := a2log.NewReader(br)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		s.kind, s.messages = "log", o.logged(lg)
		return s, nil
	}
	c, err := capture.NewReader(br)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("%s is not a recording or an exported log: %w", name, err)
	}
	s.recording = c
	s.messages = o.decoder(s).Decode(c)
	return s, nil
}

// knownFormat reports whether b, a file's first bytes, begins a pcap, a pcapng or an exported log.
func knownFormat(b []byte) bool {
	if len(b) > 0 && b[0] == '{' {
		return true
	}
	if len(b) < 4 {
		return false
	}
	switch binary.LittleEndian.Uint32(b) {
	case 0x0A0D0D0A, 0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1:
		return true
	}
	return false
}

func (o *options) logged(lg *a2log.Reader) iter.Seq2[wire.Frame, error] {
	return func(yield func(wire.Frame, error) bool) {
		for f, err := range lg.Frames() {
			if err == nil && f.Flags&wire.FromClient != 0 && !o.client {
				continue
			}
			if !yield(f, err) || err != nil {
				return
			}
		}
	}
}

func streamed(d *wire.Decoder, r io.Reader) iter.Seq2[wire.Frame, error] {
	return func(yield func(wire.Frame, error) bool) {
		buf := make([]byte, 1<<16)
		for {
			n, err := r.Read(buf)
			d.Feed(time.Unix(0, 0), streamServer, streamClient, buf[:n])
			if err == io.EOF {
				d.Flush()
			}
			for f := range d.Frames() {
				if !yield(f, nil) {
					return
				}
			}
			switch {
			case err == io.EOF:
				return
			case err != nil:
				yield(wire.Frame{}, err)
				return
			}
		}
	}
}

func (o *options) checkLive() error {
	if o.dur < 0 {
		return usagef("-for %v: how long to capture, like 2m", o.dur)
	}
	return nil
}

// openLive starts a live capture, until Ctrl-C, SIGTERM or o.dur. With o.pcap it records all the adapter's traffic to that file.
func (o *options) openLive() (*source, error) {
	l, err := capture.OpenLive(o.adapter)
	if err != nil {
		return nil, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	cancel := context.CancelFunc(func() {})
	if o.dur > 0 {
		ctx, cancel = context.WithTimeout(ctx, o.dur)
	}

	// Closing ends the decode, from another goroutine. It can take seconds on Windows, while pktmon stops.
	context.AfterFunc(ctx, func() {
		stop()
		fmt.Fprintln(o.stderr, "a2k: stopping the capture")
		l.Close()
	})
	s := &source{kind: "live", path: o.adapter, lost: l.Lost}
	s.closers = append(s.closers, func() error { cancel(); stop(); return nil }, l.Close)

	if o.pcap != "" {
		f, err := os.Create(o.pcap)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.closers = append(s.closers, f.Close)
		if err := l.Record(f); err != nil {
			s.Close()
			return nil, err
		}
	}
	s.messages = o.decoder(s).Decode(l)
	return s, nil
}

func (o *options) openLog(s *source) (*a2log.Writer, error) {
	if o.log == "-" {
		lg := a2log.NewWriter(o.stdout, a2log.Source{Kind: s.kind, Path: s.path})
		s.closers = append(s.closers, lg.Close)
		return lg, nil
	}
	f, err := os.Create(o.log)
	if err != nil {
		return nil, err
	}
	lg := a2log.NewWriter(f, a2log.Source{Kind: s.kind, Path: s.path})
	s.closers = append(s.closers, lg.Close, f.Close) // an empty log's header, before the file closes
	return lg, nil
}

// output is where a command writes, either -o's file, or stdout. Live, each message goes out as it comes.
type output struct {
	*bufio.Writer
	f    *os.File
	live bool
}

func (o *options) openOutput(live bool) (*output, error) {
	if o.out == "" {
		return &output{Writer: bufio.NewWriter(o.stdout), live: live}, nil
	}
	f, err := os.Create(o.out)
	if err != nil {
		return nil, err
	}
	return &output{Writer: bufio.NewWriter(f), live: live, f: f}, nil
}

func (w *output) flushLive() error {
	if w.live {
		return w.Flush()
	}
	return nil
}

func (w *output) Close() error {
	err := w.Flush()
	if w.f != nil {
		err = errors.Join(err, w.f.Close())
	}
	return err
}
