package a2kit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"

	"github.com/nuriland/a2kit/a2log"
	"github.com/nuriland/a2kit/capture"
	"github.com/nuriland/a2kit/game"
	"github.com/nuriland/a2kit/wire"
)

type Config struct {
	Client bool         // keep the client's messages too
	Record io.Writer    // Capture, also write every packet to it, as a pcap
	Logger *slog.Logger // what the decoder does -- resyncs, locks, lost gaps, nil is silent
}

func (cfg Config) decoder() *wire.Decoder {
	return wire.NewDecoder(wire.Config{EmitClient: cfg.Client, Logger: cfg.Logger})
}

type Reader struct {
	Source a2log.Source // where the frames came from. For a log, what its header says
	Log    bool         // it reads a2log, not packets, there is no decoder, so no Stats

	sum Summary

	frames  iter.Seq2[wire.Frame, error]
	d       *wire.Decoder
	src     wire.SegmentReader
	closers []func() error
}

func New(d *wire.Decoder, src wire.SegmentReader) *Reader {
	return &Reader{frames: d.Decode(src), d: d, src: src}
}

func Open(name string, cfg Config) (*Reader, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	r, err := openReader(f, cfg)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("a2kit: %s: %w", name, err)
	}

	if !r.Log {
		r.Source.Path = name
	}
	r.closers = append(r.closers, f.Close)
	return r, nil
}

func OpenReader(r io.Reader, cfg Config) (*Reader, error) {
	rd, err := openReader(r, cfg)
	if err != nil {
		return nil, fmt.Errorf("a2kit: %w", err)
	}
	return rd, nil
}

// openReader is OpenReader, its errors without the package's name, which Open puts before the file's.
func openReader(r io.Reader, cfg Config) (*Reader, error) {
	br := bufio.NewReaderSize(r, 1<<16) // the size capture.NewReader takes as it is
	if b, err := br.Peek(1); err == nil && b[0] == '{' {
		lg, err := a2log.NewReader(br)
		if err != nil {
			return nil, err
		}
		return &Reader{Source: lg.Header().Source, Log: true, frames: logged(lg, cfg.Client)}, nil
	}

	c, err := capture.NewReader(br)
	switch {
	case errors.Is(err, capture.ErrNotCapture):
		return nil, errors.New("not a pcap, a pcapng or a log")
	case err != nil:
		return nil, err
	}

	rd := New(cfg.decoder(), c)
	rd.Source.Kind = "pcap"
	return rd, nil
}

func Capture(ctx context.Context, adapter string, cfg Config) (*Reader, error) {
	l, err := capture.OpenLive(adapter)
	if err != nil {
		return nil, err
	}
	if cfg.Record != nil {
		if err := l.Record(cfg.Record); err != nil {
			l.Close()
			return nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() { l.Close() }) // ends Messages, from another goroutine
	r := New(cfg.decoder(), l)
	r.Source = a2log.Source{Kind: "live", Path: adapter}
	r.closers = append(r.closers, func() error { stop(); return nil }, l.Close)
	return r, nil
}

func (r *Reader) Messages() iter.Seq2[Message, error] {
	return func(yield func(Message, error) bool) {
		for f, err := range r.frames {
			if err != nil {
				yield(Message{}, err)
				return
			}
			e, err := game.Parse(f)
			m := Message{f, e, err}
			r.sum.Messages++
			switch {
			case err == nil:
				r.sum.Decoded++
			case m.Failed():
				r.sum.Failed++
			default:
				r.sum.Unread++
			}
			if !yield(m, nil) {
				return
			}
		}
	}
}

func (r *Reader) Summary() Summary {
	s := r.sum
	if r.d != nil {
		s.Stats = r.d.Stats()
	}
	if c, ok := r.src.(interface{ CutShort() int }); ok {
		s.CutShort = c.CutShort()
	}
	if l, ok := r.src.(interface{ Lost() error }); ok {
		s.Lost = l.Lost()
	}
	return s
}

func (r *Reader) Close() error {
	var errs []error
	for _, c := range r.closers {
		errs = append(errs, c())
	}
	return errors.Join(errs...)
}

func logged(lg *a2log.Reader, client bool) iter.Seq2[wire.Frame, error] {
	return func(yield func(wire.Frame, error) bool) {
		for f, err := range lg.Frames() {
			if err == nil && f.Flags&wire.FromClient != 0 && !client {
				continue
			}
			if !yield(f, err) || err != nil {
				return
			}
		}
	}
}
