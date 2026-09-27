package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nuriland/a2kit/game"
	"github.com/nuriland/a2kit/wire"
)

// A reading is a message and what game makes of it.
type reading struct {
	wire.Frame
	event game.Event
	err   error // game.ErrUnread, or one wrapping game.ErrLayout
}

func interpret(f wire.Frame) reading {
	e, err := game.Parse(f)
	return reading{f, e, err}
}

// tally counts the messages a command read.
type tally struct{ messages, decoded, notDecoded, failed int }

func (t *tally) add(r reading) {
	t.messages++
	switch {
	case r.err == nil:
		t.decoded++
	case errors.Is(r.err, game.ErrLayout):
		t.failed++
	default:
		t.notDecoded++
	}
}

// drain hands every message of s to emit, and counts them.
func drain(s *source, emit func(reading) error) (tally, error) {
	var t tally
	for f, err := range s.messages {
		if err != nil {
			return t, err
		}
		r := interpret(f)
		t.add(r)
		if err := emit(r); err != nil {
			return t, err
		}
	}
	return t, nil
}

// finish closes s and out, prints the summary of t, and returns the first error, err's if set.
func finish(o *options, s *source, out *output, t tally, err error) error {
	err = errors.Join(err, s.Close())
	if out != nil {
		err = errors.Join(err, out.Close())
	}
	if s.lost != nil {
		if lost := s.lost(); lost != nil {
			fmt.Fprintln(o.stderr, "a2k:", strings.ReplaceAll(lost.Error(), "\n", "\na2k: "))
		}
	}
	summarize(o.stderr, s, t, err)
	return err
}

// summarize prints what a command read, in a line of key=value, and what to do if it read nothing.
func summarize(w io.Writer, s *source, t tally, err error) {
	if s.recording != nil {
		if n := s.recording.CutShort(); n > 0 {
			fmt.Fprintf(w, "a2k: the recording cut %d packets short, and the bytes cut are lost; pktmon needs --pkt-size 0\n", n)
		}
	}
	if t.messages == 0 && err == nil {
		switch s.kind {
		case "live":
			fmt.Fprintln(w, "a2k: no game messages; is the game running, on the adapter captured? a2k adapters lists them")
		default:
			fmt.Fprintln(w, "a2k: no game messages in", s.path)
		}
	}

	state := "done"
	if err != nil {
		state = "stopped"
	}
	fmt.Fprintf(w, "a2k: %s messages=%d decoded=%d not_decoded=%d failed=%d", state, t.messages, t.decoded, t.notDecoded, t.failed)
	if s.decoder != nil {
		st := s.decoder.Stats()
		fmt.Fprintf(w, " sessions=%d", st.Locks)
		if st.Locks > 0 {
			fmt.Fprintf(w, " server=%v client=%v", st.Server, st.Client)
		}
		fmt.Fprintf(w, " resyncs=%d client_resyncs=%d", st.Resyncs, st.ClientResyncs)
	}
	if s.recording != nil {
		fmt.Fprintf(w, " cut_short=%d", s.recording.CutShort())
	}
	fmt.Fprintln(w)
}
