package a2kit

import (
	"errors"

	"github.com/nuriland/a2kit/game"
	"github.com/nuriland/a2kit/wire"
)

// Message is one of the game's frames, and what game reads of it.
type Message struct {
	wire.Frame
	Event game.Event // nil unless game reads it
	Err   error      // game.ErrUnread, or one wrapping game.ErrLayout
}

// Failed reports whether m's bytes do not fit the layout game reads for its type, most likely after a game patch.
func (m Message) Failed() bool { return errors.Is(m.Err, game.ErrLayout) }

type Summary struct {
	wire.Stats // Analytical stats of the source read

	Messages int   // the game's messages
	Decoded  int   // those game reads
	Unread   int   // those it does not read yet
	Failed   int   // those whose bytes do not fit what it reads, most likely after a game patch
	CutShort int   // segments the recording cut short, whose bytes are lost
	Lost     error // what a live capture lost without failing, once it is closed
}
