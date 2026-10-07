package game

import "time"

// Tick carries the server's clock, from 00 36, twenty times a second.
type Tick struct {
	Server time.Time
}

// Ping answers the client's ping with the client's clock sent back and the server's clock.
type Ping struct {
	Client uint64 // milliseconds on the client's clock
	Server time.Time
}

func (Tick) event() {}
func (Ping) event() {}
