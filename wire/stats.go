package wire

import "net/netip"

// Stats is what a Decoder has seen of the game's connection.
type Stats struct {
	Locked         bool           // whether the decoder is locked on a game stream
	Locks          int            // times the decoder found the game's connection
	Resyncs        int            // times a game stream lost its place
	ClientResyncs  int            // times a client stream lost its place
	Server, Client netip.AddrPort // the last lock's pair
}

// count adds st's resyncs to its side's
func (s *Stats) count(st *stream) {
	switch st.dir {
	case FromServer:
		s.Resyncs += st.fr.resyncs
	case FromClient:
		s.ClientResyncs += st.fr.resyncs
	}
}
