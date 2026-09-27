package main

import (
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/nuriland/a2kit"
	"github.com/nuriland/a2kit/a2log"
	"github.com/nuriland/a2kit/wire"
)

// The endpoints of a -stream file.
//
// @TODO: make them optional flags
var (
	streamServer = netip.MustParseAddrPort("10.0.0.2:13328")
	streamClient = netip.MustParseAddrPort("10.0.0.1:10000")
)

// stream reads the bare stream a server sends, as the test fixtures are, as segments from streamServer to streamClient.
type stream struct {
	r   io.Reader
	buf []byte
	seq uint32
}

func (s *stream) ReadSegment() (wire.Segment, error) {
	for {
		n, err := s.r.Read(s.buf)
		if n > 0 {
			seg := wire.Segment{Time: time.Unix(0, 0), Src: streamServer, Dst: streamClient, Seq: s.seq, Flags: wire.ACK, Payload: s.buf[:n]}
			s.seq += uint32(n)
			return seg, nil
		}
		if err != nil {
			return wire.Segment{}, err
		}
	}
}

// openStream reads name, or stdin for "-", as a bare stream.
// It is one connection, and a fixture can be too short to lock, so the decoder keeps what it finds before the lock.
func openStream(o *options, name string) (*a2kit.Reader, error) {
	var r io.Reader = os.Stdin
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		o.closers = append(o.closers, f.Close)
		r = f
	}

	d := wire.NewDecoder(wire.Config{EmitClient: o.client, EmitUnlocked: true, Logger: o.config().Logger})
	rd := a2kit.New(d, &stream{r: r, buf: make([]byte, 1<<16)})
	rd.Source = a2log.Source{Kind: "feed", Path: name}
	return rd, nil
}
