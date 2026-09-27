package a2log_test

import (
	"fmt"
	"log"
	"strings"

	"github.com/nuriland/a2kit/a2log"
)

func Example() {
	lines := `{"schema":"a2log/v0.1","decoder":"github.com/nuriland/a2kit@v0.1.0","source":{"kind":"pcap","path":"fight.pcap"},"t0":"2026-09-23T18:00:00.123Z"}
{"t":0,"opcode":"04 38","flags":["server"],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":"AQID"}
{"t":51,"opcode":"33 36","flags":["server","lz4"],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":""}
`
	r, err := a2log.NewReader(strings.NewReader(lines))
	if err != nil {
		log.Fatal(err)
	}
	hdr := r.Header()
	fmt.Println(hdr.Source.Kind, hdr.Source.Path, "by", hdr.Decoder)
	for f, err := range r.Frames() {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("+%dms %s %d bytes %v\n", f.Time.Sub(hdr.T0).Milliseconds(), f.Opcode, len(f.Payload), f.Flags)
	}
	// Output:
	// pcap fight.pcap by github.com/nuriland/a2kit@v0.1.0
	// +0ms 04 38 3 bytes server
	// +51ms 33 36 0 bytes server,lz4
}
