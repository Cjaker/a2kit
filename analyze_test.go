package a2kit

import (
	"testing"
	"time"
)

func TestWindowsUnsorted(t *testing.T) {
	var (
		t0   = time.Unix(0, 0)
		at   = func(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }
		got  = windows([]time.Time{at(5), at(0), at(0.5), at(9)}, time.Second)
		want = [][2]time.Time{{at(0), at(1.5)}, {at(5), at(6)}, {at(9), at(10)}}
	)
	if len(got) != len(want) {
		t.Fatalf("%d windows, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("window %d is %v, want %v", i, got[i], want[i])
		}
	}
}
