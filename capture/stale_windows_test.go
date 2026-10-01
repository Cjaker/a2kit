//go:build windows

package capture

import (
	"os"
	"slices"
	"testing"
	"time"
)

func TestSessionName(t *testing.T) {
	at := time.Unix(0, 1790877504412815600)
	pid, got, ok := parseSessionName(sessionName(26432, at))
	if !ok || pid != 26432 || !got.Equal(at) {
		t.Errorf("got %d, %v, %v; want 26432, %v, true", pid, got, ok, at)
	}
	for _, name := range []string{
		"PktMon",
		"a2kit-pktmon-",
		"a2kit-pktmon-26432",
		"a2kit-pktmon-x-1790877504412815600",
		"a2kit-pktmon-0-1790877504412815600",
		"a2kit-pktmon-26432-x",
		"a2kit-pktmon-26432-1-2",
	} {
		if _, _, ok := parseSessionName(name); ok {
			t.Errorf("%q read as a session of a2k", name)
		}
	}
}

func TestStale(t *testing.T) {
	at := time.Unix(0, 1790877504412815600)
	running := map[int]bool{100: true}
	names := []string{
		"PktMon",
		sessionName(100, at), // its capture still runs
		sessionName(200, at), // killed
		"Circular Kernel Context Logger",
		sessionName(300, at), // killed
	}
	got := stale(names, func(pid int, since time.Time) bool {
		if !since.Equal(at) {
			t.Errorf("pid %d: since %v, want %v", pid, since, at)
		}
		return running[pid]
	})
	if want := []string{sessionName(200, at), sessionName(300, at)}; !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestProcessAlive(t *testing.T) {
	name, err := ownSessionName()
	if err != nil {
		t.Fatal(err)
	}
	pid, created, ok := parseSessionName(name)
	if !ok || pid != os.Getpid() {
		t.Fatalf("own session name %q reads as %d, %v", name, pid, ok)
	}
	if !processAlive(pid, created) {
		t.Errorf("this process, created at %v, is not alive", created)
	}
	for _, other := range []time.Time{created.Add(-time.Second), created.Add(time.Second), time.Now()} {
		if processAlive(pid, other) {
			t.Errorf("a process created at %v reads as this one, created at %v", other, created)
		}
	}
}

func TestTraceSessions(t *testing.T) {
	names, err := traceSessions()
	if err != nil {
		t.Skipf("listing ETW sessions: %v", err) // needs Administrator, or the Performance Log Users group
	}
	if len(names) == 0 {
		t.Error("no ETW sessions; Windows always runs some")
	}
	for _, name := range names {
		if name == "" {
			t.Errorf("an empty name among %q", names)
		}
	}
}
