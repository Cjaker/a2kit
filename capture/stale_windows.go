//go:build windows

package capture

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/0xrawsec/golang-etw/etw"
	"golang.org/x/sys/windows"
)

const (
	// sessionPrefix begins the name of each ETW session a capture opens
	sessionPrefix = "a2kit-pktmon-"

	// stillActive is the exit code GetExitCodeProcess reports for a process that has not exited.
	stillActive = 259
)

var queryAllTraces = windows.NewLazySystemDLL("advapi32.dll").NewProc("QueryAllTracesW")

// sessionName is the name of the ETW session a capture of process pid, created at t, opens.
func sessionName(pid int, t time.Time) string {
	return fmt.Sprintf("%s%d-%d", sessionPrefix, pid, t.UnixNano())
}

// ownSessionName is the name of the ETW session this process opens.
func ownSessionName() (string, error) {
	created, err := processCreated(windows.CurrentProcess())
	if err != nil {
		return "", fmt.Errorf("capture: pktmon: reading when this process was created, to name its ETW session: %w", err)
	}
	return sessionName(os.Getpid(), created), nil
}

// processCreated is when the process h was created.
func processCreated(h windows.Handle) (time.Time, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, created.Nanoseconds()), nil
}

// parseSessionName reads the process and its creation time out of a name sessionName wrote.
func parseSessionName(name string) (pid int, t time.Time, ok bool) {
	rest, ok := strings.CutPrefix(name, sessionPrefix)
	if !ok {
		return 0, time.Time{}, false
	}
	p, n, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, time.Time{}, false
	}
	pid, err := strconv.Atoi(p)
	if err != nil || pid <= 0 {
		return 0, time.Time{}, false
	}
	nanos, err := strconv.ParseInt(n, 10, 64)
	if err != nil {
		return 0, time.Time{}, false
	}
	return pid, time.Unix(0, nanos), true
}

// stale picks out of names the sessions whose capture is gone. A process killed before Close leaves its
// session running, and ETW keeps it until something stops it.
func stale(names []string, alive func(pid int, created time.Time) bool) []string {
	var out []string
	for _, name := range names {
		if pid, t, ok := parseSessionName(name); ok && !alive(pid, t) {
			out = append(out, name)
		}
	}
	return out
}

// processAlive reports whether the process pid, created at created, still runs
func processAlive(pid int, created time.Time) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return !errors.Is(err, windows.ERROR_INVALID_PARAMETER) // no such process
	}
	defer windows.CloseHandle(h)

	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err == nil && code != stillActive {
		return false
	}
	t, err := processCreated(h)
	return err != nil || t.Equal(created)
}

// stopStale stops the ETW sessions that captures killed before Close left running. It reports the
// ones it could not stop, and does not fail the capture.
func stopStale() error {
	names, err := traceSessions()
	if err != nil {
		return fmt.Errorf("capture: pktmon: listing ETW sessions to stop any a2k left running: %w", err)
	}

	var errs []error
	for _, name := range stale(names, processAlive) {
		err := etw.ControlTrace(0, utf16Ptr(name), etw.NewRealTimeEventTraceSessionProperties(name), etw.EVENT_TRACE_CONTROL_STOP)
		if err != nil && !errors.Is(err, windows.ERROR_WMI_INSTANCE_NOT_FOUND) { // stopped since it was listed
			errs = append(errs, fmt.Errorf("capture: pktmon: stopping %s, left running by a2k: %w; logman stop %s -ets stops it", name, err, name))
		}
	}
	return errors.Join(errs...)
}

// traceSessions lists the names of the running ETW sessions.
func traceSessions() ([]string, error) {
	var (
		nameLen     = 1024 // UTF-16 units for each of the names QueryAllTraces fills in
		maxSessions = 64   // the most sessions a default Windows runs at once
	)
	for {
		var (
			size  = int(unsafe.Sizeof(etw.EventTraceProperties{})) + 2*2*nameLen
			props = make([]*etw.EventTraceProperties, maxSessions)
			buf   = make([]byte, maxSessions*size)
		)

		for i := range props {
			p := (*etw.EventTraceProperties)(unsafe.Pointer(&buf[i*size]))

			p.Wnode.BufferSize = uint32(size)
			p.LoggerNameOffset = uint32(unsafe.Sizeof(*p))
			p.LogFileNameOffset = p.LoggerNameOffset + 2*uint32(nameLen)
			props[i] = p
		}

		var count uint32
		r, _, _ := queryAllTraces.Call(uintptr(unsafe.Pointer(&props[0])), uintptr(maxSessions), uintptr(unsafe.Pointer(&count)))

		switch err := windows.Errno(r); {
		case err == windows.ERROR_MORE_DATA && int(count) > maxSessions:
			maxSessions = int(count)
			continue
		case err != 0:
			return nil, err
		}

		names := make([]string, 0, count)
		for _, p := range props[:count] {
			name := unsafe.Slice((*uint16)(unsafe.Add(unsafe.Pointer(p), p.LoggerNameOffset)), nameLen)
			names = append(names, windows.UTF16ToString(name))
		}
		return names, nil
	}
}
