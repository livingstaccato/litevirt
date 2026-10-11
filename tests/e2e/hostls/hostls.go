// Package hostls parses `lv host ls` output for the lab drills in tests/e2e.
// It lives outside package e2e so its tests run in a plain `go test ./...`:
// every test in package e2e is gated behind LITEVIRT_E2E.
//
// The STATE column prints the proto enum name (HOST_ACTIVE, HOST_OFFLINE,
// ...), never the database's lowercase state. There is no HOST_FENCED: a
// fenced host prints HOST_OFFLINE (grpcapi hostStateToPB).
package hostls

import (
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Active is the state `lv host ls` prints for an active host.
var Active = pb.HostState_HOST_ACTIVE.String()

// states maps each listed host to its STATE column, skipping the header.
func states(out string) (names []string, state map[string]string) {
	state = map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "NAME" {
			continue
		}
		names = append(names, f[0])
		state[f[0]] = f[2]
	}
	return names, state
}

// CountActive reads `lv host ls` output: the hosts listed, how many are
// active, and the rest as name=state.
func CountActive(out string) (total, active int, notActive []string) {
	names, state := states(out)
	for _, n := range names {
		if state[n] == Active {
			active++
		} else {
			notActive = append(notActive, n+"="+state[n])
		}
	}
	return len(names), active, notActive
}

// TakenDown reports whether `lv host ls` output shows host in any state but
// active — offline (which is also how a fenced host prints), suspect,
// draining, maintenance — and its line. A host the output does not list is
// not reported.
func TakenDown(out, host string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == host && f[2] != Active {
			return line, true
		}
	}
	return "", false
}
