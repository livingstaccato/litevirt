package hostls

import (
	"strings"
	"testing"
)

// Real `lv host ls` output from lab 1 (2026-10-10, ~/lab-build-2c2cd6a5): the
// state column prints the proto enum name. There is no HOST_FENCED — a fenced
// host prints HOST_OFFLINE (grpcapi hostStateToPB) — and anything but
// HOST_ACTIVE is a host taken out of service.
const labHostLs = `NAME    ADDRESS     STATE        CPU  MEMORY        VMs  VERSION
node-1  10.77.0.11  HOST_ACTIVE  1/4  768/2971 MiB  1    labrelay-2c2cd6a5
node-2  10.77.0.12  HOST_ACTIVE  0/4  0/2971 MiB    1    labrelay-2c2cd6a5
node-3  10.77.0.13  HOST_ACTIVE  0/4  0/2971 MiB    5    labrelay-2c2cd6a5
node-4  10.77.0.14  HOST_ACTIVE  0/4  0/2971 MiB    4    labrelay-2c2cd6a5
node-5  10.77.0.15  HOST_ACTIVE  0/4  0/2971 MiB    0    labrelay-2c2cd6a5
`

// withState is labHostLs with one host's state column replaced, keeping the
// real line's shape.
func withState(host, state string) string {
	var out []string
	for _, line := range strings.Split(labHostLs, "\n") {
		if strings.HasPrefix(line, host+" ") {
			line = strings.Replace(line, "HOST_ACTIVE", state, 1)
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// The relay drill's two `lv host ls` checks, against the strings the CLI
// really prints. Unfixed, the precondition counted "active" (never printed)
// and skipped every lab with "0 of 5 are active", and the not-fenced check
// looked for lowercase "fenced"/"offline" (never printed) and could not fail.
//
// Mutations: compare against "active" — every case red; look for
// "HOST_OFFLINE" only — suspect, draining and maintenance not caught, red.
func TestParsesRealHostLs(t *testing.T) {
	for _, tc := range []struct {
		name       string
		out        string
		wantActive int
		wantDown   bool // node-1 taken out of service
	}{
		{"all active", labHostLs, 5, false},
		{"node-1 offline (fenced prints this too)", withState("node-1", "HOST_OFFLINE"), 4, true},
		{"node-1 suspect", withState("node-1", "HOST_SUSPECT"), 4, true},
		{"node-1 draining", withState("node-1", "HOST_DRAINING"), 4, true},
		{"node-2 maintenance", withState("node-2", "HOST_MAINTENANCE"), 4, false},
		{"node-1 maintenance", withState("node-1", "HOST_MAINTENANCE"), 4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			total, active, _ := CountActive(tc.out)
			if total != 5 || active != tc.wantActive {
				t.Errorf("CountActive = %d of %d active, want %d of 5", active, total, tc.wantActive)
			}
			if _, down := TakenDown(tc.out, "node-1"); down != tc.wantDown {
				t.Errorf("TakenDown(node-1) = %v, want %v", down, tc.wantDown)
			}
		})
	}
}
