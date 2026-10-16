package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RemoveOrphanedBridge deletes a bridge only when this host's record says
// litevirt made THIS device, the record is past the grace period, and nothing
// is plugged into it; dnsmasq is stopped on the way. Anything else is kept:
// an operator's bridge (no record), a replaced device (ifindex differs), a
// bridge just made, and one with any port.
//
// Mutations: drop the record check — "operator" is deleted; drop the ifindex
// check — "replaced" is deleted; drop the grace check — "fresh" is deleted;
// drop the port check — "ported" is deleted. Each goes red.
func TestRemoveOrphanedBridge(t *testing.T) {
	sys := t.TempDir()
	origSys, origDir, origGrace := sysClassNet, createdBridgeDir, orphanBridgeGrace
	sysClassNet = sys
	createdBridgeDir = filepath.Join(t.TempDir(), "bridges")
	orphanBridgeGrace = time.Minute
	var cmds []string
	execCommand = func(name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() {
		sysClassNet, createdBridgeDir, orphanBridgeGrace = origSys, origDir, origGrace
		execCommand = defaultExec
	})
	if err := os.MkdirAll(createdBridgeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	record := func(name, idx string, age time.Duration) {
		p := filepath.Join(createdBridgeDir, name)
		if err := os.WriteFile(p, []byte(idx+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	writeSysBridge(t, sys, "orphan", 11)
	record("orphan", "11", time.Hour)
	writeSysBridge(t, sys, "operator", 12)
	writeSysBridge(t, sys, "replaced", 13)
	record("replaced", "99", time.Hour)
	writeSysBridge(t, sys, "fresh", 14)
	record("fresh", "14", time.Second)
	writeSysBridge(t, sys, "ported", 15)
	record("ported", "15", time.Hour)
	if err := os.WriteFile(filepath.Join(sys, "ported", "brif", "eth9"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	listed, err := CreatedBridges()
	if err != nil {
		t.Fatalf("CreatedBridges: %v", err)
	}
	if got := strings.Join(listed, ","); got != "fresh,orphan,ported,replaced" {
		t.Errorf("CreatedBridges = %s, want the four recorded bridges", got)
	}

	for name, want := range map[string]bool{"orphan": true, "operator": false, "replaced": false, "fresh": false, "ported": false} {
		cmds = nil
		got, err := RemoveOrphanedBridge(name)
		if err != nil {
			t.Fatalf("RemoveOrphanedBridge(%s): %v", name, err)
		}
		if got != want {
			t.Errorf("RemoveOrphanedBridge(%s) = %v, want %v", name, got, want)
		}
		deleted := false
		for _, c := range cmds {
			if c == "ip link del "+name {
				deleted = true
			}
		}
		if deleted != want {
			t.Errorf("%s: ip link del ran=%v, want %v (commands %q)", name, deleted, want, cmds)
		}
		if want {
			if !strings.Contains(strings.Join(cmds, "\n"), "pkill -f pid-file="+dnsmasqPidFile(name)) {
				t.Errorf("%s: its dnsmasq was not stopped before the delete: %q", name, cmds)
			}
			if _, err := os.Stat(filepath.Join(createdBridgeDir, name)); !os.IsNotExist(err) {
				t.Errorf("%s: record kept after the delete", name)
			}
		}
	}
}
