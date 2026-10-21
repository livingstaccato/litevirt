package fleet

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// TestMain lets point-in-time overlays sit in the harness's temporary
// directories, which may be a tmpfs; production refuses an overlay there
// (pitoverlay.Placement).
func TestMain(m *testing.M) {
	pitoverlay.AllowVolatileForTest()
	// Keep these tripwires on PATH for the entire process, including detached
	// fan-out and cleanup. They never forward to the host's network tools.
	dir, err := os.MkdirTemp("", "fleet-network-tripwire-")
	if err != nil {
		panic(err)
	}
	log := filepath.Join(dir, "attempts")
	if err := os.Setenv("LITEVIRT_FLEET_HOST_COMMAND_LOG", log); err != nil {
		panic(err)
	}
	for _, name := range []string{"bridge", "arping"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nprintf '%s\\n' \"$0 $*\" >> \"$LITEVIRT_FLEET_HOST_COMMAND_LOG\"\nprintf 'fleet host-command tripwire\\n' >&2\nexit 97\n"), 0700); err != nil {
			panic(err)
		}
	}
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH")); err != nil {
		panic(err)
	}
	rc := m.Run()
	if b, err := os.ReadFile(log); err == nil && len(b) != 0 {
		fmt.Fprintf(os.Stderr, "fleet escaped its fake network effects:\n%s", b)
		rc = 1
	} else if err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintf(os.Stderr, "fleet network tripwire cleanup: %v\n", err)
		if rc == 0 {
			rc = 1
		}
	}
	os.Exit(rc)
}
