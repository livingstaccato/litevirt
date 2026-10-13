package libvirt

import (
	"context"
	"os"
	"testing"
)

// TestProbeVNCPassword_RealQEMU runs the probe against this machine's own
// QEMU (opt-in: LV_REAL_QEMU_PROBE=1, on a host with qemu-system-* or
// qemu-kvm). On a non-FIPS host it must report "can"; LV_REAL_QEMU_PROBE_EXPECT
// =unable flips that for a FIPS-mode host (the lab-2 drill).
func TestProbeVNCPassword_RealQEMU(t *testing.T) {
	if os.Getenv("LV_REAL_QEMU_PROBE") != "1" {
		t.Skip("set LV_REAL_QEMU_PROBE=1 to probe this machine's QEMU")
	}
	if vncProbeBinary() == "" {
		t.Skip("no QEMU on this machine")
	}
	r, proven := probeVNCPassword(context.Background())
	if os.Getenv("LV_REAL_QEMU_PROBE_EXPECT") == "unable" {
		if r == "" {
			t.Fatal("the probe says this host can do VNC passwords; expected unable")
		}
		t.Logf("unable: %s", r)
		return
	}
	if r != "" {
		t.Fatalf("the probe says this host cannot do VNC passwords: %s", r)
	}
	if !proven {
		t.Fatal("the probe answered \"can\" without authenticating: an inconclusive run, not a proof")
	}
}
