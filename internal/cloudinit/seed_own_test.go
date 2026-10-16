package cloudinit

import (
	"errors"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Re-review N2: whose a seed is, one rule for every path that reuses a seed
// (the hotplug rebuild, a migration source). A seed stamped for the VM is its
// own and one stamped for another VM is not. An unstamped seed — every seed an
// earlier release wrote — is the VM's when its instance-id is one the VM's
// create wrote: its name, or the name a replacement was created under
// (<name>-next) before the cutover renamed it. Anything else (a deleted VM of
// another name's, a renamed VM's) is not proven the VM's.
//
// Mutation: take every unstamped seed as the VM's — the foreign case goes red;
// none — the name and -next cases go red; ignore the stamp — the stamped-other
// case goes red.
func TestOwnSeed(t *testing.T) {
	if _, err := exec.LookPath("genisoimage"); err != nil {
		t.Skip("genisoimage not installed")
	}
	dir := t.TempDir()
	write := func(name, instanceID, stamp string) string {
		t.Helper()
		iso := filepath.Join(dir, name+".iso")
		if err := GenerateISO(Config{InstanceID: instanceID, LocalHostname: instanceID, UserData: "#cloud-config\n"}, iso); err != nil {
			t.Fatal(err)
		}
		if stamp != "" {
			if err := StampSeed(iso, stamp); err != nil {
				t.Fatal(err)
			}
		}
		return iso
	}
	for _, tc := range []struct {
		name, instanceID, stamp string
		want                    bool
	}{
		{"stamped-own", "x", "u1", true},
		{"stamped-other", "x", "u2", false},
		{"unstamped-name", "vm", "", true},
		{"unstamped-next", "vm-next", "", true},
		{"unstamped-foreign", "other", "", false},
	} {
		iso := write(tc.name, tc.instanceID, tc.stamp)
		sd, own, err := OwnSeed(iso, "vm", "u1")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if own != tc.want {
			t.Errorf("%s: own = %v, want %v", tc.name, own, tc.want)
		}
		if sd.InstanceID() != tc.instanceID {
			t.Errorf("%s: seed not returned: %+v", tc.name, sd)
		}
	}
	// A VM with no spec uuid: an unstamped seed of its name is still its own.
	if _, own, _ := OwnSeed(write("nouuid", "vm", ""), "vm", ""); !own {
		t.Error("a VM with no uuid does not own its unstamped seed")
	}
	if _, _, err := OwnSeed(filepath.Join(dir, "missing.iso"), "vm", "u1"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing seed: err = %v, want fs.ErrNotExist", err)
	}
}

// Re-review N1: the network-config written where litevirt cannot tell the
// VM's NICs and keeps no seed of the VM's. cloud-init finds it disabled
// (net.is_disabled_cfg on the datasource's config) and renders nothing at all,
// on every boot, whatever update events the guest recorded earlier; the
// vendor-data turns the per-boot re-render off from the boot after.
func TestNetworkConfigDisabled(t *testing.T) {
	if NetworkConfigDisabled != "network:\n  config: disabled\n" {
		t.Errorf("NetworkConfigDisabled = %q", NetworkConfigDisabled)
	}
	if !strings.Contains(NetworkUpdatesOffVendorData, "updates:\n  network:\n    when: [boot-new-instance]\n") ||
		!strings.HasPrefix(NetworkUpdatesOffVendorData, "#cloud-config\n") {
		t.Errorf("NetworkUpdatesOffVendorData = %q", NetworkUpdatesOffVendorData)
	}
	// A seed that disables network config names nothing.
	if p := PriorFrom(NetworkConfigDisabled); len(p.Names) != 0 {
		t.Errorf("PriorFrom(disabled) = %+v", p.Names)
	}
}
