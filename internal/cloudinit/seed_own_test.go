package cloudinit

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Re-review N2, re-review 2 N4: whose a seed is, one rule for every path that
// reuses a seed (the hotplug rebuild, a migration source, the reconciler). A
// VM whose spec has no cloud-init owns no seed. Otherwise a seed stamped for
// the VM is its own and one stamped for another VM is not. An unstamped seed —
// every seed an earlier release wrote — is the VM's only when the VM's domain
// here attaches exactly that file as its cdrom (the guest boots from it
// already), that domain is not another VM's, and its instance-id is one the
// VM's create wrote: its name, or <name>-next, and (re-review 3 N5) its
// user-data is what the VM's spec yields. The instance-id alone cannot tell a
// deleted VM of the same name from this one, and an earlier release attached
// any file at the path to the new VM's domain: such a VM's leftover seed is
// never taken on those.
//
// Mutation: take an unstamped seed of the VM's name as its own without the
// cdrom check — "unstamped-name, no domain" goes red; skip the cloud-init
// check — both no-cloud-init cases go red; skip the domain uuid check —
// "another VM's domain" goes red; skip the instance-id check — "foreign"
// goes red; ignore the stamp — "stamped-other" goes red; skip the user-data
// check — "another user-data" goes red.
func TestOwnSeed(t *testing.T) {
	UseGoISOWithoutGenisoimage(t)
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
	const specUUID, otherUUID = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	domain := func(uuid, cdrom string) func() string {
		return func() string {
			return "<domain type='kvm'><name>vm</name><uuid>" + uuid + "</uuid><devices>" +
				"<disk type='file' device='cdrom'><source file='" + cdrom + "'/><target dev='sdb' bus='sata'/></disk>" +
				"</devices></domain>"
		}
	}
	for _, tc := range []struct {
		name, instanceID, stamp string
		cloudInit               bool
		domainUUID              string // "" = no domain here
		domainCDROM             string // "" = the seed itself
		want                    bool
		specUserData            string // "" = the seed's own
	}{
		{"stamped-own", "x", specUUID, true, "", "", true, ""},
		{"stamped-other", "x", otherUUID, true, "", "", false, ""},
		{"stamped-own, no cloud-init", "x", specUUID, false, specUUID, "", false, ""},
		{"unstamped-name, attached", "vm", "", true, specUUID, "", true, ""},
		{"unstamped-next, attached", "vm-next", "", true, specUUID, "", true, ""},
		{"unstamped-name, no domain", "vm", "", true, "", "", false, ""},
		{"unstamped-name, domain attaches another file", "vm", "", true, specUUID, "/elsewhere/vm.iso", false, ""},
		{"unstamped-name, another VM's domain", "vm", "", true, otherUUID, "", false, ""},
		{"unstamped-name, attached, no cloud-init", "vm", "", false, specUUID, "", false, ""},
		{"unstamped-foreign, attached", "other", "", true, specUUID, "", false, ""},
		{"unstamped-name, attached, another user-data", "vm", "", true, specUUID, "", false, "#cloud-config\npassword: mine\n"},
		{"stamped-own, another user-data", "x", specUUID, true, "", "", true, "#cloud-config\npassword: mine\n"},
	} {
		iso := write(strings.NewReplacer(" ", "_", ",", "", "'", "").Replace(tc.name), tc.instanceID, tc.stamp)
		c := SeedClaim{VMName: "vm", UUID: specUUID, CloudInit: tc.cloudInit, UserData: "#cloud-config\n"}
		if tc.specUserData != "" {
			c.UserData = tc.specUserData
		}
		if tc.domainUUID != "" {
			cdrom := tc.domainCDROM
			if cdrom == "" {
				cdrom = iso
			}
			c.DomainXML = domain(tc.domainUUID, cdrom)
		}
		sd, own, err := OwnSeed(iso, c)
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
	// A VM with no spec uuid: an unstamped seed of its name that its domain
	// attaches is still its own.
	nouuid := write("nouuid", "vm", "")
	if _, own, _ := OwnSeed(nouuid, SeedClaim{VMName: "vm", CloudInit: true, UserData: "#cloud-config\n", DomainXML: domain(otherUUID, nouuid)}); !own {
		t.Error("a VM with no uuid does not own its unstamped seed its domain attaches")
	}
	if _, _, err := OwnSeed(filepath.Join(dir, "missing.iso"), SeedClaim{VMName: "vm", UUID: specUUID, CloudInit: true}); !errors.Is(err, fs.ErrNotExist) {
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

// Re-review 3 N5: the user-data a seed written for a VM carries, as every
// writer writes it: the spec's, or an empty cloud-config.
func TestSpecUserData(t *testing.T) {
	if got := SpecUserData(nil); got != "#cloud-config\n{}\n" {
		t.Errorf("no spec: %q", got)
	}
	if got := SpecUserData(&pb.VMSpec{Image: "ubuntu", CloudInit: &pb.CloudInitSpec{}}); got != "#cloud-config\n{}\n" {
		t.Errorf("empty user-data: %q", got)
	}
	if got := SpecUserData(&pb.VMSpec{CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\npassword: mine\n"}}); got != "#cloud-config\npassword: mine\n" {
		t.Errorf("spec user-data: %q", got)
	}
}
