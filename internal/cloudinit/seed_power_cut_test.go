package cloudinit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A seed whose .owner stamp a power cut left empty or zero-filled has an
// owner not known: SeedOwner reads it as stamped with owner "", and
// OwnSeedWhy says so instead of naming "another VM (uuid )" — the reason an
// operator reads in seed.not_rebuilt after exactly that power cut (abort
// re-review 34, m1).
//
// Mutations: drop the owner == "" case in OwnSeedWhy — the reason names
// another VM, red; drop the printable check in SeedOwner — the zeroed stamp
// reads as an owner of NULs, red.
func TestOwnSeedWhy_AStampAPowerCutLeftIsAnOwnerNotKnown(t *testing.T) {
	UseGoISOWithoutGenisoimage(t)
	const specUUID = "11111111-1111-1111-1111-111111111111"
	for _, tc := range []struct {
		name  string
		stamp []byte
	}{
		{"empty", nil},
		{"blank", []byte(" \n")},
		{"zeroed", bytes.Repeat([]byte{0}, 37)},
		{"torn", []byte("1111\x00\x00\x00\x00")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iso := filepath.Join(t.TempDir(), "vm.iso")
			if err := GenerateISO(Config{InstanceID: "vm", LocalHostname: "vm", UserData: "#cloud-config\n"}, iso); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(SeedOwnerPath(iso), tc.stamp, 0o600); err != nil {
				t.Fatal(err)
			}
			if o, ok, err := SeedOwner(iso); err != nil || !ok || o != "" {
				t.Fatalf("SeedOwner = %q, %v, %v; want owner not known (\"\", true)", o, ok, err)
			}
			_, own, why, err := OwnSeedWhy(iso, SeedClaim{VMName: "vm", UUID: specUUID, CloudInit: true, UserData: "#cloud-config\n"})
			if err != nil || own {
				t.Fatalf("OwnSeedWhy = own %v, %v; want not own", own, err)
			}
			if !strings.Contains(why, "empty or unreadable") || !strings.Contains(why, "not known") || strings.Contains(why, "another VM") {
				t.Errorf("reason = %q; want an owner not known, not another VM", why)
			}
		})
	}
	// A real stamp is still read as written.
	iso := filepath.Join(t.TempDir(), "vm.iso")
	if err := GenerateISO(Config{InstanceID: "vm", LocalHostname: "vm"}, iso); err != nil {
		t.Fatal(err)
	}
	if err := StampSeed(iso, specUUID); err != nil {
		t.Fatal(err)
	}
	if o, ok, err := SeedOwner(iso); err != nil || !ok || o != specUUID {
		t.Fatalf("SeedOwner = %q, %v, %v; want %s", o, ok, err, specUUID)
	}
}

// failDirSync makes every directory sync fail until t ends.
func failDirSync(t *testing.T) {
	t.Helper()
	prev := dirSync
	dirSync = func(*os.File) error { return errors.New("EIO") }
	t.Cleanup(func() { dirSync = prev })
}

// A new seed whose directory cannot be synced is not left at its path: its
// caller never stamps or records it, and a seed the create moved aside — a
// kept one, at its .kept- name — must link back there (os.Link, as
// grpcapi's restoreSeed does, which never replaces a file). The kept seed is
// not touched (abort re-review 34, m3).
//
// Mutation: leave the new seed in place on a failed directory sync, as
// before — the path is taken and the link fails with EEXIST, red.
func TestGenerateISO_ADirSyncFailureLeavesThePathFreeForAKeptSeed(t *testing.T) {
	UseGoISOWithoutGenisoimage(t)
	dir := t.TempDir()
	iso := filepath.Join(dir, "vm.iso")
	kept := iso + ".kept-20261017T000000Z"
	keptBytes := []byte("the kept VM's seed")
	if err := os.WriteFile(kept, keptBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	failDirSync(t)
	err := GenerateISO(Config{InstanceID: "vm", LocalHostname: "vm", UserData: "#cloud-config\n"}, iso)
	if err == nil || !strings.Contains(err.Error(), "EIO") {
		t.Fatalf("GenerateISO = %v; want the directory sync's error", err)
	}
	if _, err := os.Lstat(iso); !os.IsNotExist(err) {
		t.Fatalf("the new seed is left at %s after a failed directory sync: %v", iso, err)
	}
	if b, err := os.ReadFile(kept); err != nil || !bytes.Equal(b, keptBytes) {
		t.Fatalf("the kept seed = %q, %v; want it untouched", b, err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(m) != 0 {
		t.Errorf("temp files left: %v", m)
	}
	if err := os.Link(kept, iso); err != nil {
		t.Fatalf("the kept seed cannot be linked back: %v", err)
	}
}

// A rebuild whose directory sync fails keeps the seed it wrote: the path
// held the VM's own seed, stamped, and removing it would leave the VM none.
//
// Mutation: remove the seed on a rebuild too — the seed is gone, red.
func TestRebuildISO_ADirSyncFailureKeepsTheSeed(t *testing.T) {
	UseGoISOWithoutGenisoimage(t)
	iso := filepath.Join(t.TempDir(), "vm.iso")
	if err := GenerateISO(Config{InstanceID: "vm", LocalHostname: "vm"}, iso); err != nil {
		t.Fatal(err)
	}
	failDirSync(t)
	if _, err := RebuildISO(iso, "version: 2\n", ""); err == nil || !strings.Contains(err.Error(), "EIO") {
		t.Fatalf("RebuildISO = %v; want the directory sync's error", err)
	}
	s, err := ReadSeed(iso)
	if err != nil || s.NetworkConfig != "version: 2\n" {
		t.Fatalf("the rebuilt seed = %+v, %v; want it at its path with its new network-config", s, err)
	}
}
