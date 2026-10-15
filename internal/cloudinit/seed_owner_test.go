package cloudinit

import (
	"os"
	"path/filepath"
	"testing"
)

// A seed is this VM's only when its stamp names the VM's spec uuid. Another
// VM's stamp, a VM with no uuid, no seed, and an unstamped seed — however
// recently written — are not, and the caller writes it again.
//
// Mutations: accept any stamped seed — "another VM's stamp" is red; reuse a
// recently written unstamped seed — "unstamped, just written" is red.
func TestSeedIsFor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write bool
		stamp string
		owner string
		want  bool
	}{
		{"its own stamp", true, "u1", "u1", true},
		{"another VM's stamp", true, "u0", "u1", false},
		{"stamped, VM without uuid", true, "u0", "", false},
		{"unstamped, just written", true, "", "u1", false},
		{"no seed", false, "", "u1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iso := filepath.Join(t.TempDir(), "cloudinit", "vm.iso")
			if tc.write {
				if err := os.MkdirAll(filepath.Dir(iso), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(iso, []byte("seed"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := StampSeed(iso, tc.stamp); err != nil {
					t.Fatal(err)
				}
			}
			if got := SeedIsFor(iso, tc.owner); got != tc.want {
				t.Fatalf("SeedIsFor = %v, want %v", got, tc.want)
			}
		})
	}
}

// RemoveSeed takes the stamp with the seed, and StampSeed("") drops a stamp.
func TestRemoveSeedAndEmptyStamp(t *testing.T) {
	iso := filepath.Join(t.TempDir(), "vm.iso")
	if err := os.WriteFile(iso, []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := StampSeed(iso, "u1"); err != nil {
		t.Fatal(err)
	}
	if owner, ok, err := SeedOwner(iso); err != nil || !ok || owner != "u1" {
		t.Fatalf("SeedOwner = %q %v %v", owner, ok, err)
	}
	if err := StampSeed(iso, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := SeedOwner(iso); ok {
		t.Fatal("an empty owner left the stamp")
	}
	if err := StampSeed(iso, "u1"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSeed(iso); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{iso, SeedOwnerPath(iso)} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s survived RemoveSeed (%v)", p, err)
		}
	}
}
