package cloudinit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A seed is this VM's when its stamp names the VM's spec uuid, or, unstamped,
// when it was written no earlier than seedLegacyLead before the VM's row was
// created. Anything else — another VM's stamp, an old unstamped seed, no seed,
// an unparseable created_at — is not, and the caller writes it again.
//
// Mutations: accept any stamped seed — "another VM's stamp" is red; drop the
// legacy age check — "unstamped, older" is red.
func TestSeedIsFor(t *testing.T) {
	created := time.Now().Add(-24 * time.Hour)
	createdAt := created.UTC().Format(time.RFC3339Nano)
	for _, tc := range []struct {
		name    string
		write   bool
		stamp   string
		mtime   time.Time
		owner   string
		created string
		want    bool
	}{
		{"its own stamp", true, "u1", created.Add(-48 * time.Hour), "u1", createdAt, true},
		{"another VM's stamp", true, "u0", created, "u1", createdAt, false},
		{"stamped, VM without uuid", true, "u0", created, "", createdAt, false},
		{"unstamped, written at its create", true, "", created.Add(-time.Minute), "u1", createdAt, true},
		{"unstamped, older", true, "", created.Add(-2 * seedLegacyLead), "u1", createdAt, false},
		{"unstamped, created_at unreadable", true, "", created, "u1", "", false},
		{"no seed", false, "", created, "u1", createdAt, false},
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
				if err := os.Chtimes(iso, tc.mtime, tc.mtime); err != nil {
					t.Fatal(err)
				}
				if err := StampSeed(iso, tc.stamp); err != nil {
					t.Fatal(err)
				}
			}
			if got := SeedIsFor(iso, tc.owner, tc.created); got != tc.want {
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
