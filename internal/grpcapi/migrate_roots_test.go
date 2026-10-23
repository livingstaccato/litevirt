package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The source of a cold move reads the file at a disk's recorded path and, once
// the move has committed, removes it. A crafted disk record must not make it
// read or delete a file outside its own disk places, nor through a link in
// them, nor in the PKI directory (the F1 review's I1).
//
// Mutations: drop the withinDiskArtifactRoot check in coldSourcePathCheck - the
// outside row goes red; drop its CheckWriteRoot - the symlink row goes red;
// drop the call in removeColdMigratedSourceDisks - the removal rows go red.
func TestColdSourcePathIsCheckedBeforeTheCopyAndTheRemoval(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	data, pki, other := filepath.Join(root, "data"), filepath.Join(root, "pki"), filepath.Join(root, "other")
	for _, d := range []string{filepath.Join(data, "disks"), pki, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(pki, filepath.Join(data, "disks", "link")); err != nil {
		t.Fatal(err)
	}
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := &Server{hostName: "src", dataDir: data, pkiDir: pki, db: db}

	ok := filepath.Join(data, "disks", "ok.qcow2")
	cases := []struct {
		name, path string
		allowed    bool
	}{
		{"its own disks dir", ok, true},
		{"outside every disk place", filepath.Join(other, "x.qcow2"), false},
		{"the PKI dir", filepath.Join(pki, "key.pem"), false},
		{"through a link in the disks dir to the PKI dir", filepath.Join(data, "disks", "link", "key.pem"), false},
		{"the state db", filepath.Join(data, "state.db"), false},
	}
	var disks []corrosion.DiskRecord
	for _, tc := range cases {
		if err := os.WriteFile(tc.path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		disks = append(disks, corrosion.DiskRecord{VMName: "v", DiskName: tc.name, Path: tc.path})
		if err := s.coldSourcePathCheck(tc.path); (err == nil) != tc.allowed {
			t.Errorf("%s: coldSourcePathCheck(%s) = %v, want allowed=%v", tc.name, tc.path, err, tc.allowed)
		}
	}
	s.removeColdMigratedSourceDisks(ctx, "v", disks)
	for _, tc := range cases {
		_, err := os.Lstat(tc.path)
		if tc.allowed && err == nil {
			t.Errorf("%s: the source copy %s was not removed", tc.name, tc.path)
		}
		if !tc.allowed && err != nil {
			t.Errorf("%s: %s was removed from outside the source's disk places (%v)", tc.name, tc.path, err)
		}
	}
}
