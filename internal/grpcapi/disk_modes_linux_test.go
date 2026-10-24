//go:build linux

package grpcapi

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// An import placed on a filesystem with neither link() nor RENAME_NOREPLACE
// is a copy: it is owner-only whatever the mode of what it copied.
//
// Mutation: copy the source's mode again (copyIntoPlace) — this goes red.
func TestPlaceNoReplace_ACopiedImportIsOwnerOnly(t *testing.T) {
	umask022(t)
	noLinkNoRenameNoReplace(t)
	dir := t.TempDir()
	src, dst := filepath.Join(dir, ".a.convert-x"), filepath.Join(dir, "a.qcow2")
	if err := os.WriteFile(src, []byte("guest data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := placeNoReplace(context.Background(), src, dst, nil); err != nil {
		t.Fatal(err)
	}
	wantMode(t, dst, 0o600)
}

// qemu-img writes into the file a caller made for it and keeps that file's
// mode: every convert in the daemon (move, copy, replicate, restore, import,
// promote) writes into a 0600 temp, so its output is 0600 — and a destination
// not there yet is made 0600 by convertImage itself before qemu-img runs
// (qemu-img writes through its descriptor). Needs a real qemu-img.
//
// Mutation: create a missing destination with a wider mode in openConvertTop
// — this goes red.
func TestConvertImage_OutputIsOwnerOnly(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
	umask022(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	noop := func(*pb.MoveVolumeProgress) error { return nil }
	// Into a temp the caller made, as every caller does.
	f, err := os.CreateTemp(dir, ".repl-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := convertImage(context.Background(), src, "qcow2", nil, f.Name(), noop); err != nil {
		t.Fatal(err)
	}
	wantMode(t, f.Name(), 0o600)
	// Onto a name nothing holds: convertImage creates it, owner-only.
	fresh := filepath.Join(dir, "fresh.qcow2")
	if err := convertImage(context.Background(), src, "qcow2", nil, fresh, noop); err != nil {
		t.Fatal(err)
	}
	wantMode(t, fresh, 0o600)
}
