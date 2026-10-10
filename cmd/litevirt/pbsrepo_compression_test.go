package main

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pbsstore"
)

func runBackupRepoCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newBackupRepoCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd.Execute()
}

func openRepo(t *testing.T, dir string) *pbsstore.Repo {
	t.Helper()
	r, err := pbsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// withFeature opens or closes backup_zstd for the test.
func withFeature(t *testing.T, open bool) {
	t.Helper()
	prev := releaseFeatureOpen
	releaseFeatureOpen = func(context.Context, string) (bool, string) { return open, "the release token has not latched" }
	t.Cleanup(func() { releaseFeatureOpen = prev })
}

// Before the release token latches (backup_zstd closed), a new repo is
// uncompressed: older peers refuse a schema-2 repo.
func TestBackupRepoInit_DefaultFollowsTheReleaseToken(t *testing.T) {
	withFeature(t, false)
	dir := filepath.Join(t.TempDir(), "repo")
	if err := runBackupRepoCmd(t, "init", dir); err != nil {
		t.Fatal(err)
	}
	if r := openRepo(t, dir); r.Compression() != pbsstore.CompressionNone || r.Meta().SchemaVersion != 1 {
		t.Fatalf("closed gate: compression=%q schema=%d, want none and 1", r.Compression(), r.Meta().SchemaVersion)
	}
	withFeature(t, true)
	dir2 := filepath.Join(t.TempDir(), "repo")
	if err := runBackupRepoCmd(t, "init", dir2); err != nil {
		t.Fatal(err)
	}
	if r := openRepo(t, dir2); r.Compression() != pbsstore.CompressionZstd {
		t.Fatalf("open gate: compression=%q, want zstd", r.Compression())
	}
}

// An explicit zstd before the latch needs --force; none always works.
func TestBackupRepoInit_ExplicitZstdIsGated(t *testing.T) {
	withFeature(t, false)
	dir := filepath.Join(t.TempDir(), "repo")
	err := runBackupRepoCmd(t, "init", dir, "--compression", "zstd")
	if err == nil || !strings.Contains(err.Error(), "backup_zstd") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("zstd before the latch: %v", err)
	}
	if err := runBackupRepoCmd(t, "init", dir, "--compression", "zstd", "--force"); err != nil {
		t.Fatalf("--force: %v", err)
	}
	if r := openRepo(t, dir); r.Compression() != pbsstore.CompressionZstd {
		t.Fatalf("--force: %q", r.Compression())
	}
	if err := runBackupRepoCmd(t, "init", filepath.Join(t.TempDir(), "x"), "--compression", "gzip"); err == nil {
		t.Fatal("init accepted an unknown compression mode")
	}
}

// m-12: set-compression to zstd is gated the same way.
func TestBackupRepoSetCompression_Gated(t *testing.T) {
	withFeature(t, false)
	dir := filepath.Join(t.TempDir(), "repo")
	if err := runBackupRepoCmd(t, "init", dir); err != nil {
		t.Fatal(err)
	}
	if err := runBackupRepoCmd(t, "set-compression", dir, "zstd"); err == nil || !strings.Contains(err.Error(), "backup_zstd") {
		t.Fatalf("set-compression zstd before the latch: %v", err)
	}
	if r := openRepo(t, dir); r.Compression() != pbsstore.CompressionNone || r.Meta().SchemaVersion != 1 {
		t.Fatal("a refused set-compression changed the repo")
	}
	if err := runBackupRepoCmd(t, "set-compression", dir, "zstd", "--force"); err != nil {
		t.Fatal(err)
	}
	if r := openRepo(t, dir); r.Compression() != pbsstore.CompressionZstd {
		t.Fatalf("after --force: %q", r.Compression())
	}
	if err := runBackupRepoCmd(t, "set-compression", dir, "none"); err != nil {
		t.Fatalf("none is never gated: %v", err)
	}
}
