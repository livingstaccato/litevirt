package main

import (
	"io"
	"path/filepath"
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

// A repo created by `lv backup repo init` compresses new backups by default.
func TestBackupRepoInit_CompressesByDefault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	if err := runBackupRepoCmd(t, "init", dir); err != nil {
		t.Fatalf("init: %v", err)
	}
	r, err := pbsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Compression() != pbsstore.CompressionZstd {
		t.Fatalf("default init compression = %q, want zstd", r.Compression())
	}
}

// --compression none keeps a new repo in the format every release reads.
func TestBackupRepoInit_CompressionNone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	if err := runBackupRepoCmd(t, "init", dir, "--compression", "none"); err != nil {
		t.Fatalf("init: %v", err)
	}
	r, err := pbsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Compression() != pbsstore.CompressionNone || r.Meta().SchemaVersion != 1 {
		t.Fatalf("--compression none: compression=%q schema=%d, want none and 1", r.Compression(), r.Meta().SchemaVersion)
	}
	if err := runBackupRepoCmd(t, "init", filepath.Join(t.TempDir(), "x"), "--compression", "gzip"); err == nil {
		t.Fatal("init accepted an unknown compression mode")
	}
}

func TestBackupRepoSetCompression(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	if err := runBackupRepoCmd(t, "init", dir, "--compression", "none"); err != nil {
		t.Fatal(err)
	}
	if err := runBackupRepoCmd(t, "set-compression", dir, "zstd"); err != nil {
		t.Fatalf("set-compression: %v", err)
	}
	r, err := pbsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Compression() != pbsstore.CompressionZstd {
		t.Fatalf("after set-compression zstd: %q", r.Compression())
	}
}
