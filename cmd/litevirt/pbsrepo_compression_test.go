package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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

// daemonStub stands in for the daemon's SetBackupRepoCompression: it records
// every request and, when open, does what the daemon does with a grant (a
// local zstd init or conversion); closed, it refuses as the gate does.
type daemonStub struct {
	open bool
	reqs []*pb.SetBackupRepoCompressionRequest
	down bool // no daemon to ask
}

const stubRefusal = "the cluster upgrade must finish first (backup_zstd needs release_2026_11_v1)"

func (d *daemonStub) call(_ context.Context, req *pb.SetBackupRepoCompressionRequest) (*pb.SetBackupRepoCompressionResponse, error) {
	d.reqs = append(d.reqs, req)
	if d.down {
		return nil, errors.New("connect: no daemon")
	}
	if !d.open {
		return nil, status.Error(codes.FailedPrecondition, stubRefusal)
	}
	var r *pbsstore.Repo
	var err error
	if req.GetInit() {
		opts := pbsstore.InitOptions{Compression: pbsstore.CompressionZstd}
		if req.GetEncrypted() {
			opts.Encryption = pbsstore.EncryptionModeAESGCM
		}
		r, err = pbsstore.InitUngated(req.GetRepo(), opts)
	} else if r, err = pbsstore.Open(req.GetRepo()); err == nil {
		err = r.SetCompressionUngated(pbsstore.CompressionZstd)
	}
	if err != nil {
		return nil, err
	}
	return &pb.SetBackupRepoCompressionResponse{Host: "node-x", Path: r.Root(), Compression: r.Compression(),
		SchemaVersion: int32(r.Meta().SchemaVersion)}, nil
}

// withFeature installs a daemon stub, open or closed, for the test.
func withFeature(t *testing.T, open bool) *daemonStub {
	t.Helper()
	d := &daemonStub{open: open}
	prev := repoZstdViaDaemon
	repoZstdViaDaemon = d.call
	t.Cleanup(func() { repoZstdViaDaemon = prev })
	return d
}

// A plain init's stdout is byte-identical to main's (no compression suffix):
// main:cmd/litevirt/pbsrepo.go prints exactly these lines.
func TestBackupRepoInit_DefaultStdoutIsMains(t *testing.T) {
	withFeature(t, true)
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "Repository initialised at %s\n"},
		{[]string{"--compression", "none"}, "Repository initialised at %s\n"},
		{[]string{"--encrypted", "--key-file", key},
			"Encrypted repository initialised at %s\nKeep the key file safe — without it, no chunk can be decrypted.\n"},
	} {
		dir := filepath.Join(t.TempDir(), "repo")
		var err error
		out := captureStdout(t, func() { err = runBackupRepoCmd(t, append([]string{"init", dir}, tc.args...)...) })
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.Replace(tc.want, "%s", openRepo(t, dir).Root(), 1); out != want {
			t.Fatalf("init %v: stdout = %q, want main's %q", tc.args, out, want)
		}
	}
}

// I1: a plain init is the local, uncompressed repository main creates, however
// the cluster stands: the daemon is never asked, even when backup_zstd is open,
// so where the repo lands does not depend on credentials or connectivity.
func TestBackupRepoInit_DefaultIsLocalAndUncompressed(t *testing.T) {
	for _, open := range []bool{false, true} {
		d := withFeature(t, open)
		dir := filepath.Join(t.TempDir(), "repo")
		if err := runBackupRepoCmd(t, "init", dir); err != nil {
			t.Fatal(err)
		}
		if r := openRepo(t, dir); r.Compression() != pbsstore.CompressionNone || r.Meta().SchemaVersion != 1 {
			t.Fatalf("open=%v: compression=%q schema=%d, want none and 1", open, r.Compression(), r.Meta().SchemaVersion)
		}
		if len(d.reqs) != 0 {
			t.Fatalf("open=%v: a plain init asked the daemon: %+v", open, d.reqs)
		}
	}
}

// An explicit zstd before the latch needs --force; none always works. The
// daemon is asked for zstd without --force, and never with it.
func TestBackupRepoInit_ExplicitZstdIsGated(t *testing.T) {
	d := withFeature(t, false)
	dir := filepath.Join(t.TempDir(), "repo")
	err := runBackupRepoCmd(t, "init", dir, "--compression", "zstd")
	if err == nil || !strings.Contains(err.Error(), "backup_zstd") || !strings.Contains(err.Error(), "--force") ||
		!strings.Contains(err.Error(), "the cluster upgrade must finish first") {
		t.Fatalf("zstd before the latch: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "repo.json")); serr == nil {
		t.Fatal("a refused zstd init created the repository")
	}
	if len(d.reqs) != 1 {
		t.Fatalf("explicit zstd asked the daemon %+v, want one request that fails when closed", d.reqs)
	}
	if err := runBackupRepoCmd(t, "init", dir, "--compression", "zstd", "--force"); err != nil {
		t.Fatalf("--force: %v", err)
	}
	if len(d.reqs) != 1 {
		t.Fatal("--force asked the daemon")
	}
	if r := openRepo(t, dir); r.Compression() != pbsstore.CompressionZstd {
		t.Fatalf("--force: %q", r.Compression())
	}
	if err := runBackupRepoCmd(t, "init", filepath.Join(t.TempDir(), "x"), "--compression", "gzip"); err == nil {
		t.Fatal("init accepted an unknown compression mode")
	}
	if err := runBackupRepoCmd(t, "init", filepath.Join(t.TempDir(), "n"), "--compression", "none"); err != nil || len(d.reqs) != 1 {
		t.Fatalf("none: err=%v requests=%d, want no daemon call", err, len(d.reqs))
	}
}

// Once open, an explicit zstd (and an encrypted one) is created by the daemon.
func TestBackupRepoInit_ExplicitZstdThroughTheDaemon(t *testing.T) {
	d := withFeature(t, true)
	dir := filepath.Join(t.TempDir(), "repo")
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	out := captureStdout(t, func() {
		err = runBackupRepoCmd(t, "init", dir, "--compression", "zstd", "--encrypted", "--key-file", key)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Created on host node-x") {
		t.Fatalf("the CLI did not say which host created the repo:\n%s", out)
	}
	if len(d.reqs) != 1 || !d.reqs[0].GetEncrypted() || !d.reqs[0].GetInit() {
		t.Fatalf("daemon request %+v, want an encrypted init", d.reqs)
	}
	if r := openRepo(t, dir); r.Compression() != pbsstore.CompressionZstd || !r.IsEncrypted() {
		t.Fatalf("repo: compression=%q encrypted=%v", r.Compression(), r.IsEncrypted())
	}
}

// m-12: set-compression to zstd is gated the same way.
func TestBackupRepoSetCompression_Gated(t *testing.T) {
	d := withFeature(t, false)
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
	n := len(d.reqs)
	if err := runBackupRepoCmd(t, "set-compression", dir, "zstd", "--force"); err != nil {
		t.Fatal(err)
	}
	if len(d.reqs) != n {
		t.Fatal("--force asked the daemon")
	}
	if r := openRepo(t, dir); r.Compression() != pbsstore.CompressionZstd {
		t.Fatalf("after --force: %q", r.Compression())
	}
	if err := runBackupRepoCmd(t, "set-compression", dir, "none"); err != nil {
		t.Fatalf("none is never gated: %v", err)
	}
	if len(d.reqs) != n {
		t.Fatal("turning compression off asked the daemon")
	}
}

// Open: set-compression zstd goes through the daemon, which converts the repo.
func TestBackupRepoSetCompression_ThroughTheDaemon(t *testing.T) {
	d := withFeature(t, true)
	dir := filepath.Join(t.TempDir(), "repo")
	if _, err := pbsstore.Init(dir); err != nil {
		t.Fatal(err)
	}
	var err error
	out := captureStdout(t, func() { err = runBackupRepoCmd(t, "set-compression", dir, "zstd") })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Converted on host node-x") {
		t.Fatalf("the CLI did not say which host converted the repo:\n%s", out)
	}
	if len(d.reqs) != 1 || d.reqs[0].GetInit() || d.reqs[0].GetRepo() != dir {
		t.Fatalf("daemon request %+v, want a conversion of %s", d.reqs, dir)
	}
	if r := openRepo(t, dir); r.Compression() != pbsstore.CompressionZstd || r.Meta().SchemaVersion != 2 {
		t.Fatalf("converted repo: %q schema %d", r.Compression(), r.Meta().SchemaVersion)
	}
}
