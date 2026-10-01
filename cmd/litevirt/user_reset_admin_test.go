package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

func resetAdminTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// offlineReset runs the daemon-down path the way runResetAdmin does.
func offlineReset(t *testing.T, db *corrosion.Client, dataDir, pw string) error {
	t.Helper()
	password, hash, err := mintAdminPassword()
	if err != nil {
		t.Fatalf("mintAdminPassword: %v", err)
	}
	return resetAdminOffline(context.Background(), db, dataDir, pw, "root", password, hash, io.Discard)
}

// `lv user reset-admin` must not resurrect a deliberately deleted admin.
//
// GetUser filters `deleted_at IS NULL`, so a tombstoned admin reads as absent.
// The old create-if-missing branch then called InsertUser, whose first branch
// reactivates a soft-deleted row (`SET deleted_at = NULL`) — replicating a
// revoked account back to life cluster-wide, with a fresh password, from a
// command whose documented job is to *reset* an existing one.
//
// The daemon's own seed path was given a tombstone-aware guard; this is the
// second mint site, and it had none.
func TestResetAdminPassword_DoesNotResurrectADeletedAdmin(t *testing.T) {
	ctx := context.Background()
	db := resetAdminTestDB(t)
	pw := filepath.Join(t.TempDir(), "admin-password")

	if err := corrosion.InsertUser(ctx, db, "admin", "admin", "$2a$10$stub"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := corrosion.DeleteUser(ctx, db, "admin"); err != nil {
		t.Fatalf("delete admin: %v", err)
	}

	err := offlineReset(t, db, t.TempDir(), pw)
	if err == nil {
		t.Fatal("reset-admin succeeded against a deleted admin; it either resurrected the " +
			"revoked account or minted a new one, and that replicates cluster-wide")
	}
	if u, gErr := corrosion.GetUser(ctx, db, "admin"); gErr != nil || u != nil {
		t.Errorf("the admin account is live again after reset-admin (%v, err %v)", u, gErr)
	}
	if _, sErr := os.Stat(pw); sErr == nil {
		t.Error("a password file was written for an account that must not exist")
	}
}

// A cluster that genuinely has no admin must get a clear refusal, not a silent
// mint — on a joining node the credential arrives by replication.
func TestResetAdminPassword_RefusesWhenThereIsNoAdminAtAll(t *testing.T) {
	db := resetAdminTestDB(t)
	pw := filepath.Join(t.TempDir(), "admin-password")

	err := offlineReset(t, db, t.TempDir(), pw)
	if err == nil {
		t.Fatal("reset-admin minted an admin on a cluster that has none; that row wins LWW " +
			"and replaces the real credential on every peer once replication converges")
	}
	if !strings.Contains(err.Error(), "replicat") {
		t.Errorf("the refusal does not tell the operator where the credential comes from: %v", err)
	}
}

// The ordinary case still works.
func TestResetAdminPassword_ResetsALiveAdmin(t *testing.T) {
	ctx := context.Background()
	db := resetAdminTestDB(t)
	pw := filepath.Join(t.TempDir(), "admin-password")

	if err := corrosion.InsertUser(ctx, db, "admin", "admin", "$2a$10$stub"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := offlineReset(t, db, t.TempDir(), pw); err != nil {
		t.Fatalf("resetAdminOffline: %v", err)
	}

	u, err := corrosion.GetUser(ctx, db, "admin")
	if err != nil || u == nil {
		t.Fatalf("admin missing after a reset: %v %v", u, err)
	}
	if u.PasswordHash == "$2a$10$stub" {
		t.Error("the password hash was not changed")
	}
	b, err := os.ReadFile(pw)
	if err != nil {
		t.Fatalf("read password file: %v", err)
	}
	if len(strings.TrimSpace(string(b))) != 32 {
		t.Errorf("password file holds %q, want a 32-char hex password", strings.TrimSpace(string(b)))
	}
	if fi, _ := os.Stat(pw); fi != nil && fi.Mode().Perm() != 0600 {
		t.Errorf("password file mode = %04o, want 0600", fi.Mode().Perm())
	}
}

// A failing lookup must not read as "there is no admin".
//
// This is the same class as the merged "a read that fails must not read as
// absence" work: with the error discarded, a transient local database failure is
// indistinguishable from an empty users table, and whatever the nil branch does
// then happens for the wrong reason.
func TestResetAdminPassword_AFailedLookupIsNotAnAbsentAdmin(t *testing.T) {
	ctx := context.Background()
	db := resetAdminTestDB(t)
	pw := filepath.Join(t.TempDir(), "admin-password")

	if err := corrosion.InsertUser(ctx, db, "admin", "admin", "$2a$10$stub"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	// Make the read fail: a closed client cannot answer.
	db.Close()

	err := offlineReset(t, db, t.TempDir(), pw)
	if err == nil {
		t.Fatal("reset-admin succeeded although the admin lookup could not run")
	}
	if strings.Contains(err.Error(), "no live admin account") {
		t.Errorf("a failed lookup was reported as an absent admin: %v\n"+
			"the database was unreadable, not empty — those need different answers", err)
	}
}

// fakeResetDaemon answers ResetAdminPassword with err and remembers the request.
type fakeResetDaemon struct {
	pb.LiteVirtClient
	err error
	got *pb.ResetAdminPasswordRequest
}

func (f *fakeResetDaemon) ResetAdminPassword(_ context.Context, req *pb.ResetAdminPasswordRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	f.got = req
	if f.err != nil {
		return nil, f.err
	}
	return &emptypb.Empty{}, nil
}

func envFor(t *testing.T, d *fakeResetDaemon, dataDir string, openDB func() (*corrosion.Client, error)) resetAdminEnv {
	t.Helper()
	return resetAdminEnv{
		connect: func() (pb.LiteVirtClient, func(), error) { return d, func() {}, nil },
		openDB:  openDB,
		dataDir: dataDir,
		pwPath:  filepath.Join(t.TempDir(), "admin-password"),
		osUser:  "tim",
		out:     io.Discard,
		errOut:  io.Discard,
	}
}

func noDB(t *testing.T) func() (*corrosion.Client, error) {
	return func() (*corrosion.Client, error) {
		t.Error("reset-admin opened the local database although the daemon answered")
		return nil, os.ErrInvalid
	}
}

// TestRunResetAdmin_DaemonUpGoesThroughTheDaemon: with the daemon answering,
// the CLI touches neither the database nor the journal, sends only the hash,
// and the password file holds the password that hash accepts.
func TestRunResetAdmin_DaemonUpGoesThroughTheDaemon(t *testing.T) {
	d := &fakeResetDaemon{}
	dataDir := t.TempDir()
	env := envFor(t, d, dataDir, noDB(t))
	if err := runResetAdmin(context.Background(), env); err != nil {
		t.Fatalf("runResetAdmin: %v", err)
	}
	if d.got == nil {
		t.Fatal("the daemon was never asked")
	}
	b, err := os.ReadFile(env.pwPath)
	if err != nil {
		t.Fatalf("read password file: %v", err)
	}
	pw := strings.TrimSpace(string(b))
	if bcrypt.CompareHashAndPassword([]byte(d.got.PasswordHash), []byte(pw)) != nil {
		t.Error("the hash sent to the daemon does not accept the password written to the file")
	}
	if strings.Contains(d.got.PasswordHash, pw) || d.got.OsUser != "tim" {
		t.Errorf("request = %+v; want only the hash and the OS user", d.got)
	}
	if _, err := os.Stat(filepath.Join(dataDir, corrosion.PendingAuditDirName)); !os.IsNotExist(err) {
		t.Errorf("the daemon path journalled an entry as well (stat err %v); it would be folded as a second row", err)
	}
}

// TestRunResetAdmin_ADaemonAnswerIsNotAFallback: a refusal, or a timeout that
// may have applied the reset, must not send the CLI round the daemon.
func TestRunResetAdmin_ADaemonAnswerIsNotAFallback(t *testing.T) {
	for _, code := range []codes.Code{codes.PermissionDenied, codes.FailedPrecondition, codes.InvalidArgument, codes.DeadlineExceeded, codes.Internal} {
		t.Run(code.String(), func(t *testing.T) {
			d := &fakeResetDaemon{err: status.Error(code, "no")}
			env := envFor(t, d, t.TempDir(), noDB(t))
			if err := runResetAdmin(context.Background(), env); status.Code(err) != code {
				t.Fatalf("err = %v, want the daemon's %s", err, code)
			}
			if _, err := os.Stat(env.pwPath); !os.IsNotExist(err) {
				t.Error("a password file was written for a reset the daemon did not make")
			}
		})
	}
}

// signedDaemonDB is the daemon's own client on dataDir: file backed, with the
// host's signing key adopted, exactly as litevirtd opens it.
func signedDaemonDB(t *testing.T, dataDir, host string) *corrosion.Client {
	t.Helper()
	ctx := context.Background()
	pkiDir := t.TempDir()
	caCert, caKey := filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := pki.GenerateHostCert(caCert, caKey, filepath.Join(pkiDir, "host.crt"),
		filepath.Join(pkiDir, "host.key"), host, net.IPv4(127, 0, 0, 1)); err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}
	db, err := corrosion.NewLocalClient(dataDir, host)
	if err != nil {
		t.Fatalf("NewLocalClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	kr, err := corrosion.LoadAuditKeyring(pkiDir, host)
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	db.SetAuditKeyring(kr)
	if _, err := corrosion.AdoptAuditKey(ctx, db, kr, host); err != nil {
		t.Fatalf("AdoptAuditKey: %v", err)
	}
	return db
}

// TestRunResetAdmin_DaemonDownIsAuditedWhenTheDaemonStarts is the daemon-down
// path end to end: the daemon is unreachable, the CLI resets in the local
// database and journals the entry, and when the daemon comes up and folds the
// journal there is exactly one signed user.reset-admin row, no secret in it,
// and `lv audit verify` is clean.
func TestRunResetAdmin_DaemonDownIsAuditedWhenTheDaemonStarts(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	daemonDB := signedDaemonDB(t, dataDir, "node-0")
	if err := corrosion.InsertUser(ctx, daemonDB, "admin", "admin", "$2a$10$stub"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := corrosion.InsertAuditLog(ctx, daemonDB, corrosion.AuditRecord{
		Username: "admin", HostName: "node-0", Action: "vm.start", Target: "vm1", Result: "ok",
	}); err != nil {
		t.Fatalf("seed audit row: %v", err)
	}

	d := &fakeResetDaemon{err: status.Error(codes.Unavailable, "connection refused")}
	env := envFor(t, d, dataDir, func() (*corrosion.Client, error) {
		return corrosion.NewLocalClient(dataDir, "node-0")
	})
	if err := runResetAdmin(ctx, env); err != nil {
		t.Fatalf("runResetAdmin: %v", err)
	}
	b, err := os.ReadFile(env.pwPath)
	if err != nil {
		t.Fatalf("read password file: %v", err)
	}
	password := strings.TrimSpace(string(b))
	u, err := corrosion.GetUser(ctx, daemonDB, "admin")
	if err != nil || u == nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		t.Fatalf("the stored admin hash does not accept the password in the file (%v, %v)", u, err)
	}
	if n := countResetRows(t, daemonDB); n != 0 {
		t.Fatalf("%d reset rows before the daemon folded anything; the CLI must not write audit_log", n)
	}

	// The daemon starts.
	if n, err := corrosion.FoldPendingAudit(ctx, daemonDB, dataDir, "node-0"); err != nil || n != 1 {
		t.Fatalf("FoldPendingAudit = %d, %v; want 1, nil", n, err)
	}
	rows, err := daemonDB.Query(ctx, `SELECT username, host_name, target, detail, result, signature
		FROM audit_log WHERE action = 'user.reset-admin'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("want exactly one user.reset-admin row, got %d (%v)", len(rows), err)
	}
	r := rows[0]
	if r.String("username") != "root@node-0" || r.String("target") != "admin" || r.String("result") != "ok" ||
		r.String("signature") == "" || !strings.Contains(r.String("detail"), "os_user=tim") {
		t.Errorf("row = %q/%q/%q/%q signed=%v", r.String("username"), r.String("target"),
			r.String("detail"), r.String("result"), r.String("signature") != "")
	}
	for _, col := range []string{"username", "host_name", "target", "detail", "result"} {
		if v := r.String(col); strings.Contains(v, password) || strings.Contains(v, u.PasswordHash) || strings.Contains(v, "$2a$") {
			t.Errorf("audit column %s carries secret material: %q", col, v)
		}
	}

	if err := corrosion.InsertAuditLog(ctx, daemonDB, corrosion.AuditRecord{
		Username: "admin", HostName: "node-0", Action: "vm.stop", Target: "vm1", Result: "ok",
	}); err != nil {
		t.Fatalf("audit row after the fold: %v", err)
	}
	res, err := corrosion.VerifyAuditChain(ctx, daemonDB)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if res.Tampered() || res.Unsigned != 0 {
		t.Fatalf("`lv audit verify` is not clean after a daemon-down reset: %+v", res)
	}
}

// TestRunResetAdmin_NoJournalNoReset: an admin reset that cannot be put on the
// record is not made.
func TestRunResetAdmin_NoJournalNoReset(t *testing.T) {
	ctx := context.Background()
	db := resetAdminTestDB(t)
	if err := corrosion.InsertUser(ctx, db, "admin", "admin", "$2a$10$stub"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	// A data dir that is a regular file: the journal cannot be created under it.
	notADir := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := offlineReset(t, db, notADir, filepath.Join(t.TempDir(), "admin-password")); err == nil {
		t.Fatal("reset-admin reset the password although it could not journal the audit entry")
	}
	if u, _ := corrosion.GetUser(ctx, db, "admin"); u == nil || u.PasswordHash != "$2a$10$stub" {
		t.Fatal("the admin password changed with no audit entry journalled")
	}
}

func countResetRows(t *testing.T, db *corrosion.Client) int {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT id FROM audit_log WHERE action = 'user.reset-admin'`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return len(rows)
}
