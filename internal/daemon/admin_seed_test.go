package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A node joining an existing cluster must not mint an admin credential.
//
// Confirmed on a live five-node cluster. seedAdminUser runs 163 lines before
// repl.Start, so a joining node reads an empty `users` table, inserts its own
// `admin` row with a current updated_at, and publishes it the moment replication
// comes up.
//
// Nothing in the replication layer stops that row, on either lane. `users`
// resolves under policyChain(), which reads like a fail-to-human guard but is a
// TIE chain: lwwOrder settles every non-tie conflict itself, and only an
// exact-instant tie ever reaches resolveTie. A fresh mint is strictly NEWER, so
// anti-entropy applies it on the `ord < 0` fall-through without consulting the
// resolver, and the WAL lane applies it through applyLWWGated.
//
// So the last node to start its daemon owns the cluster's admin password and
// every earlier node's /etc/litevirt/admin-password is silently dead. It does
// not need an unusual join: an ordinary four-node bootstrap ends with three
// wrong password files, no error, no warning and no audit row.
//
// The assertion is on the `users` row rather than the password file, because the
// row is what replicates — and it is written first, so a node that inserts and
// then fails to write its own file has still taken the cluster's credential.
func TestSeedAdminUser_AJoiningNodeMintsNoCredential(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	// What a joiner looks like at first start: an empty local database, and a
	// config.yaml the adding node wrote with the cluster's gossip peers in it.
	// `lv host add` refuses to provision a node with an empty join_peers ("would
	// be provisioned with an empty join_peers and never reach the cluster"), so
	// this list is non-empty on every joining node before its daemon starts.
	// adminPasswordPath even though a correct joiner never writes it: the guard is
	// mutation-verified by deleting it and re-running, and an unfixed seedAdminUser
	// then writes the real /etc/litevirt/admin-password. Harmless as an ordinary
	// user, but as root on a lab node that clobbers a live credential file.
	d := &Daemon{db: db, adminPasswordPath: filepath.Join(t.TempDir(), "admin-password"), cfg: &Config{
		HostName:  "node-5",
		JoinPeers: []string{"10.77.0.11:7946", "10.77.0.12:7946"},
	}}

	// The error is deliberately not the assertion. Writing the password file can
	// fail for unrelated reasons (no /etc/litevirt, not root); the finding is the
	// replicated row, which InsertUser writes before the file either way.
	_ = d.seedAdminUser(ctx)

	users, err := corrosion.ListUsers(ctx, db)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("a joining node seeded %d user(s) %v into an empty local database; "+
			"replication publishes that row under applyLWWGated, so its fresh updated_at "+
			"overwrites the cluster's real admin credential and every other node's "+
			"password file stops working", len(users), users)
	}
}

// The founder still has to seed, or the fix is just a cluster nobody can log
// into. `lv host init` leaves join_peers empty, and that first start is the one
// moment an admin credential legitimately gets minted.
//
// Note for anyone reading this as documentation: `lv host init` does NOT print
// the password, and after this change the file exists on exactly one node in the
// cluster. Where to find it belongs in docs/, not in a comment here.
//
// This is the guard against over-fixing, so it is worth nothing unless it can
// fail: deleting the seed, or widening the joiner check to skip unconditionally,
// must turn it red.
func TestSeedAdminUser_AFounderStillMintsTheFirstCredential(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	pwFile := filepath.Join(t.TempDir(), "admin-password")
	d := founderDaemon(t, db, pwFile)

	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("seedAdminUser on a founder: %v", err)
	}

	users, err := corrosion.ListUsers(ctx, db)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Username != "admin" {
		t.Fatalf("founder seeded %v; `lv host init` prints a password the operator is "+
			"told to log in with, and nothing else creates that account", users)
	}

	pw, err := os.ReadFile(pwFile)
	if err != nil {
		t.Fatalf("read the seeded password file: %v", err)
	}
	if len(strings.TrimSpace(string(pw))) == 0 {
		t.Fatal("the seeded password file is empty; the operator has an admin account " +
			"and no way to authenticate as it")
	}
}

// The sole founder — a one-node cluster, never added to, join_peers still empty
// — restarts straight into the seed path. Nothing but the `len(users) > 0` guard
// stops it re-minting, and the joiner check deliberately does not cover it, so
// this is the only test that holds that guard down.
//
// Re-minting here is the same operator-visible failure as the join bug, reached
// by a different route: a new row with a fresh updated_at, a rewritten password
// file, and the password the operator was given no longer working.
func TestSeedAdminUser_ASoleFounderDoesNotReMintOnRestart(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	pwFile := filepath.Join(t.TempDir(), "admin-password")
	d := founderDaemon(t, db, pwFile)
	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("first start: %v", err)
	}
	first, err := os.ReadFile(pwFile)
	if err != nil {
		t.Fatalf("read password file: %v", err)
	}

	// Restart. Still a cluster of one, so join_peers is still empty. Re-arm the
	// marker so the `users` guard is the only thing standing between this
	// restart and a second mint.
	rearmFounderMarker(t, d)
	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("restart: %v", err)
	}

	users, err := corrosion.ListUsers(ctx, db)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("a sole founder restart left %d admin users: %v", len(users), users)
	}
	second, err := os.ReadFile(pwFile)
	if err != nil {
		t.Fatalf("read password file after restart: %v", err)
	}
	if string(first) != string(second) {
		t.Error("a restart re-minted the admin credential and rewrote the password file; " +
			"the password the operator was given at `lv host init` stops working")
	}
}

// The skip path must not point the operator at a file it never wrote.
//
// This is the trigger for the worse bug next door. A joiner now writes no
// /etc/litevirt/admin-password; if the log still names that path, the operator
// greps for it, finds nothing, and escalates to the one documented recovery —
// `lv user reset-admin` (docs/cli-reference.md). That once minted a fresh admin
// row on a node that had not converged, which was #186 again by another route;
// it now only resets a live admin and refuses there, which reads as a second
// failure. So the message is load-bearing, not cosmetic: it has to say that no
// file is written here and that the credential arrives by replication.
func TestSeedAdminUser_TheSkipLogDoesNotNameAFileItNeverWrote(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	d := &Daemon{db: db, adminPasswordPath: filepath.Join(t.TempDir(), "admin-password"), cfg: &Config{
		HostName:  "node-5",
		JoinPeers: []string{"10.77.0.11:7946"},
	}}
	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("seedAdminUser on a joiner: %v", err)
	}

	logged := buf.String()
	if logged == "" {
		t.Fatal("a node that silently declines to create the admin account logged nothing at all")
	}
	if strings.Contains(logged, adminPasswordFile) {
		t.Errorf("the skip log names %s, which this branch never writes:\n\t%s\n"+
			"the operator greps for that file, finds nothing, and reaches for "+
			"`lv user reset-admin`, which refuses on a node with no live admin",
			adminPasswordFile, strings.TrimSpace(logged))
	}
	if !strings.Contains(logged, "replicat") {
		t.Errorf("the skip log never tells the operator the credential arrives by "+
			"replication, so it reads as a failure to create one:\n\t%s",
			strings.TrimSpace(logged))
	}
}

// The password file must end up 0600 even when it already existed.
//
// os.WriteFile applies its mode only when it CREATES the file, so a pre-existing
// loose-permissioned admin-password keeps whatever mode it had — and the next
// seed writes the cluster admin's plaintext password into it. The installer
// creates /etc/litevirt with a plain `mkdir -p` (umask default 0755), so any
// local account on the node can then read it and log in as cluster admin from
// anywhere. A restore that does not preserve modes, a config-management copy, or
// an operator's `touch` while hunting a lost credential all produce that file.
//
// internal/cli/host_init.go already treats this exact hazard as a bug and follows
// its WriteFile with an explicit Chmod; this path did not.
func TestSeedAdminUser_TightensAPreExistingLoosePasswordFile(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	pwFile := filepath.Join(t.TempDir(), "admin-password")
	if err := os.WriteFile(pwFile, []byte("left over from a restore\n"), 0644); err != nil {
		t.Fatalf("pre-create the password file: %v", err)
	}
	if fi, err := os.Stat(pwFile); err != nil || fi.Mode().Perm() != 0644 {
		t.Fatalf("test setup did not produce a 0644 file (umask?): mode=%v err=%v", fi.Mode().Perm(), err)
	}

	d := founderDaemon(t, db, pwFile)
	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("seedAdminUser: %v", err)
	}

	fi, err := os.Stat(pwFile)
	if err != nil {
		t.Fatalf("stat the password file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("the admin password file is mode %04o, not 0600; it holds the cluster "+
			"admin's plaintext password and /etc/litevirt is world-traversable, so any "+
			"local account on this node can read it and authenticate as admin cluster-wide",
			perm)
	}
}

// A deliberately deleted admin must stay deleted.
//
// ListUsers filters `WHERE deleted_at IS NULL`, so a soft-deleted admin reads as
// "this cluster has no users" — and InsertUser's first branch finds the tombstone
// and does `UPDATE users SET role = ?, password_hash = ?, deleted_at = NULL`,
// which replicates under LWW like any other write. So a cluster that moved to
// OIDC and removed the local admin, or that removed it after a credential leak,
// gets the account back — live, role=admin, new password — the next time the
// founder restarts. Whoever can read that node's password file then holds
// cluster admin, and nothing logs that a revoked account came back.
//
// An empty live-user set is not the same fact as a cluster that never had an
// admin, and only the second one justifies minting.
func TestSeedAdminUser_DoesNotResurrectADeletedAdmin(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	pwFile := filepath.Join(t.TempDir(), "admin-password")
	d := founderDaemon(t, db, pwFile)
	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("founder first start: %v", err)
	}

	// The operator moves the cluster to SSO and removes the local admin.
	if err := corrosion.DeleteUser(ctx, db, "admin"); err != nil {
		t.Fatalf("delete the admin account: %v", err)
	}
	if u, err := corrosion.GetUser(ctx, db, "admin"); err != nil || u != nil {
		t.Fatalf("admin is still live after DeleteUser: %v (err %v)", u, err)
	}

	// The founder reboots. Re-arm the marker so this test holds down the
	// ever-existed guard on its own; seeding consumed the first one, and without
	// this the test would pass with that guard deleted.
	rearmFounderMarker(t, d)
	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("founder restart after the admin was deleted: %v", err)
	}

	u, err := corrosion.GetUser(ctx, db, "admin")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u != nil {
		t.Errorf("a restart resurrected the deleted admin account (role %q); the "+
			"un-delete replicates to every peer, so a revoked credential is live "+
			"cluster-wide and whoever reads %s is cluster admin", u.Role, pwFile)
	}
}

// founderDaemon is a node as `lv host init` leaves it at first start: no
// join_peers, and the founder marker in its data dir. Only that combination is
// allowed to mint the cluster's first admin credential.
func founderDaemon(t *testing.T, db *corrosion.Client, pwFile string) *Daemon {
	t.Helper()
	d := &Daemon{db: db, adminPasswordPath: pwFile, cfg: &Config{HostName: "node-1", DataDir: t.TempDir()}}
	rearmFounderMarker(t, d)
	return d
}

func rearmFounderMarker(t *testing.T, d *Daemon) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(d.cfg.DataDir, genesisMarkerName), nil, 0600); err != nil {
		t.Fatalf("write the founder marker: %v", err)
	}
}

// A node with no founder marker must not mint, even with an empty join_peers.
//
// An empty join_peers is an ABSENCE, and #186 survived the join_peers guard by
// every route that leaves one on a node that is not founding anything: a founder
// whose peer list was never written (driving the cluster from a workstation
// leaves it [] for life) and whose state.db was later rebuilt, a member
// re-initialised with `lv host init`, a config restored from a template. Each
// reads an empty `users` table, mints, and publishes a fresh admin row that wins
// LWW cluster-wide.
//
// Founding is now a POSITIVE fact: `lv host init` writes the marker, and only
// while the data dir holds no state.db. Without it there is nothing to found.
func TestSeedAdminUser_NoFounderMarkerMintsNothing(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	pwFile := filepath.Join(t.TempDir(), "admin-password")
	d := &Daemon{db: db, adminPasswordPath: pwFile, cfg: &Config{HostName: "node-1", DataDir: t.TempDir()}}
	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("seedAdminUser without a founder marker: %v", err)
	}

	users, err := corrosion.ListUsers(ctx, db)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("a node with no founder marker minted %v; with an empty state.db and an "+
			"empty join_peers that row is newer than the cluster's real admin and replaces "+
			"it on every node", users)
	}
	if _, err := os.Stat(pwFile); !os.IsNotExist(err) {
		t.Errorf("a node that minted nothing wrote a password file (stat err %v)", err)
	}

	logged := buf.String()
	// The way out for a genuine founder is the marker path itself; the log names it
	// (as the "marker" attribute) so the operator can create it.
	for _, want := range []string{"replicat", "lv host init", genesisMarkerName, "restart"} {
		if !strings.Contains(logged, want) {
			t.Errorf("the skip log does not mention %q, so the operator cannot tell why no "+
				"admin exists or what to do about it:\n\t%s", want, strings.TrimSpace(logged))
		}
	}
	if strings.Contains(logged, adminPasswordFile) {
		t.Errorf("the skip log names %s, which this branch never writes", adminPasswordFile)
	}
}

// Seeding consumes the marker, so a founder can mint exactly once.
//
// Without that the marker is a standing licence: lose the founder's state.db (a
// disk swap, a restore, an operator deleting it to "reset" a wedged node) and the
// next start reads an empty `users` table beside a marker that still says "found
// a cluster here", and mints over the live credential.
func TestSeedAdminUser_SeedingConsumesTheFounderMarker(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	d := founderDaemon(t, db, filepath.Join(t.TempDir(), "admin-password"))
	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("founder first start: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.cfg.DataDir, genesisMarkerName)); !os.IsNotExist(err) {
		t.Fatalf("the founder marker survived a successful seed (stat err %v); it licenses "+
			"another mint the moment state.db is lost", err)
	}

	// state.db is rebuilt empty under the same data dir.
	d.db = newHostTestClient(t)
	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("start after a state.db rebuild: %v", err)
	}
	users, err := corrosion.ListUsers(ctx, d.db)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("a founder whose state.db was rebuilt minted %v again; that row replaces "+
			"the cluster's admin credential when replication comes up", users)
	}
}

// A marker does not outrank evidence of earlier membership.
//
// Capability latches (data_dir/split_brain_activated.<token>) are written only
// after a daemon has run as a member, and they survive a state.db loss. A node
// holding one is not founding anything, whatever marker it carries: the docs tell
// an operator to create the marker by hand on a genuine founder, and one created
// on a former member must not mint a second admin over the cluster's.
func TestSeedAdminUser_CapabilityLatchesOutrankTheMarker(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	d := founderDaemon(t, db, filepath.Join(t.TempDir(), "admin-password"))
	latch := filepath.Join(d.cfg.DataDir, "split_brain_activated.voter_config_v1")
	if err := os.WriteFile(latch, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("seedAdminUser on a former member: %v", err)
	}
	users, err := corrosion.ListUsers(ctx, db)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("a node holding capability latches minted %v despite having run as a member", users)
	}
}

// A stale marker does not outrank join_peers.
//
// A node can carry a marker it never consumed: `lv host init`, then — before the
// daemon ever started — `lv host add` into a different cluster. join_peers is the
// stronger fact there, and the joiner must still mint nothing.
func TestSeedAdminUser_AJoinerWithAStaleMarkerStillMintsNothing(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	d := founderDaemon(t, db, filepath.Join(t.TempDir(), "admin-password"))
	d.cfg.HostName = "node-5"
	d.cfg.JoinPeers = []string{"10.77.0.11:7946"}
	if err := d.seedAdminUser(ctx); err != nil {
		t.Fatalf("seedAdminUser on a joiner with a stale marker: %v", err)
	}
	users, err := corrosion.ListUsers(ctx, db)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("a joiner holding a stale founder marker minted %v", users)
	}
}
