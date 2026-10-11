package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// --user resets the named admin account, and only that one (re-review 3, I1a:
// the account the admin floor reinstated has no usable credential until root
// gives it one).
func TestResetAdmin_UserResetsTheNamedAdmin(t *testing.T) {
	ctx := context.Background()
	db := resetAdminTestDB(t)
	for _, u := range []string{"admin", "oldops"} {
		if err := corrosion.InsertUser(ctx, db, u, "admin", "$2a$10$stub-"+u); err != nil {
			t.Fatal(err)
		}
	}
	pw := filepath.Join(t.TempDir(), "admin-password")
	password, hash, err := mintAdminPassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := resetAdminOffline(ctx, db, t.TempDir(), pw, "root", "oldops", password, hash, false, io.Discard); err != nil {
		t.Fatalf("reset-admin --user oldops: %v", err)
	}
	if u, _ := corrosion.GetUser(ctx, db, "oldops"); u == nil || u.PasswordHash != hash {
		t.Errorf("oldops was not reset: %+v", u)
	}
	if u, _ := corrosion.GetUser(ctx, db, "admin"); u == nil || u.PasswordHash != "$2a$10$stub-admin" {
		t.Errorf("reset-admin --user oldops changed admin: %+v", u)
	}
	if cmd := newUserResetAdminCmd(); cmd.Flags().Lookup("user") == nil {
		t.Error("reset-admin has no --user flag")
	}
}

// --user never gives a password to an account that is not an admin.
func TestResetAdmin_UserRefusesANonAdmin(t *testing.T) {
	ctx := context.Background()
	db := resetAdminTestDB(t)
	if err := corrosion.InsertUser(ctx, db, "admin", "admin", "$2a$10$stub"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, db, "bob", "viewer", "$2a$10$stub-bob"); err != nil {
		t.Fatal(err)
	}
	pw := filepath.Join(t.TempDir(), "admin-password")
	password, hash, _ := mintAdminPassword()
	if err := resetAdminOffline(ctx, db, t.TempDir(), pw, "root", "bob", password, hash, false, io.Discard); err == nil {
		t.Fatal("reset-admin --user bob reset a viewer's password")
	}
	if u, _ := corrosion.GetUser(ctx, db, "bob"); u == nil || u.PasswordHash != "$2a$10$stub-bob" {
		t.Errorf("bob's password changed: %+v", u)
	}
	if _, err := os.Stat(pw); err == nil {
		t.Error("a password file was written for a refused reset")
	}
}

// Through the daemon, --user is sent; a daemon that predates the field resets
// "admin" instead, and the CLI says so (and keeps admin's new password).
func TestResetAdmin_UserThroughTheDaemon(t *testing.T) {
	d := &fakeResetDaemon{}
	env := envFor(t, d, t.TempDir(), noDB(t))
	env.username = "oldops"
	var out bytes.Buffer
	env.out = &out
	if err := runResetAdmin(context.Background(), env); err != nil {
		t.Fatalf("runResetAdmin --user oldops: %v", err)
	}
	if d.got.GetUsername() != "oldops" || !strings.Contains(out.String(), "oldops") {
		t.Fatalf("request %+v, output %q; want the request and the output to name oldops", d.got, out.String())
	}

	// A daemon that predates --user but whose Ping does not show it (an
	// unreleased build at the same schema version): it resets admin, and the
	// CLI says so after the fact.
	old := &fakeResetDaemon{predatesUser: true}
	env = envFor(t, old, t.TempDir(), noDB(t))
	env.username = "oldops"
	err := runResetAdmin(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "predates --user") {
		t.Fatalf("an older daemon that reset admin instead: err = %v, want it said", err)
	}
	if _, serr := os.Stat(env.pwPath); serr != nil {
		t.Error("admin's new password was not written although the older daemon set it")
	}
}

// re-review 4, m-7: a daemon whose Ping shows a build before --user is
// refused BEFORE it is asked to reset anything: it would reset "admin" — maybe
// a live colleague's password — whatever --user named.
func TestResetAdmin_UserRefusedUpFrontByAnOlderDaemon(t *testing.T) {
	old := &fakeResetDaemon{predatesUser: true, pingSchema: resetAdminUserSchema - 1}
	env := envFor(t, old, t.TempDir(), noDB(t))
	env.username = "oldops"
	err := runResetAdmin(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "predates --user") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("--user against a daemon that predates it: err = %v, want a refusal that changed nothing", err)
	}
	if old.got != nil {
		t.Fatalf("the older daemon was asked to reset %+v", old.got)
	}
	if _, serr := os.Stat(env.pwPath); serr == nil {
		t.Error("a password file was written although nothing was reset")
	}

	// Without --user the probe is not made, and the reset goes through as before.
	plain := &fakeResetDaemon{predatesUser: true, pingSchema: resetAdminUserSchema - 1}
	env = envFor(t, plain, t.TempDir(), noDB(t))
	if err := runResetAdmin(context.Background(), env); err != nil {
		t.Fatalf("plain reset-admin against an older daemon: %v", err)
	}
	if plain.pinged != 0 {
		t.Errorf("plain reset-admin pinged the daemon %d times", plain.pinged)
	}

	// A Ping that fails says nothing about the build: the reset is asked,
	// and the after-the-fact check still stands behind it.
	unsure := &fakeResetDaemon{pingErr: errors.New("ping refused")}
	env = envFor(t, unsure, t.TempDir(), noDB(t))
	env.username = "oldops"
	if err := runResetAdmin(context.Background(), env); err != nil || unsure.got.GetUsername() != "oldops" {
		t.Fatalf("--user with a failing Ping: %v (asked %+v)", err, unsure.got)
	}
}

// login-fu review Minor 3: the note the daemon returns — a cut-off it left in
// place — is printed; and the daemon-down path, which cannot open the gate,
// prints its own.
func TestResetAdmin_PrintsTheCutoffNote(t *testing.T) {
	d := &fakeResetDaemon{note: "The account admin has a cut-off dated in the future: it was left in place"}
	env := envFor(t, d, t.TempDir(), noDB(t))
	var out bytes.Buffer
	env.out = &out
	if err := runResetAdmin(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), d.note) {
		t.Errorf("output %q does not carry the daemon's note", out.String())
	}

	ctx := context.Background()
	db := resetAdminTestDB(t)
	if err := corrosion.InsertUser(ctx, db, "admin", "admin", "$2a$10$stub"); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `INSERT INTO user_lifecycle (username, attribute, value, set_by, updated_at)
		VALUES ('admin', ?, ?, 'peer', ?)`, corrosion.UserAttrSessionsNotBefore,
		time.Now().Add(2*time.Hour).UTC().Format(time.RFC3339), db.NowTS()); err != nil {
		t.Fatal(err)
	}
	password, hash, _ := mintAdminPassword()
	out.Reset()
	if err := resetAdminOffline(ctx, db, t.TempDir(), filepath.Join(t.TempDir(), "pw"), "root", "", password, hash, false, &out); err != nil {
		t.Fatalf("daemon-down reset under a future cut-off: %v", err)
	}
	if !strings.Contains(out.String(), "left in place") || !strings.Contains(out.String(), "litevirtd is not running") {
		t.Errorf("daemon-down output %q: want the cut-off note", out.String())
	}
}
