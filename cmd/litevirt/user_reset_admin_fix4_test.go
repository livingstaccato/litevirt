package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	old := &fakeResetDaemon{predatesUser: true}
	env = envFor(t, old, t.TempDir(), noDB(t))
	env.username = "oldops"
	err := runResetAdmin(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "admin") {
		t.Fatalf("an older daemon that reset admin instead: err = %v, want it said", err)
	}
	if _, serr := os.Stat(env.pwPath); serr != nil {
		t.Error("admin's new password was not written although the older daemon set it")
	}
}
