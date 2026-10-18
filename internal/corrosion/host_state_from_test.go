package corrosion

import (
	"context"
	"testing"
)

// UpdateHostStateFrom writes only while the host is recorded `from`, read
// inside the write's transaction, before and after the membership split; a
// host recorded otherwise, or absent, is left as it is.
//
// Mutation: make the guard return true — the fenced host is overwritten.
func TestUpdateHostStateFrom(t *testing.T) {
	ctx := context.Background()
	for _, split := range []bool{false, true} {
		c := NewTestClientT(t)
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
		if err := InsertHost(ctx, c, HostRecord{Name: "h", Address: "10.0.0.9", SSHUser: "root", CertSerial: "s", State: "active"}); err != nil {
			t.Fatal(err)
		}
		if split {
			c.SetHostMembershipGate(func() bool { return true })
			if _, err := c.SplitHostMembership(ctx); err != nil || !c.HostMembershipLive() {
				t.Fatalf("split: live=%v err=%v", c.HostMembershipLive(), err)
			}
		}
		state := func() string {
			h, err := GetHost(ctx, c, "h")
			if err != nil || h == nil {
				t.Fatalf("GetHost: %v", err)
			}
			return h.State
		}
		if err := UpdateHostState(ctx, c, "h", "upgrading"); err != nil {
			t.Fatal(err)
		}
		if ok, err := UpdateHostStateFrom(ctx, c, "h", "upgrading", "active"); err != nil || !ok || state() != "active" {
			t.Fatalf("split=%v: upgrading→active applied=%v err=%v state=%q", split, ok, err, state())
		}
		if err := UpdateHostState(ctx, c, "h", "fenced"); err != nil {
			t.Fatal(err)
		}
		if ok, err := UpdateHostStateFrom(ctx, c, "h", "upgrading", "active"); err != nil || ok || state() != "fenced" {
			t.Fatalf("split=%v: a fenced host: applied=%v err=%v state=%q, want left fenced", split, ok, err, state())
		}
		if ok, err := UpdateHostStateFrom(ctx, c, "nobody", "upgrading", "active"); err != nil || ok {
			t.Fatalf("split=%v: an absent host: applied=%v err=%v", split, ok, err)
		}
	}
}

// UpdateHostStartupFrom is the boot report (state, version, resources) written
// only while the host is recorded `from`, read inside the write's transaction,
// before and after the membership split. A host recorded otherwise, or
// absent, is left as it is, report and all.
//
// Mutations: make the guard return true — the fenced host is overwritten and
// takes the new version; write the state only (UpdateHostStateFrom) — the
// version and resources are not reported.
func TestUpdateHostStartupFrom(t *testing.T) {
	ctx := context.Background()
	for _, split := range []bool{false, true} {
		c := NewTestClientT(t)
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
		if err := InsertHost(ctx, c, HostRecord{Name: "h", Address: "10.0.0.9", SSHUser: "root", CertSerial: "s", State: "active"}); err != nil {
			t.Fatal(err)
		}
		if split {
			c.SetHostMembershipGate(func() bool { return true })
			if _, err := c.SplitHostMembership(ctx); err != nil || !c.HostMembershipLive() {
				t.Fatalf("split: live=%v err=%v", c.HostMembershipLive(), err)
			}
		}
		host := func() *HostRecord {
			h, err := GetHost(ctx, c, "h")
			if err != nil || h == nil {
				t.Fatalf("GetHost: %v", err)
			}
			return h
		}
		if err := UpdateHostState(ctx, c, "h", "upgrading"); err != nil {
			t.Fatal(err)
		}
		ok, err := UpdateHostStartupFrom(ctx, c, "h", "upgrading", "active", "v9", 4, 8, 16, true)
		if h := host(); err != nil || !ok || h.State != "active" || h.Version != "v9" || h.CPUTotal != 4 {
			t.Fatalf("split=%v: upgrading→active report applied=%v err=%v host=%+v", split, ok, err, h)
		}
		if ok, err := UpdateHostStartupFrom(ctx, c, "h", "active", "active", "v10", 4, 8, 16, true); err != nil || !ok || host().Version != "v10" {
			t.Fatalf("split=%v: active→active report applied=%v err=%v host=%+v", split, ok, err, host())
		}
		if err := UpdateHostState(ctx, c, "h", "fenced"); err != nil {
			t.Fatal(err)
		}
		ok, err = UpdateHostStartupFrom(ctx, c, "h", "upgrading", "active", "v11", 2, 2, 2, true)
		if h := host(); err != nil || ok || h.State != "fenced" || h.Version != "v10" || h.CPUTotal != 4 {
			t.Fatalf("split=%v: a fenced host: applied=%v err=%v host=%+v, want left as it was", split, ok, err, h)
		}
		if ok, err := UpdateHostStartupFrom(ctx, c, "nobody", "upgrading", "active", "v1", 0, 0, 0, false); err != nil || ok {
			t.Fatalf("split=%v: an absent host: applied=%v err=%v", split, ok, err)
		}
	}
}
