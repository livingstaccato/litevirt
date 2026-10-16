package corrosion

import (
	"context"
	"strings"
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

// The conditional writer must use membership authority and preserve the
// retired/frozen stream shape, including when no membership row has arrived.
func TestUpdateHostStateFromMembershipAuthority(t *testing.T) {
	ctx := context.Background()
	for _, retired := range []bool{false, true} {
		t.Run(map[bool]string{false: "dual-home", true: "retired"}[retired], func(t *testing.T) {
			c := newTestDB(t)
			seedMembershipHosts(t, c, "h1")
			if retired {
				retireLive(t, c)
			} else {
				openMembershipGate(c)
				if _, err := c.SplitHostMembership(ctx); err != nil {
					t.Fatal(err)
				}
			}
			// Deliberately disagree: the live membership state wins over hosts.
			if err := c.execLocal(ctx, `UPDATE hosts SET state = 'upgrading' WHERE name = 'h1'`); err != nil {
				t.Fatal(err)
			}
			if err := c.execLocal(ctx, `UPDATE host_membership SET state = 'fenced' WHERE host_name = 'h1'`); err != nil {
				t.Fatal(err)
			}
			from := maxSeq(t, c)
			if applied, err := UpdateHostStateFrom(ctx, c, "h1", "upgrading", "active"); err != nil || applied {
				t.Fatalf("membership fence lost: applied=%v err=%v", applied, err)
			}
			if got := resolvedState(t, c, "h1"); got != "fenced" {
				t.Fatalf("resolved state = %q, want fenced", got)
			}
			if got := logSince(t, c, from); len(got) != 0 {
				t.Fatalf("declined writer logged mutations: %v", got)
			}
			if err := c.execLocal(ctx, `UPDATE host_membership SET state = 'upgrading' WHERE host_name = 'h1'`); err != nil {
				t.Fatal(err)
			}
			if applied, err := UpdateHostStateFrom(ctx, c, "h1", "upgrading", "active"); err != nil || !applied {
				t.Fatalf("conditional activation: applied=%v err=%v", applied, err)
			}
			if got := resolvedState(t, c, "h1"); got != "active" {
				t.Fatalf("resolved state = %q, want active", got)
			}
			entries := logSince(t, c, from)
			if len(entries) != 1 || !strings.Contains(entries[0], "host_membership") {
				t.Fatalf("conditional activation stream: %v", entries)
			}
			if strings.Contains(entries[0], "UPDATE hosts") == retired {
				t.Fatalf("retired=%v: wrong hosts stream shape: %s", retired, entries[0])
			}
			if retired {
				if got := hostsCol(t, c, "h1", "state"); got != "upgrading" {
					t.Fatalf("retired hosts copy changed to %q", got)
				}
				if err := c.execLocal(ctx, `DELETE FROM host_membership WHERE host_name = 'h1'`); err != nil {
					t.Fatal(err)
				}
				from = maxSeq(t, c)
				if applied, err := UpdateHostStateFrom(ctx, c, "h1", "upgrading", "active"); err != nil || applied {
					t.Fatalf("missing frozen membership adopted hosts state: applied=%v err=%v", applied, err)
				}
				if got := resolvedState(t, c, "h1"); got != HostStateUnknown {
					t.Fatalf("missing frozen member reads %q", got)
				}
				if tableCount(t, c, "host_membership") != 0 || len(logSince(t, c, from)) != 0 {
					t.Fatal("declined frozen writer created or logged a membership row")
				}
			}
		})
	}
}
