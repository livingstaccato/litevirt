package corrosion

import (
	"context"
	"reflect"
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

// The conditional startup batch must honor both retirement latches and the
// resolved membership authority, without logging a declined report or
// recreating identity after a frozen/missing row.
func TestUpdateHostStartupFromRetirementAndMembership(t *testing.T) {
	ctx := context.Background()
	for _, retireRuntime := range []bool{false, true} {
		for _, retireMembership := range []bool{false, true} {
			name := map[bool]string{false: "runtime-live", true: "runtime-retired"}[retireRuntime] + "/" + map[bool]string{false: "membership-live", true: "membership-retired"}[retireMembership]
			t.Run(name, func(t *testing.T) {
				c := newTestDB(t)
				seedMembershipHosts(t, c, "h1")
				openMembershipGate(c)
				if _, err := c.SplitHostMembership(ctx); err != nil {
					t.Fatal(err)
				}
				splitRuntime(t, c)
				c.SetHostMembershipRetireGate(func() bool { return retireMembership })
				c.SetHostRuntimeRetireGate(func() bool { return retireRuntime })
				if err := IsolateHost(ctx, c, "observer", "h1", "manual"); err != nil {
					t.Fatal(err)
				}
				epoch, reason, err := HostIsolation(ctx, c, "h1")
				if err != nil || epoch == 0 {
					t.Fatalf("isolation: %d %q %v", epoch, reason, err)
				}
				if err := c.execLocal(ctx, `UPDATE hosts SET state = 'upgrading' WHERE name = 'h1'`); err != nil {
					t.Fatal(err)
				}
				if err := c.execLocal(ctx, `UPDATE host_membership SET state = 'fenced' WHERE host_name = 'h1'`); err != nil {
					t.Fatal(err)
				}
				before := *hostOf(t, c, "h1")
				seq := maxSeq(t, c)
				if applied, err := UpdateHostStartupFrom(ctx, c, "h1", "upgrading", "active", "wrong-report", 1, 2, 3, true); err != nil || applied {
					t.Fatalf("membership fence lost: applied=%v err=%v", applied, err)
				}
				if after := *hostOf(t, c, "h1"); !reflect.DeepEqual(after, before) || len(logSince(t, c, seq)) != 0 {
					t.Fatalf("declined report changed row or emitted a mutation: before=%+v after=%+v log=%v", before, after, logSince(t, c, seq))
				}
				if err := c.execLocal(ctx, `UPDATE host_membership SET state = 'upgrading' WHERE host_name = 'h1'`); err != nil {
					t.Fatal(err)
				}
				hostState, hostVersion, hostTS := hostsCol(t, c, "h1", "state"), hostsCol(t, c, "h1", "version"), hostsCol(t, c, "h1", "updated_at")
				if applied, err := UpdateHostStartupFrom(ctx, c, "h1", "upgrading", "active", "v-conditional", 7, 14, 21, true); err != nil || !applied {
					t.Fatalf("conditional report: applied=%v err=%v", applied, err)
				}
				h := hostOf(t, c, "h1")
				if h.State != "active" || h.Version != "v-conditional" || h.CPUTotal != 7 || h.MemTotal != 14 || h.DiskTotal != 21 || h.SchemaVersion != CurrentSchemaVersion {
					t.Fatalf("resolved report: %+v", h)
				}
				if e, r, err := HostIsolation(ctx, c, "h1"); err != nil || e != epoch || r != reason {
					t.Fatalf("report changed isolation: %d %q %v", e, r, err)
				}
				entries := logSince(t, c, seq)
				if len(entries) != 1 || !strings.Contains(entries[0], "host_runtime") || !strings.Contains(entries[0], "host_membership") || strings.Contains(entries[0], "UPDATE hosts") == (retireRuntime && retireMembership) {
					t.Fatalf("single conditional report batch has wrong retirement shape: %v", entries)
				}
				memberTS := oneString(t, c, `SELECT updated_at AS v FROM host_membership WHERE host_name = 'h1'`, "v")
				if runtimeCol(t, c, "h1", "updated_at") != memberTS {
					t.Fatal("state and runtime report did not share one timestamp")
				}
				if retireRuntime && hostsCol(t, c, "h1", "version") != hostVersion {
					t.Fatal("retired runtime hosts copy changed")
				}
				if retireRuntime && retireMembership {
					if hostsCol(t, c, "h1", "state") != hostState || hostsCol(t, c, "h1", "updated_at") != hostTS {
						t.Fatal("fully retired hosts copy changed")
					}
				} else if hostsCol(t, c, "h1", "state") != "active" || hostsCol(t, c, "h1", "updated_at") != memberTS {
					t.Fatal("live hosts state did not share the report timestamp")
				}
				if applied, err := UpdateHostStartupFrom(ctx, c, "h1", "active", "active", "", 0, 0, 0, false); err != nil || !applied {
					t.Fatalf("blank report: %v %v", applied, err)
				}
				if h := hostOf(t, c, "h1"); h.Version != "v-conditional" || h.CPUTotal != 7 || h.MemTotal != 14 || h.DiskTotal != 21 {
					t.Fatalf("blank/no-resource report erased values: %+v", h)
				}
				if retireMembership {
					if err := c.execLocal(ctx, `DELETE FROM host_membership WHERE host_name = 'h1'`); err != nil {
						t.Fatal(err)
					}
					seq = maxSeq(t, c)
					runtimeTS := runtimeCol(t, c, "h1", "updated_at")
					if applied, err := UpdateHostStartupFrom(ctx, c, "h1", "upgrading", "active", "no-recreate", 1, 1, 1, true); err != nil || applied {
						t.Fatalf("missing frozen member adopted hosts state: %v %v", applied, err)
					}
					if tableCount(t, c, "host_membership") != 0 || len(logSince(t, c, seq)) != 0 || runtimeCol(t, c, "h1", "updated_at") != runtimeTS || resolvedState(t, c, "h1") != HostStateUnknown {
						t.Fatal("declined frozen startup wrote or recreated identity/report")
					}
				}
				seq = maxSeq(t, c)
				if applied, err := UpdateHostStartupFrom(ctx, c, "absent", HostStateUnknown, "active", "missing", 1, 1, 1, true); err != nil || applied {
					t.Fatalf("absent identity report: %v %v", applied, err)
				}
				if len(logSince(t, c, seq)) != 0 || tableCount(t, c, "host_runtime") != 1 || tableCount(t, c, "hosts") != 1 {
					t.Fatal("missing identity was recreated or emitted a mutation")
				}
			})
		}
	}
}
