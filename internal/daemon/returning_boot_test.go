package daemon

import (
	"context"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/hostboot"
)

// openGate is the release gate once returning_boot is open: it runs the write
// with a grant for the feature asked about, and counts the calls.
func openGate(t *testing.T, calls *int) releaseGate {
	return func(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
		*calls++
		return write(ctx, capabilities.GrantForTest(t, f))
	}
}

// closedGate is the release gate before release_2026_11_v1 has latched.
func closedGate(context.Context, capabilities.Feature, func(context.Context, capabilities.FeatureGrant) error) error {
	return status.Error(codes.FailedPrecondition, "the cluster upgrade must finish first (returning_boot needs release_2026_11_v1)")
}

// returningDaemon is a daemon of host "h" recorded state, read from
// host_membership as on every current cluster, so the boot's guarded write
// checks the same copy hostboot read.
func returningDaemon(t *testing.T, ctx context.Context, state string) (*Daemon, func() *corrosion.HostRecord) {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h", Address: "127.0.0.1", SSHUser: "root", CertSerial: "s", State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	db.SetHostMembershipGate(func() bool { return true })
	if _, err := db.SplitHostMembership(ctx); err != nil || !db.HostMembershipLive() {
		t.Fatalf("split host membership: live=%v err=%v", db.HostMembershipLive(), err)
	}
	if err := corrosion.UpdateHostState(ctx, db, "h", state); err != nil {
		t.Fatal(err)
	}
	host := func() *corrosion.HostRecord {
		h, err := corrosion.GetHost(ctx, db, "h")
		if err != nil || h == nil {
			t.Fatalf("GetHost: %v", err)
		}
		return h
	}
	return &Daemon{cfg: &Config{HostName: "h", DataDir: t.TempDir(), Version: "v-boot"}, db: db}, host
}

// TestReturningHostBootWiring: the daemon of a host the cluster recorded
// fenced, offline, in maintenance, draining or joining starts, with the
// returning_boot feature open. (Joining here is in the node's own replica: a
// re-admission it received before restarting. A fresh joiner reads the
// 'active' its registration inserts: hostboot
// TestFreshJoinerFirstBootTakesTheRestartRules.) Its boot write goes through the release gate
// and records the host 'upgrading' — the guarded write, checked against the
// membership row hostboot read, is applied — and the host turns 'active' once
// this daemon answers its own Ping, not before.
//
// Mutations: have hostboot.BootState skip returningBoot — the boot write
// records 'active' at once; write the returning boot without the gate — the
// gate is not called; take the state from the hosts column instead of
// readHost — the guarded write is refused and the host stays as recorded.
func TestReturningHostBootWiring(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()
	for _, st := range []string{"fenced", "offline", "maintenance", "draining", corrosion.HostStateJoining} {
		t.Run(st, func(t *testing.T) {
			var checks bootChecks
			defer checks.wait(t) // after cancel
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d, host := returningDaemon(t, ctx, st)
			calls := 0
			d.returningGate = openGate(t, &calls)
			serving := make(chan struct{})
			d.selfPinger = checks.pinger(&gatedPinger{open: serving})
			d.writeBootState(ctx, 2, 2048, 10, true)
			if h := host(); h.State != "upgrading" || h.Version != "v-boot" {
				t.Fatalf("the boot write of a host recorded %s recorded %q (version %q), want upgrading with its report", st, h.State, h.Version)
			}
			if calls != 1 {
				t.Fatalf("the returning boot went through the release gate %d times, want once", calls)
			}
			time.Sleep(50 * time.Millisecond)
			if got := host().State; got != "upgrading" {
				t.Fatalf("before this daemon serves the host is %q, want upgrading", got)
			}
			close(serving)
			for deadline := time.Now().Add(3 * time.Second); host().State != "active"; time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatalf("this daemon serves, and the host is still %q: the boot did not start the serving check", host().State)
				}
			}
			for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				if _, err := os.Stat(hostboot.AwaitingPath(d.cfg.DataDir)); os.IsNotExist(err) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("this daemon serves, and the boot's awaiting-serving note is still there")
				}
			}
		})
	}
}

// TestReturningHostBootBeforeTheFeatureOpens: until returning_boot is open
// (release_2026_11_v1 not latched, or the boot cannot reach the gate), a
// returning host's boot records it 'active' at once, as before this release:
// a failover leader on the previous release clears a fenced host from its
// handled cache only once it is 'active'.
//
// Mutations: ignore the gate's refusal and write 'upgrading' anyway — the
// host is recorded upgrading; skip the fallback — the host keeps its
// returning state.
func TestReturningHostBootBeforeTheFeatureOpens(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()
	for name, gate := range map[string]releaseGate{"refused": closedGate, "no checker": nil} {
		t.Run(name, func(t *testing.T) {
			var checks bootChecks
			defer checks.wait(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d, host := returningDaemon(t, ctx, "fenced")
			d.returningGate = gate
			d.selfPinger = checks.pinger(&gatedPinger{open: make(chan struct{})})
			d.writeBootState(ctx, 2, 2048, 10, true)
			if h := host(); h.State != "active" || h.Version != "v-boot" {
				t.Fatalf("the boot of a fenced host before the feature opens recorded %q (version %q), want active at once with its report", h.State, h.Version)
			}
		})
	}
}

// TestReturningBootThroughTheRealGate: the boot of a fenced host on a cluster
// where release_2026_11_v1 has latched (its marker, and failover_scope_v1's,
// on disk) and returning_boot's use is recorded and acknowledged goes through
// the daemon's own health checker and release gate — no injected gate, no
// test grant — and records the host 'upgrading'. The gate re-records the use
// in cluster_policies before it grants, so the cluster-policy write gate must
// be wired before the boot write.
//
// Mutation: wire the cluster-policy gate after the boot write (drop it from
// checkerThenBootWrite) — the gate refuses and the host is recorded 'active'.
func TestReturningBootThroughTheRealGate(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()
	var checks bootChecks
	defer checks.wait(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, host := returningDaemon(t, ctx, "fenced")
	for _, tok := range []string{capabilities.Release202611V1, capabilities.FailoverScopeV1} {
		if err := os.WriteFile(health.ActivationMarkerPath(d.cfg.DataDir, tok), capabilities.MarkerContent(tok), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	info, ok := capabilities.LookupFeature(capabilities.FeatureReturningBoot)
	if !ok {
		t.Fatal("returning_boot is not declared")
	}
	d.db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.RecordReleaseFeatureUse(ctx, d.db, info.Token, string(capabilities.FeatureReturningBoot), "leader", true); err != nil {
		t.Fatalf("seed the acknowledged use: %v", err)
	}
	// As at daemon start: nothing has opened the policy gate yet.
	d.db.SetClusterPolicyGate(func() bool { return false })
	d.selfPinger = checks.pinger(&gatedPinger{open: make(chan struct{})})
	d.checkerThenBootWrite(ctx, 2, 2048, 10, true)
	if h := host(); h.State != "upgrading" || h.Version != "v-boot" {
		t.Fatalf("the boot of a fenced host through the real gate recorded %q (version %q), want upgrading with its report", h.State, h.Version)
	}
}
