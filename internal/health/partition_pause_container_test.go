package health

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// fakeCT is an LXC runtime with running / frozen / stopped containers and the
// IsFrozen capability LxcRunner has. Anything else panics (nil embedded).
type fakeCT struct {
	lxc.Runtime
	mu    sync.Mutex
	state map[string]string
	stops []string
}

func newFakeCT(running ...string) *fakeCT {
	f := &fakeCT{state: map[string]string{}}
	for _, n := range running {
		f.state[n] = "running"
	}
	return f
}

func (f *fakeCT) get(name string) string { f.mu.Lock(); defer f.mu.Unlock(); return f.state[name] }

func (f *fakeCT) List(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for n := range f.state {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeCT) State(_ context.Context, name string) (lxc.State, error) {
	switch f.get(name) {
	case "running", "frozen": // lxc.parseLxcInfoState folds frozen into running
		return lxc.StateRunning, nil
	case "stopped":
		return lxc.StateStopped, nil
	}
	return lxc.StateUnknown, lxc.ErrContainerNotFound
}

func (f *fakeCT) IsFrozen(_ context.Context, name string) (bool, error) {
	return f.get(name) == "frozen", nil
}

func (f *fakeCT) Freeze(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state[name] != "running" {
		return errors.New("not running")
	}
	f.state[name] = "frozen"
	return nil
}

func (f *fakeCT) Unfreeze(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state[name] != "frozen" {
		return errors.New("not frozen")
	}
	f.state[name] = "running"
	return nil
}

func (f *fakeCT) Stop(_ context.Context, name string, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[name] = "stopped"
	f.stops = append(f.stops, name)
	return nil
}

// newContainerPauseFixture is newPauseFixture with two containers on node-a
// (one recoverable, one policy none) and no VM backend.
func newContainerPauseFixture(t *testing.T) (*pauseFixture, *fakeCT) {
	t.Helper()
	f := newPauseFixture(t)
	f.p.SetVMBackend(nil)
	ctx := context.Background()
	for _, ct := range []struct{ name, policy string }{{"ct-ha", "image-recreate"}, {"ct-none", "none"}} {
		if err := corrosion.UpsertContainer(ctx, f.db, corrosion.ContainerRecord{HostName: "node-a", Name: ct.name,
			State: "running", Image: "alpine:3.19", OnHostFailure: ct.policy}); err != nil {
			t.Fatal(err)
		}
	}
	rt := newFakeCT("ct-ha", "ct-none")
	f.p.SetContainerRuntime(rt)
	return f, rt
}

// A recoverable container is frozen after T_pause and unfrozen on the
// majority's confirmation; a policy-none container is left running.
//
// Mutations: drop the container recoverability filter — ct-none freezes; skip
// the unfreeze on resume — ct-ha stays frozen.
func TestPartitionPause_FreezesAndUnfreezesARecoverableContainer(t *testing.T) {
	f, rt := newContainerPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := rt.get("ct-ha"); st != "frozen" {
		t.Fatalf("ct-ha is %s after T_pause of lost quorum, want frozen", st)
	}
	if st := rt.get("ct-none"); st != "running" {
		t.Fatalf("ct-none (on_host_failure=none) is %s", st)
	}
	if recs := f.records(); len(recs) != 1 || recs[0].Key() != "ct/ct-ha" {
		t.Fatalf("records = %+v, want ct/ct-ha", recs)
	}
	f.regain()
	if st := rt.get("ct-ha"); st != "running" {
		t.Fatalf("ct-ha is %s after the majority confirmed it", st)
	}
}

// A container someone else froze is not recorded and not unfrozen.
//
// Mutation: skip the IsFrozen check — the operator's container is recorded
// (and later unfrozen) and this goes red.
func TestPartitionPause_LeavesAFrozenContainerAlone(t *testing.T) {
	f, rt := newContainerPauseFixture(t)
	if err := rt.Freeze(context.Background(), "ct-ha"); err != nil {
		t.Fatal(err)
	}
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if recs := f.records(); len(recs) != 0 {
		t.Fatalf("a container frozen by someone else was recorded: %+v", recs)
	}
	if c, ok := f.condition(corrosion.CondPartitionPauseFailed); ok && c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("the pauser tried to freeze a container someone else froze: %s", c.Evidence)
	}
	f.regain()
	if st := rt.get("ct-ha"); st != "frozen" {
		t.Fatalf("a container frozen by someone else is %s after the majority returned", st)
	}
}

// Layer 3 for a container: this host froze ct-ha, the majority relocated it to
// node-b on a certified claim, and on return the frozen copy is stopped — on a
// verified certificate for the recorded incarnation and epoch, and not without
// one.
//
// Mutations: settle without verifying (ignore the verifier's error) — the
// "unverified" subtest stops the copy and goes red; skip the stop — the
// settled subtest goes red.
func TestPartitionPause_SettlesARelocatedContainer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		certErr error
		status  string
		want    string
	}{
		{"verified", nil, "", "stopped"},
		{"unverified", errors.New("too few valid accepts"), "", "frozen"},
		{"prepared proof", nil, corrosion.ProofPrepared, "frozen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, rt := newContainerPauseFixture(t)
			ctx := context.Background()
			f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
			recs := f.records()
			if len(recs) != 1 {
				t.Fatalf("setup: records %+v", recs)
			}
			if err := corrosion.RelocateContainer(ctx, f.db, "node-a", "ct-ha", "node-b"); err != nil {
				t.Fatal(err)
			}
			proof := corrosion.ProofRecord{ActionProof: corrosion.ActionProof{ID: "reloc-1", Action: corrosion.ActionRelocate,
				TargetKind: corrosion.ClaimKindContainer, TargetName: "ct-ha", DestHost: "node-b", OwnerEpoch: "0",
				ClaimCertificate: "{}"}, Status: corrosion.ProofCompleted, ExecutorHost: "node-b"}
			if tc.status != "" {
				proof.Status = tc.status
			}
			f.p.SetPeerRuntimeChecker(func(_ context.Context, host, name string) (string, error) {
				if host == "node-b" && name == "ct-ha" {
					return RuntimeRunning, nil
				}
				return RuntimeAbsent, nil
			})
			cert := corrosion.ClaimCertificate{Key: corrosion.ClaimKey{TargetKind: corrosion.ClaimKindContainer,
				TargetName: "ct-ha", OwnerEpoch: recs[0].OwnerEpoch, Incarnation: recs[0].Incarnation}, ConfigGeneration: 1}
			f.p.settleProofs = func(context.Context, *corrosion.Client, string, string) ([]corrosion.ProofRecord, error) {
				return []corrosion.ProofRecord{proof}, nil
			}
			f.p.SetSettleVerifier(func(context.Context, corrosion.ActionProof) (corrosion.ClaimCertificate, error) {
				return cert, tc.certErr
			})
			f.regain()
			if st := rt.get("ct-ha"); st != tc.want {
				t.Fatalf("ct-ha is %s, want %s", st, tc.want)
			}
			if tc.want != "stopped" {
				return
			}
			if recs := f.records(); len(recs) != 0 {
				t.Fatalf("the record outlived the settled container: %+v", recs)
			}
			c, ok, err := corrosion.GetHealthCondition(ctx, f.db, corrosion.PartitionPauseEvaluator,
				corrosion.CondCTSettled, "container", "ct-ha@node-a")
			if err != nil || !ok {
				t.Fatalf("ct_settled = (%+v, %v, %v)", c, ok, err)
			}
		})
	}
}
