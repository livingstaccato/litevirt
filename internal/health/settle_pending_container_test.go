package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// relocatedCTFixture is TestPartitionPause_SettlesARelocatedContainer's setup:
// node-a froze ct-ha, the majority relocated it to node-b on a verified
// certificate, and node-b runs it.
func relocatedCTFixture(t *testing.T) (*pauseFixture, *fakeCT, PauseRecord, corrosion.ProofRecord, corrosion.ClaimCertificate) {
	t.Helper()
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
	cert := corrosion.ClaimCertificate{Key: corrosion.ClaimKey{TargetKind: corrosion.ClaimKindContainer,
		TargetName: "ct-ha", OwnerEpoch: recs[0].OwnerEpoch, Incarnation: recs[0].Incarnation}, ConfigGeneration: 1}
	wire := func(p *PartitionPauser) {
		p.SetPeerRuntimeChecker(func(_ context.Context, host, name string) (string, error) {
			if host == "node-b" && name == "ct-ha" {
				return RuntimeRunning, nil
			}
			return RuntimeAbsent, nil
		})
		p.settleProofs = func(context.Context, *corrosion.Client, string, string) ([]corrosion.ProofRecord, error) {
			return []corrosion.ProofRecord{proof}, nil
		}
		p.SetSettleVerifier(func(context.Context, corrosion.ActionProof) (corrosion.ClaimCertificate, error) {
			return cert, nil
		})
	}
	wire(f.p)
	return f, rt, recs[0], proof, cert
}

func ctSettleRows(t *testing.T, f *pauseFixture) int {
	t.Helper()
	rows, err := f.db.Query(context.Background(),
		`SELECT id FROM audit_log WHERE action = 'partition.settle' AND target = 'container/ct-ha'`)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func ctPending(t *testing.T, f *pauseFixture) []settlePending {
	t.Helper()
	recs, err := newSettlePendingStore(f.dataDir).list(PauseKindContainer)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func ctSettledRaised(t *testing.T, f *pauseFixture) bool {
	t.Helper()
	c, ok, err := corrosion.GetHealthCondition(context.Background(), f.db, corrosion.PartitionPauseEvaluator,
		corrosion.CondCTSettled, "container", "ct-ha@node-a")
	if err != nil {
		t.Fatal(err)
	}
	return ok && c.ConfirmedAt != ""
}

// A container settle whose audit row and ct_settled fail to write still stops
// the copy, and the pauser's next resume pass writes both, once.
//
// Mutations: settleContainer saves no pending record — nothing is written
// later, red; drop the retry from tryResume — red.
func TestPartitionPause_AContainerSettleRecordIsRetried(t *testing.T) {
	f, rt, _, _, _ := relocatedCTFixture(t)
	fail := true
	f.p.settleFault = func(string) error {
		if fail {
			return errors.New("injected write failure")
		}
		return nil
	}
	f.regain()
	if st := rt.get("ct-ha"); st != "stopped" {
		t.Fatalf("ct-ha is %s; a failed record write must not hold the stop back", st)
	}
	if n := ctSettleRows(t, f); n != 0 || ctSettledRaised(t, f) {
		t.Fatalf("rows %d / ct_settled raised through injected failures", n)
	}
	if recs := ctPending(t, f); len(recs) != 1 || recs[0].Phase != settlePhaseStopped {
		t.Fatalf("pending records = %+v, want one stopped", recs)
	}
	fail = false
	f.tick()
	f.tick()
	if n := ctSettleRows(t, f); n != 1 {
		t.Fatalf("partition.settle rows = %d after the retry, want 1", n)
	}
	if !ctSettledRaised(t, f) {
		t.Fatal("ct_settled not raised by the retry")
	}
	if recs := ctPending(t, f); len(recs) != 0 {
		t.Fatalf("pending records %+v outlived a complete record", recs)
	}
}

// A daemon that died between a container settle's stop and its record: the
// restarted pauser writes the record once and drops the matching pause
// record. One that died before the stop (the container still frozen) has its
// record dropped, and the settle runs again: one row either way.
//
// Mutations: complete a stopping record whatever the runtime says — "died
// before the stop" writes two rows, red; drop the retry — "died after the
// stop" writes none, red.
func TestPartitionPause_AContainerSettleSurvivesACrash(t *testing.T) {
	for _, tc := range []struct {
		name    string
		stopped bool
	}{
		{"died after the stop", true},
		{"died before the stop", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, rt, pr, proof, cert := relocatedCTFixture(t)
			w := f.p.settleRec()
			rec := w.newPending(PauseKindContainer, "ct-ha", "stopped the frozen local copy (test)", proof, cert,
				pr.Incarnation, pr.OwnerEpoch, "partition-pause record")
			if err := newSettlePendingStore(f.dataDir).put(rec); err != nil {
				t.Fatal(err)
			}
			if tc.stopped {
				if err := rt.Stop(context.Background(), "ct-ha", 10); err != nil {
					t.Fatal(err)
				}
			}
			// The restarted daemon's pauser, wired the same way.
			f.p = NewPartitionPauser("node-a", f.dataDir, f.db)
			f.p.SetQuorum(func(context.Context) (QuorumState, int, int) { f.mu.Lock(); defer f.mu.Unlock(); return f.quorum, 1, 2 })
			f.p.SetEnabled(func() bool { return true })
			f.p.SetClock(func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now })
			f.p.SetResumeConfirmer(func(_ context.Context, recs []PauseRecord) map[string]ResumeVerdict {
				out := map[string]ResumeVerdict{}
				for _, r := range recs {
					out[r.Key()] = ResumeVerdict{OK: true, Reason: "test: confirmed"}
				}
				return out
			})
			f.p.SetSelfFence(func() bool { return false }, func() {})
			f.p.SetContainerRuntime(rt)
			f.p.SetPeerRuntimeChecker(func(_ context.Context, host, name string) (string, error) {
				if host == "node-b" && name == "ct-ha" {
					return RuntimeRunning, nil
				}
				return RuntimeAbsent, nil
			})
			f.p.settleProofs = func(context.Context, *corrosion.Client, string, string) ([]corrosion.ProofRecord, error) {
				return []corrosion.ProofRecord{proof}, nil
			}
			f.p.SetSettleVerifier(func(context.Context, corrosion.ActionProof) (corrosion.ClaimCertificate, error) {
				return cert, nil
			})
			f.regain()
			if st := rt.get("ct-ha"); st != "stopped" {
				t.Fatalf("ct-ha is %s, want stopped", st)
			}
			if n := ctSettleRows(t, f); n != 1 {
				t.Fatalf("partition.settle rows = %d, want 1", n)
			}
			if !ctSettledRaised(t, f) {
				t.Fatal("ct_settled not raised")
			}
			if recs := ctPending(t, f); len(recs) != 0 {
				t.Fatalf("pending records %+v remain", recs)
			}
			if recs := f.records(); len(recs) != 0 {
				t.Fatalf("pause records %+v outlived the settled container", recs)
			}
		})
	}
}
