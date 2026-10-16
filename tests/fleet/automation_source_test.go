package fleet

import (
	"context"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Requiring a genesis self-vote, inventing old content from live successor
// state, or refusing self-targets breaks actual later-joiner progress here.
func TestFleet_AutomationSourceLaterJoiner(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 52621})
	a, b, d, source := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	initVoters(t, c, source, a, b, d)
	if state, found, err := source.DB.ClaimState(ctx, corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVoterConfig}); err != nil || (found && state.Accept != nil) {
		t.Fatal("later joiner unexpectedly voted for genesis", err)
	}
	if _, err := c.SelfClient(a).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "add", Host: source.Name}); err != nil {
		t.Fatal(err)
	}
	adoptAll(t, c, 2)
	old := voterRow(t, source, 2)
	if err := source.DB.SealVoterGeneration(ctx, 2, "source cut test"); err != nil {
		t.Fatal(err)
	}
	engine, err := source.Server.AutomationEngine()
	if err != nil {
		t.Fatal(err)
	}
	cut, err := engine.FreezeMembershipCut(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if cut == "" {
		t.Fatal("missing completed cut")
	}
	if _, err := c.SelfClient(a).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: d.Name}); err != nil {
		t.Fatal(err)
	}
	adoptAll(t, c, 3)
	request := corrosion.AutomationSourceRequest{Generation: 2, Target: a.Name, Job: "later-joiner", Revision: 1, Sources: old.Members}
	t.Run("source-tombstone", func(t *testing.T) {
		if err := source.DB.ExecOutOfProcessForTest(`UPDATE hosts SET deleted_at='removed' WHERE name=?`, source.Name); err != nil {
			t.Fatal(err)
		}
		candidate, err := source.Server.PrepareAutomationSource(ctx, request)
		if candidate != nil {
			candidate.Discard()
		}
		if err == nil {
			t.Error("tombstoned source prepared a current assertion")
		}
		if err := source.DB.ExecOutOfProcessForTest(`UPDATE hosts SET deleted_at=NULL WHERE name=?`, source.Name); err != nil {
			t.Fatal(err)
		}
	})
	for _, target := range []string{a.Name, source.Name} {
		candidate, err := source.Server.PrepareAutomationSource(ctx, corrosion.AutomationSourceRequest{Generation: 2, Target: target, Job: "later-joiner", Revision: 1, Sources: old.Members})
		if err != nil {
			t.Fatalf("real later-joined source could not prepare preserved cut for %s: %v", target, err)
		}
		candidate.Discard()
	}
	refused := func(t *testing.T, r corrosion.AutomationSourceRequest) {
		t.Helper()
		candidate, err := source.Server.PrepareAutomationSource(ctx, r)
		if candidate != nil {
			candidate.Discard()
		}
		if err == nil {
			t.Fatal("invalid binding prepared")
		}
	}
	for _, mode := range []string{"old-generation", "unadopted-generation", "job-empty", "job-large", "revision", "target-removed", "roster-subset", "roster-duplicate", "roster-incarnation", "roster-excludes-source"} {
		t.Run(mode, func(t *testing.T) {
			r := request
			r.Sources = append([]corrosion.VoterMember(nil), request.Sources...)
			switch mode {
			case "old-generation":
				r.Generation = 1
			case "unadopted-generation":
				r.Generation = 4
			case "job-empty":
				r.Job = ""
			case "job-large":
				r.Job = strings.Repeat("x", 129)
			case "revision":
				r.Revision = 0
			case "target-removed":
				r.Target = d.Name
			case "roster-subset":
				r.Sources = []corrosion.VoterMember{r.Sources[0], r.Sources[len(r.Sources)-1]}
			case "roster-duplicate":
				r.Sources[1] = r.Sources[0]
			case "roster-incarnation":
				r.Sources[0].Incarnation = "reimaged"
			case "roster-excludes-source":
				r.Sources = r.Sources[:3]
			}
			refused(t, r)
		})
	}
	t.Run("expected-TLS-host", func(t *testing.T) {
		target, err := corrosion.GetHost(ctx, source.DB, a.Name)
		if err != nil {
			t.Fatal(err)
		}
		other, err := corrosion.GetHost(ctx, source.DB, b.Name)
		if err != nil {
			t.Fatal(err)
		}
		if err := source.DB.ExecOutOfProcessForTest(`UPDATE hosts SET address=?,grpc_port=? WHERE name=?`, other.Address, other.GRPCPort, a.Name); err != nil {
			t.Fatal(err)
		}
		refused(t, request)
		if err := source.DB.ExecOutOfProcessForTest(`UPDATE hosts SET address=?,grpc_port=? WHERE name=?`, target.Address, target.GRPCPort, a.Name); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("actual-target-incarnation", func(t *testing.T) {
		oldInc, err := a.DB.VoterIncarnation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.DB.ReplaceVoterIncarnationForTest(ctx); err != nil {
			t.Fatal(err)
		}
		refused(t, request)
		if err := a.DB.ExecOutOfProcessForTest(`UPDATE local_voter_incarnation SET incarnation=? WHERE id=1`, oldInc); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("dependency-changed-during-actual-RPC", func(t *testing.T) {
		host, err := corrosion.GetHost(ctx, source.DB, source.Name)
		if err != nil {
			t.Fatal(err)
		}
		reached := make(chan struct{}, 1)
		a.HookUnary("GetRecoveryClaim", func(rpcCtx context.Context, raw any, handler grpc.UnaryHandler) (any, error) {
			if err := source.DB.ExecOutOfProcessForTest(`UPDATE hosts SET address='127.0.0.2' WHERE name=?`, source.Name); err != nil {
				return nil, err
			}
			reached <- struct{}{}
			return handler(rpcCtx, raw)
		})
		refused(t, request)
		select {
		case <-reached:
		default:
			t.Fatal("actual target RPC did not execute")
		}
		if err := source.DB.ExecOutOfProcessForTest(`UPDATE hosts SET address=? WHERE name=?`, host.Address, source.Name); err != nil {
			t.Fatal(err)
		}
		p, err := source.Server.PrepareAutomationSource(ctx, request)
		if err != nil {
			t.Fatal("restored source dependencies refused", err)
		}
		p.Discard()
	})
	t.Run("captured-served-signer-changed-during-actual-RPC", func(t *testing.T) {
		reached := make(chan struct{}, 1)
		a.HookUnary("GetRecoveryClaim", func(rpcCtx context.Context, raw any, handler grpc.UnaryHandler) (any, error) {
			if _, _, err := pki.RenewLocal(filepath.Join(source.PKIDir, "ca.crt"), filepath.Join(source.PKIDir, "ca.key"), source.PKIDir, source.Name); err != nil {
				return nil, err
			}
			reached <- struct{}{}
			return handler(rpcCtx, raw)
		})
		refused(t, request)
		select {
		case <-reached:
		default:
			t.Fatal("actual target RPC did not execute")
		}
		p, err := source.Server.PrepareAutomationSource(ctx, request)
		if err != nil {
			t.Fatal("fresh served signer refused", err)
		}
		p.Discard()
	})
	t.Run("bounded-registry-discard-cancel-progress", func(t *testing.T) {
		var held []*corrosion.AutomationSourcePreparation
		for i := 0; i < 8; i++ {
			p, err := source.Server.PrepareAutomationSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			held = append(held, p)
		}
		refused(t, request)
		for _, p := range held {
			p.Discard()
		}
		for i := 0; i < 132; i++ {
			p, err := source.Server.PrepareAutomationSource(ctx, request)
			if err != nil {
				t.Fatalf("discard leaked host slots at attempt %d: %v", i, err)
			}
			p.Discard()
		}
		cancelCtx, cancel := context.WithCancel(ctx)
		for i := 0; i < 8; i++ {
			p, err := source.Server.PrepareAutomationSource(cancelCtx, request)
			if err != nil {
				t.Fatal(err)
			}
			_ = p
		}
		cancel()
		eventually(t, 3*time.Second, "cancelled candidate slots to release", func() bool {
			p, err := source.Server.PrepareAutomationSource(ctx, request)
			if err != nil {
				return false
			}
			p.Discard()
			return true
		})
	})
	t.Run("current-renewal-reattests-exact-stored-accepts", func(t *testing.T) {
		for _, n := range []*Node{a, b} {
			if _, _, err := pki.RenewLocal(filepath.Join(n.PKIDir, "ca.crt"), filepath.Join(n.PKIDir, "ca.key"), n.PKIDir, n.Name); err != nil {
				t.Fatal(err)
			}
		}
		candidate, err := source.Server.PrepareAutomationSource(ctx, request)
		if err != nil {
			t.Fatalf("fresh renewal could not re-attest unchanged old cut: %v", err)
		}
		candidate.Discard()
	})
	again, err := engine.FreezeMembershipCut(ctx, 2)
	if err != nil || again != cut {
		t.Fatal("preparation changed archived content", again, err)
	}
	t.Run("reseed-lifecycle", func(t *testing.T) {
		generation, err := source.DB.BeginReseed(ctx, a.Name)
		if err != nil {
			t.Fatal(err)
		}
		refused(t, request)
		if err := source.DB.FinishReseed(ctx, generation); err != nil {
			t.Fatal(err)
		}
		refused(t, request)
	})
}

// Freeze after an ordinary committed accept, before successor adoption. No
// explicit local seal row is manufactured for this normal membership path.
func TestFleet_AutomationSourceImplicitSeal(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 52622})
	source, a, b, parked := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	initVoters(t, c, parked, source, a, b)
	old := voterRow(t, source, 1)
	engine, err := source.Server.AutomationEngine()
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	var cut string
	var freezeErr error
	frozen := make(chan struct{})
	source.Server.SetClaimVoteObserverForTest(func(v grpcapi.ClaimVote) {
		if v.Phase == "accept" && v.Key.TargetKind == corrosion.ClaimKindVoterConfig && v.Key.OwnerEpoch == 1 {
			once.Do(func() { cut, freezeErr = engine.FreezeMembershipCut(ctx, 1); close(frozen) })
		}
	})
	if _, err := c.SelfClient(source).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "add", Host: parked.Name}); err != nil {
		t.Fatal(err)
	}
	source.Server.SetClaimVoteObserverForTest(nil)
	select {
	case <-frozen:
	case <-time.After(3 * time.Second):
		t.Fatal("ordinary source accept callback did not finish")
	}
	if freezeErr != nil || cut == "" {
		t.Fatal("normal accept did not freeze", cut, freezeErr)
	}
	adoptAll(t, c, 2)
	p, err := source.Server.PrepareAutomationSource(ctx, corrosion.AutomationSourceRequest{Generation: 1, Target: parked.Name, Job: "implicit-seal", Revision: 1, Sources: old.Members})
	if err != nil {
		t.Fatalf("actual implicit sealed archive could not prepare: %v", err)
	}
	p.Discard()
	t.Run("close-during-real-RPC", func(t *testing.T) {
		// Keep the same named fixture database alive so the final replicated-shape
		// audit still reads every original mutation after the tested client closes.
		// No daemon work uses this extra handle.
		for _, node := range c.Nodes {
			if node.replStarted {
				node.repl.Stop()
				node.replStarted = false
			}
		}
		auditDB, err := corrosion.NewSharedTestClient("fleet-"+source.Name, source.Name)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { source.DB = auditDB }()
		entered := make(chan struct{})
		release := make(chan struct{})
		parked.HookUnary("GetRecoveryClaim", func(rpcCtx context.Context, raw any, handler grpc.UnaryHandler) (any, error) {
			result, err := handler(rpcCtx, raw)
			close(entered)
			select {
			case <-release:
				return result, err
			case <-rpcCtx.Done():
				return nil, rpcCtx.Err()
			}
		})
		request := corrosion.AutomationSourceRequest{Generation: 1, Target: parked.Name, Job: "close-race", Revision: 1, Sources: old.Members}
		type outcome struct {
			p   *corrosion.AutomationSourcePreparation
			err error
		}
		prepared := make(chan outcome, 1)
		go func() { p, err := source.Server.PrepareAutomationSource(ctx, request); prepared <- outcome{p, err} }()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("actual target RPC did not pause")
		}
		closed := make(chan error, 1)
		go func() { closed <- source.DB.Close() }()
		// This valid request cannot reach another RPC before Close wins the gate:
		// the real database has adopted only generation 2.
		closedProbe := request
		closedProbe.Generation = 1000
		eventually(t, 2*time.Second, "closed client registration gate", func() bool {
			p, err := source.Server.PrepareAutomationSource(ctx, closedProbe)
			if p != nil {
				p.Discard()
			}
			return err != nil && strings.Contains(err.Error(), "source client is closed")
		})
		select {
		case err := <-closed:
			t.Fatal("Close did not wait for in-flight construction", err)
		default:
		}
		close(release)
		select {
		case got := <-prepared:
			if got.p != nil {
				got.p.Discard()
			}
			if got.err == nil || got.p != nil {
				t.Fatal("in-flight closed client returned preparation", got.err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("preparation did not finish")
		}
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Close did not finish")
		}
		// All 256 real PKI registrations must remain available after the candidate
		// registers its validations and then observes the closed client barrier.
		view, err := pki.CaptureHostTrust(ctx, source.PKIDir, source.Name)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := pki.ServedHostKeyPair(source.PKIDir)
		if err != nil {
			t.Fatal(err)
		}
		var caps []*pki.HostCertificateValidation
		defer func() {
			for _, cap := range caps {
				cap.Discard()
			}
		}()
		for i := 0; i < 256; i++ {
			cap, err := view.ValidateHostCertificate(ctx, pair.Certificate, source.Name)
			if err != nil {
				t.Fatalf("Close leaked a PKI registration at %d: %v", i, err)
			}
			caps = append(caps, cap)
		}
	})
}
