package fleet

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_RecoveryClaim_ClaimReleaseCannotRaceARestoreRelocation is the
// window between RestoreContainer's claim of a carried relocation proof and
// the container lock it takes later. A release landing there finds nothing
// to refuse it: the lock is free, no container of the name exists, and no
// row carries the relocation's token yet, so the destination records the
// abandonment. The restore must then refuse to lay the container down —
// the database arbitrates, through the guarded start step it records before
// creating anything — or the destination runs a proof it has just promised
// never to run, while the next tick decides the workload afresh elsewhere.
//
// Scenario: container A's relocation by backup restore to D is decided under
// a legacy claim; D claims it and is held in the window (a hook). A is deleted
// and B re-created under the name elsewhere. D is asked for the operator
// release at B's scoped key and gives it. D's restore then resumes.
//
// Mutation: drop the guarded start step from RestoreContainer — D creates and
// starts the container after it released the proof.
func TestFleet_RecoveryClaim_ClaimReleaseCannotRaceARestoreRelocation(t *testing.T) {
	ctx := context.Background()
	const name = "ct-window"
	c, _, clock := incarnationFleet(t, 2573, func(*Cluster, *Node, *Node) {})
	a, d, second, victim := c.Nodes[0], c.Nodes[2], c.Nodes[3], c.Nodes[4]
	dead := map[string]bool{}

	// A lives on the victim and is backed up.
	createSizedContainer(t, c, victim, name, "", 1, 512)
	repo, ts := backupContainer(t, c, victim, name)
	c.WaitConvergedExcept(t, 2*convergeTimeout, []string{"leader_lease_terms", "audit_log", "operations", "operation_steps"})
	ctA, err := corrosion.GetContainer(ctx, a.DB, victim.Name, name)
	if err != nil || ctA == nil {
		t.Fatalf("read A: %v %+v", err, ctA)
	}
	alive := failHost(t, c, clock, dead, victim)

	// The relocation to D, decided at the legacy key.
	const token = "tok-a-window"
	p := corrosion.ActionProof{ID: "reloc-a-window", Action: corrosion.ActionRelocate, TargetKind: "container",
		TargetName: name, DestHost: d.Name, Coordinator: a.Name, RelocationToken: token,
		OwnerEpoch: fmt.Sprint(ctA.OwnerEpoch)}
	legacy := corrosion.ClaimKey{TargetKind: "container", TargetName: name, OwnerEpoch: ctA.OwnerEpoch}
	out, err := a.Server.DecideRecoveryClaim(ctx, legacy, corrosion.ClaimValue{Proof: &p, SourceHost: victim.Name}, 1, nil)
	if err != nil || !out.Ours {
		t.Fatalf("decide A's relocation at the legacy key: ours=%v %v", out.Ours, err)
	}
	cert, err := out.Certificate.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p.ClaimCertificate = cert
	if err := corrosion.WriteActionProof(ctx, a.DB, p); err != nil {
		t.Fatalf("write A's relocation proof: %v", err)
	}
	c.WaitConverged(t, convergeTimeout, alive...)

	// D's restore claims the proof and is held in the window.
	claimed, resume := make(chan struct{}), make(chan struct{})
	d.Server.SetRestoreClaimedHook(func(n string) {
		if n == name {
			close(claimed)
			<-resume
		}
	})
	defer d.Server.SetRestoreClaimedHook(nil)
	restored := make(chan error, 1)
	go func() {
		rctx := metadata.AppendToOutgoingContext(ctx, relocateTokenHeader, token)
		st, err := c.SelfClient(d).RestoreContainer(rctx, &pb.RestoreContainerRequest{
			RepoPath: repo, Name: name, Timestamp: ts, HostName: d.Name, Start: true, Proof: &pb.RuntimeActionProof{
				Id: p.ID, Action: p.Action, TargetKind: p.TargetKind, TargetName: p.TargetName, DestHost: p.DestHost,
				Coordinator: p.Coordinator, RelocationToken: p.RelocationToken, OwnerEpoch: p.OwnerEpoch,
				ClaimCertificate: p.ClaimCertificate}})
		if err != nil {
			restored <- err
			return
		}
		for {
			if _, rerr := st.Recv(); rerr != nil {
				if rerr == io.EOF {
					rerr = nil
				}
				restored <- rerr
				return
			}
		}
	}()
	select {
	case <-claimed:
	case err := <-restored:
		t.Fatalf("D's restore never reached the window: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("D's restore never reached the window")
	}
	if pr, ok, _ := corrosion.GetActionProof(ctx, d.DB, p.ID); !ok || pr.ExecutorHost != d.Name || pr.Status != corrosion.ProofInProgress {
		t.Fatalf("D did not claim the relocation: %+v", pr)
	}

	// A deleted; B re-created elsewhere; D releases A's proof at B's key.
	if err := corrosion.DeleteContainer(ctx, a.DB, victim.Name, name); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(ctx, a.DB, corrosion.ContainerRecord{HostName: second.Name, Name: name,
		Image: "docker.io/library/alpine:3.19", State: "running", MemMiB: 512}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout, alive...)
	ctB, err := corrosion.GetContainer(ctx, d.DB, second.Name, name)
	if err != nil || ctB == nil {
		t.Fatalf("D's replica of B: %v %+v", err, ctB)
	}
	keyB := corrosion.ClaimKey{TargetKind: "container", TargetName: name, OwnerEpoch: ctB.OwnerEpoch,
		Incarnation: corrosion.IncarnationOf(ctB.CreatedAt)}
	resp, err := c.SelfClient(d).AbandonRecoveryProof(ctx, &pb.AbandonRecoveryProofRequest{Key: &pb.RecoveryClaimKey{
		TargetKind: keyB.TargetKind, TargetName: keyB.TargetName, OwnerEpoch: keyB.OwnerEpoch, Incarnation: keyB.Incarnation},
		ProofId: p.ID, Reason: "test: operator release in the restore window", ForeignOnly: true, OperatorRelease: true})
	if err != nil || resp.GetAbandonment() == "" {
		// Refusing here is safe too; the scenario then shows nothing.
		t.Fatalf("the release in the window was refused, so the window is not exercised: %v", err)
	}

	// D's restore resumes: it must not lay the container down.
	close(resume)
	select {
	case err := <-restored:
		if err == nil {
			t.Fatal("D's restore succeeded after D released its proof")
		}
		t.Logf("D's restore after the release: %v", err)
	case <-time.After(60 * time.Second):
		t.Fatal("D's restore did not return")
	}
	if d.CT.Exists(name) || len(d.CT.StartCalls()) != 0 {
		t.Fatalf("D laid down %s after releasing its proof (exists=%v, starts=%v): a second runner",
			name, d.CT.Exists(name), d.CT.StartCalls())
	}
	if row, _ := corrosion.GetContainer(ctx, d.DB, d.Name, name); row != nil {
		t.Fatalf("D recorded %s after releasing its proof: %+v", name, row)
	}
}
