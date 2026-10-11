// Fleet scenario for the merge of fix/credentials-clear and feat/login-policy
// (progress.md MERGE-TIME CHECKLIST M1): login-policy's GetUser matches the
// normalized name, credentials-clear's UserLocalCredential matches exactly.
package fleet

import (
	"context"
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_CredentialsClear_ACaseVariantOIDCSubjectNeverAdoptsALaggingLocalAccount:
// after the clear, a local admin `ops` reaches a node with an empty old column
// and its credential row still in flight. An OIDC subject is not normalized,
// so `Ops` arrives as written; GetUser finds `ops`, and the local-or-external
// judgement must be made on `ops` — judged on `Ops` it finds no row, and the
// external principal used to be handed the local admin's account.
func TestFleet_CredentialsClear_ACaseVariantOIDCSubjectNeverAdoptsALaggingLocalAccount(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 2701})
	a, n := c.Nodes[0], c.Nodes[1]
	c.WaitConverged(t, convergeTimeout)
	latchAndClear(t, a, n)
	c.WaitConverged(t, convergeTimeout)

	// n hears of ops only through its own anti-entropy, and only the public lane.
	c.SetLinkFault(a, n, LinkFault{Block: true})
	restore := a.DoNotImplement("GetSensitiveStateDigest")
	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "ops", Password: "0ps-pass", Role: "admin",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	if u, err := corrosion.GetUser(ctx, n.DB, "Ops"); err != nil || u == nil || u.Username != "ops" || u.PasswordHash != "" {
		t.Fatalf("%s holds ops as %+v (err %v); the scenario needs the cleared users row, found by its "+
			"variant spelling, without its credential", n.Name, u, err)
	}
	p := &auth.Principal{Subject: "Ops", Realm: "oidc:corp"}
	err := auth.EnsureUserShadow(ctx, n.DB, p, "viewer")
	if err == nil {
		t.Fatalf("an OIDC principal `Ops` adopted the local admin ops (subject now %q) while its credential row was in flight", p.Subject)
	}
	if !errors.Is(err, auth.ErrShadowPending) && !errors.Is(err, auth.ErrExternalUnproven) {
		t.Errorf("EnsureUserShadow(Ops) = %v, want ErrShadowPending or ErrExternalUnproven", err)
	}

	restore()
	corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	if u, _ := corrosion.GetUser(ctx, n.DB, "ops"); u == nil || u.PasswordHash == "" {
		t.Fatalf("ops's credential did not arrive on %s; the rest is vacuous", n.Name)
	}
	if err := auth.EnsureUserShadow(ctx, n.DB, &auth.Principal{Subject: "Ops", Realm: "oidc:corp"}, "viewer"); !errors.Is(err, auth.ErrLocalAccount) {
		t.Errorf("after ops's credential arrived, EnsureUserShadow(Ops) = %v, want ErrLocalAccount", err)
	}
}
