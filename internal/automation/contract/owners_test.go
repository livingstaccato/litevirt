package contract

import (
	"strings"
	"testing"
)

func ownerDecision(kind string) Decision {
	c := Command{Kind: kind, ClusterUID: "cluster", ProjectUID: "project", PrincipalID: "principal", OwnerID: "owner/key", RequestID: "request", Body: []byte(`{"version":1}`)}
	assignment := `{"version":1,"cluster_uid":"cluster","operation_id":"owner-operation","recorded_at":"2026-10-17T00:00:00Z"}`
	if kind != "ensure_owner" {
		assignment = `{"version":1,"cluster_uid":"cluster","operation_id":"owner-operation","recorded_at":"2026-10-17T00:00:00Z","owner":{"session_id":"new-session"}}`
	}
	if kind == "handoff_session" {
		c.Session = 1
		c.SessionID = "old-session"
		c.Body = []byte(`{"version":1,"next_principal_uid":"successor"}`)
	}
	return Decision{Sequence: 7, ParentDigest: strings.Repeat("a", 64), Command: c, Assignment: []byte(assignment)}
}
func ownerProjection() Projection {
	return Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 6}, Ownership: &OwnershipProjection{
		Project:       &IdentityRecord{ClusterUID: "cluster", Kind: "project", UID: "project", Alias: "acme", Witness: "project-witness", Generation: 1},
		Principal:     &IdentityRecord{ClusterUID: "cluster", Kind: "principal", UID: "principal", Alias: "alice", Witness: "principal-lifetime", Generation: 1},
		NextPrincipal: &IdentityRecord{ClusterUID: "cluster", Kind: "principal", UID: "successor", Alias: "bob", Witness: "successor-lifetime", Generation: 1},
	}}
}
func currentOwner() *OwnerRecord {
	return &OwnerRecord{ClusterUID: "cluster", ProjectUID: "project", OwnerID: "owner/key", FounderPrincipalUID: "principal", SessionPrincipalUID: "principal", SessionID: "old-session", Activation: 1}
}

func TestAutomationOwnershipEnsureAndAcquire(t *testing.T) {
	p := ownerProjection()
	d := ownerDecision("ensure_owner")
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.OwnerEffect == nil || r.OwnerEffect.FounderPrincipalUID != "principal" || r.OwnerEffect.Activation != 0 {
		t.Fatalf("ensure owner: receipt=%+v effect=%+v err=%v", r.Receipt, r.OwnerEffect, err)
	}
	p.Ownership.Owner = r.OwnerEffect
	d = ownerDecision("acquire_session")
	r, err = Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.OwnerEffect == nil || r.OwnerEffect.Activation != 1 || r.OwnerEffect.SessionID != "new-session" || r.OwnerEffect.SessionPrincipalUID != "principal" {
		t.Fatalf("acquire owner: receipt=%+v effect=%+v err=%v", r.Receipt, r.OwnerEffect, err)
	}
}

func TestAutomationHandoffFencesOldSession(t *testing.T) {
	p := ownerProjection()
	p.Ownership.Owner = currentOwner()
	d := ownerDecision("handoff_session")
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.OwnerEffect == nil || r.OwnerEffect.Activation != 2 || r.OwnerEffect.SessionID != "new-session" || r.OwnerEffect.SessionPrincipalUID != "successor" || r.OwnerEffect.FounderPrincipalUID != "principal" {
		t.Fatalf("handoff: receipt=%+v effect=%+v err=%v", r.Receipt, r.OwnerEffect, err)
	}
	p.Ownership.Owner = r.OwnerEffect
	r, err = Reduce(p, d)
	if err != nil || r.Receipt.Code != CodeOwnershipConflict || r.OwnerEffect != nil {
		t.Fatalf("stale handoff admitted: %+v %v", r.Receipt, err)
	}
}

func TestAutomationOwnershipPrincipalRecreationCannotInherit(t *testing.T) {
	p := ownerProjection()
	p.Ownership.Owner = currentOwner()
	p.Ownership.Owner.Activation = 0
	p.Ownership.Owner.SessionID = ""
	p.Ownership.Owner.SessionPrincipalUID = ""
	p.Ownership.Principal.UID = "recreated-principal"
	d := ownerDecision("acquire_session")
	d.Command.PrincipalID = "recreated-principal"
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != CodeOwnershipConflict || r.OwnerEffect != nil {
		t.Fatalf("same username inherited owner: %+v %v", r.Receipt, err)
	}
}

func TestAutomationHandoffRequiresSessionAndActivation(t *testing.T) {
	for _, field := range []string{"session", "activation", "principal", "retired", "overflow"} {
		t.Run(field, func(t *testing.T) {
			p := ownerProjection()
			p.Ownership.Owner = currentOwner()
			d := ownerDecision("handoff_session")
			switch field {
			case "session":
				d.Command.SessionID = "wrong"
			case "activation":
				d.Command.Session = 2
			case "principal":
				p.Ownership.Owner.SessionPrincipalUID = "other"
			case "retired":
				p.Ownership.Principal.Retired = true
			case "overflow":
				p.Ownership.Owner.Activation = 9223372036854775807
				d.Command.Session = 9223372036854775807
			}
			r, err := Reduce(p, d)
			if err == nil && r.Receipt.Code == "" {
				t.Fatalf("invalid current authority admitted: %+v", r.Receipt)
			}
			if r.OwnerEffect != nil {
				t.Fatal("failed handoff changed owner")
			}
		})
	}
}

func TestAutomationOwnershipAssignedSessionCollision(t *testing.T) {
	p := ownerProjection()
	p.Ownership.Owner = currentOwner()
	d := ownerDecision("handoff_session")
	p.Ownership.AssignedSession = &OwnerRecord{ClusterUID: "cluster", ProjectUID: "other-project", OwnerID: "other-owner", SessionID: "new-session", Activation: 1}
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != CodeValidation || r.OwnerEffect != nil {
		t.Fatalf("assigned session aliased another owner: %+v %v", r.Receipt, err)
	}
}
