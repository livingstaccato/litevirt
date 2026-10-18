package contract

import (
	"encoding/json"
	"math"
)

// OwnerRecord separates client activation from runtime host owner epochs.
// FounderPrincipalUID survives handoff; SessionPrincipalUID is the explicitly
// enrolled principal allowed to use the current session.
type OwnerRecord struct {
	ClusterUID, ProjectUID, OwnerID, FounderPrincipalUID string
	SessionID, SessionPrincipalUID                       string
	Activation                                           uint64
}

type OwnerBody struct {
	Version          int    `json:"version"`
	NextPrincipalUID string `json:"next_principal_uid,omitempty"`
}

type OwnerAssignment struct {
	SessionID string `json:"session_id"`
}

type OwnershipProjection struct {
	AssignedSession                   *OwnerRecord
	Project, Principal, NextPrincipal *IdentityRecord
	Owner                             *OwnerRecord
}

func DecodeOwnerBody(c Command) (OwnerBody, error) {
	var b OwnerBody
	fields := []string{"version"}
	if c.Kind == "handoff_session" {
		fields = append(fields, "next_principal_uid")
	}
	if decodeFields(c.Body, &b, fields...) != nil || b.Version != 1 || c.ClusterUID == "" || c.ProjectUID == "" || c.OwnerID == "" || c.PrincipalID == "" || c.RequestID == "" || c.ManagementKey != "" || c.ResourceUID != "" || c.Generation != 0 || c.ExpectedRevision != 0 || len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" || c.Session > math.MaxInt64 || len(c.SessionID) > MaxStringBytes {
		return b, codedError(CodeValidation)
	}
	if c.Kind == "handoff_session" {
		if c.Session == 0 || c.SessionID == "" || b.NextPrincipalUID == "" || len(b.NextPrincipalUID) > MaxStringBytes {
			return b, codedError(CodeValidation)
		}
	} else if c.Session != 0 || c.SessionID != "" {
		return b, codedError(CodeValidation)
	}
	return b, nil
}

func validateOwnerAssignment(d Decision, a Assignment) error {
	if a.ClusterUID != d.Command.ClusterUID || a.Identity != nil {
		return codedError(CodeValidation)
	}
	if d.Command.Kind == "ensure_owner" {
		if a.Owner != nil {
			return codedError(CodeValidation)
		}
		return nil
	}
	if a.Owner == nil || a.Owner.SessionID == "" || len(a.Owner.SessionID) > MaxStringBytes || a.Owner.SessionID == d.Command.SessionID {
		return codedError(CodeValidation)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(d.Assignment, &raw) != nil {
		return codedError(CodeValidation)
	}
	var nested OwnerAssignment
	return decodeFieldsObject(raw["owner"], &nested, "session_id")
}

func liveIdentity(r *IdentityRecord, cluster, kind, uid string) bool {
	return r != nil && r.ClusterUID == cluster && r.Kind == kind && r.UID == uid && r.ProjectUID == "" && r.Generation > 0 && !r.Retired
}

func reduceOwner(out *Reduction, p Projection, d Decision, a Assignment) error {
	c := d.Command
	b, err := DecodeOwnerBody(c)
	if err != nil {
		return err
	}
	if p.Head.Sequence == 0 || p.Head.ClusterUID != c.ClusterUID || p.Ownership == nil {
		return codedError(CodeUnavailable)
	}
	facts := p.Ownership
	if !liveIdentity(facts.Project, c.ClusterUID, "project", c.ProjectUID) || !liveIdentity(facts.Principal, c.ClusterUID, "principal", c.PrincipalID) {
		return codedError(CodeUnavailable)
	}
	out.Receipt.ResourceUID = ""
	old := facts.Owner
	if old != nil && (old.ClusterUID != c.ClusterUID || old.ProjectUID != c.ProjectUID || old.OwnerID != c.OwnerID || old.FounderPrincipalUID == "") {
		return codedError(CodeUnavailable)
	}
	if a.Owner != nil && facts.AssignedSession != nil {
		rejectReduction(out, CodeValidation)
		return nil
	}
	switch c.Kind {
	case "ensure_owner":
		if old != nil {
			if old.FounderPrincipalUID != c.PrincipalID {
				rejectReduction(out, CodeOwnershipConflict)
			} else {
				out.Receipt.Generation = old.Activation
			}
			return nil
		}
		out.OwnerEffect = &OwnerRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, OwnerID: c.OwnerID, FounderPrincipalUID: c.PrincipalID}
	case "acquire_session":
		if old == nil || old.FounderPrincipalUID != c.PrincipalID || old.Activation != 0 || old.SessionID != "" {
			rejectReduction(out, CodeOwnershipConflict)
			return nil
		}
		next := *old
		next.Activation = 1
		next.SessionID = a.Owner.SessionID
		next.SessionPrincipalUID = c.PrincipalID
		out.OwnerEffect = &next
		out.Receipt.Generation = 1
	case "handoff_session":
		if old == nil || old.SessionID != c.SessionID || old.Activation != c.Session || old.SessionPrincipalUID != c.PrincipalID || old.Activation >= math.MaxInt64 {
			rejectReduction(out, CodeOwnershipConflict)
			return nil
		}
		if !liveIdentity(facts.NextPrincipal, c.ClusterUID, "principal", b.NextPrincipalUID) {
			return codedError(CodeUnavailable)
		}
		next := *old
		next.Activation++
		next.SessionID = a.Owner.SessionID
		next.SessionPrincipalUID = b.NextPrincipalUID
		out.OwnerEffect = &next
		out.Receipt.Generation = next.Activation
	}
	return nil
}
