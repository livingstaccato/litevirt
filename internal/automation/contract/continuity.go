package contract

import (
	"encoding/json"
	"math"
	"unicode/utf8"
)

// ParentLifetime records exact facts from a current parent owner. It is not a
// certified identity or evidence of originating observation.
type ParentLifetime struct {
	Kind  string `json:"kind"`
	Alias string `json:"alias"`
	Realm string `json:"realm"`
	Birth string `json:"birth"`
}

const IdentityContinuityCommand = "attach_identity_lifetime"

// IdentityContinuity attaches an existing certified identity to its exact
// parent lifetime. These nonsecret facts supply no authorization or currentness.
type IdentityContinuity struct {
	ClusterUID      string         `json:"cluster_uid"`
	UID             string         `json:"uid"`
	OriginalWitness string         `json:"original_witness"`
	Generation      uint64         `json:"generation"`
	Parent          ParentLifetime `json:"parent"`
}

type IdentityContinuityBody struct {
	Version int `json:"version"`
	IdentityContinuity
}

// ContinuityProjection must come from the authoritative predecessor history.
// A missing identity is unavailable, never permission to allocate one.
type ContinuityProjection struct {
	Identity *IdentityRecord
	Existing *IdentityContinuity
}

// ValidateIdentityContinuity checks inert fact shape only; it supplies no
// currentness, provenance, admission, or identity allocation authority.
func ValidateIdentityContinuity(f IdentityContinuity) error {
	if !validContinuity(f) {
		return codedError(CodeValidation)
	}
	return nil
}

func validContinuity(f IdentityContinuity) bool {
	for _, s := range []string{f.ClusterUID, f.UID, f.OriginalWitness, f.Parent.Kind, f.Parent.Alias, f.Parent.Birth} {
		if s == "" || len(s) > MaxStringBytes || !utf8.ValidString(s) {
			return false
		}
	}
	if !utf8.ValidString(f.Parent.Realm) || len(f.Parent.Realm) > MaxStringBytes || f.Generation == 0 || f.Generation > math.MaxInt64 {
		return false
	}
	return (f.Parent.Kind == "principal" && f.Parent.Realm == "local") || (f.Parent.Kind == "project" && f.Parent.Realm == "")
}

func continuityFields(raw []byte, body bool) bool {
	fields := []string{"cluster_uid", "uid", "original_witness", "generation", "parent"}
	if body {
		fields = append(fields, "version")
	}
	if !requiredIdentityFields(raw, fields...) {
		return false
	}
	var outer map[string]json.RawMessage
	if json.Unmarshal(raw, &outer) != nil {
		return false
	}
	var parent ParentLifetime
	return decodeFieldsObject(outer["parent"], &parent, "kind", "alias", "realm", "birth") == nil && requiredIdentityFields(outer["parent"], "kind", "alias", "realm", "birth")
}

func DecodeIdentityContinuityBody(c Command) (IdentityContinuityBody, error) {
	var b IdentityContinuityBody
	if c.Kind != IdentityContinuityCommand || decodeFields(c.Body, &b, "version", "cluster_uid", "uid", "original_witness", "generation", "parent") != nil || !continuityFields(c.Body, true) || b.Version != 1 || !validContinuity(b.IdentityContinuity) {
		return b, codedError(CodeValidation)
	}
	if c.ClusterUID != b.ClusterUID || c.ResourceUID != b.UID || c.Generation != b.Generation || c.PrincipalID == "" || c.RequestID == "" || c.OwnerID != "" || c.ManagementKey != "" || c.Session != 0 || c.SessionID != "" || c.ExpectedRevision != 0 || len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" {
		return b, codedError(CodeValidation)
	}
	for _, s := range []string{c.PrincipalID, c.RequestID, c.ProjectUID} {
		if len(s) > MaxStringBytes || !utf8.ValidString(s) {
			return b, codedError(CodeValidation)
		}
	}
	if (b.Parent.Kind == "principal" && (c.PrincipalID != b.UID || c.ProjectUID != "")) || (b.Parent.Kind == "project" && c.ProjectUID != b.UID) {
		return b, codedError(CodeValidation)
	}
	return b, nil
}

func validateContinuityAssignment(d Decision, a Assignment) error {
	b, e := DecodeIdentityContinuityBody(d.Command)
	if e != nil {
		return e
	}
	if a.Continuity == nil || *a.Continuity != b.IdentityContinuity || a.ClusterUID != b.ClusterUID {
		return codedError(CodeValidation)
	}
	return nil
}

func reduceContinuity(out *Reduction, p Projection, d Decision, a Assignment) error {
	f := *a.Continuity
	if p.Head.Sequence == 0 || p.Head.ClusterUID != f.ClusterUID || p.Head.Digest != d.ParentDigest || p.Continuity == nil || p.Continuity.Identity == nil {
		return codedError(CodeUnavailable)
	}
	i := p.Continuity.Identity
	if i.ClusterUID != f.ClusterUID || i.ProjectUID != "" || i.Kind != f.Parent.Kind || i.UID != f.UID || i.Generation != f.Generation || i.Alias != f.Parent.Alias || i.Witness != f.OriginalWitness {
		return codedError(CodeUnavailable)
	}
	if i.Retired {
		rejectReduction(out, CodeRetired)
		return nil
	}
	if old := p.Continuity.Existing; old != nil {
		if !validContinuity(*old) || old.ClusterUID != i.ClusterUID || old.UID != i.UID || old.Generation != i.Generation || old.OriginalWitness != i.Witness || old.Parent.Kind != i.Kind || old.Parent.Alias != i.Alias {
			return codedError(CodeUnavailable)
		}
		if *old != f {
			rejectReduction(out, CodeOwnershipConflict)
			return nil
		}
	} else {
		out.ContinuityEffect = &f
	}
	out.Receipt.ResourceUID = i.UID
	out.Receipt.Generation = i.Generation
	return nil
}
