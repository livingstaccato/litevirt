package contract

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func continuityDecision(t *testing.T, kind string) (Decision, Projection) {
	t.Helper()
	realm := "local"
	actor := "original-uid"
	project := ""
	if kind == "project" {
		realm = ""
		actor = "actor-uid"
		project = "original-uid"
	}
	f := IdentityContinuity{ClusterUID: "cluster", UID: "original-uid", OriginalWitness: "original-witness", Generation: 7, Parent: ParentLifetime{Kind: kind, Alias: "alice", Realm: realm, Birth: "exact opaque birth"}}
	body, _ := json.Marshal(IdentityContinuityBody{Version: 1, IdentityContinuity: f})
	assignment, _ := json.Marshal(Assignment{Version: 1, ClusterUID: "cluster", OperationID: "attach-op", RecordedAt: "2026-10-22T00:00:00Z", Continuity: &f})
	d := Decision{Sequence: 3, ParentDigest: strings.Repeat("a", 64), Command: Command{Kind: IdentityContinuityCommand, ClusterUID: "cluster", ProjectUID: project, PrincipalID: actor, RequestID: "attach-request", ResourceUID: f.UID, Generation: f.Generation, Body: body}, Assignment: assignment}
	// Constructed certified-history predecessor only: no enrollment, native,
	// current parent, policy, session, quorum or FULL admission is established.
	p := Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 2, Digest: d.ParentDigest}, Continuity: &ContinuityProjection{Identity: &IdentityRecord{ClusterUID: f.ClusterUID, Kind: kind, UID: f.UID, Alias: f.Parent.Alias, Witness: f.OriginalWitness, Generation: f.Generation}}}
	return d, p
}

func TestContinuitySupportedKinds(t *testing.T) {
	for _, kind := range []string{"principal", "project"} {
		t.Run(kind, func(t *testing.T) {
			d, p := continuityDecision(t, kind)
			if e := ValidateSupportedCommand(d.Command); e != nil {
				t.Fatal(e)
			}
			if _, e := CanonicalCommand(d.Command); e != nil {
				t.Fatal(e)
			}
			if _, e := DecodeAssignment(d); e != nil {
				t.Fatal(e)
			}
			if e := ValidateSupportedDecision(d); e != nil {
				t.Fatal(e)
			}
			encoded, e := EncodeDecision(d)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = DecodeDecision(encoded); e != nil {
				t.Fatal(e)
			}
			old := *p.Continuity.Identity
			r, e := Reduce(p, d)
			if e != nil || r.Receipt.State != "succeeded" || r.Receipt.ResourceUID != old.UID || r.Receipt.Generation != old.Generation || r.ContinuityEffect == nil || r.ContinuityEffect.OriginalWitness != old.Witness || r.IdentityEffect != nil {
				t.Fatalf("attachment: %+v %v", r, e)
			}
			if *p.Continuity.Identity != old || p.Continuity.Existing != nil {
				t.Fatal("mutated predecessor")
			}
			r.ContinuityEffect.Parent.Birth = "mutated effect"
			if p.Continuity.Identity.Witness != old.Witness {
				t.Fatal("aliased effect")
			}
		})
	}
}

func TestContinuityPermanentRequestAndAttachment(t *testing.T) {
	d, p := continuityDecision(t, "principal")
	original, e := Reduce(p, d)
	if e != nil {
		t.Fatal(e)
	}
	f := *original.ContinuityEffect
	p.Continuity.Existing = &f
	p.Existing = &Request{Identity: original.Identity, Receipt: original.Receipt}
	retry := d
	retry.Sequence = 9
	// Session renewal is external to the closed command; reuse its immutable
	// intent and permanent RequestID. No session token belongs in this body.
	r, e := Reduce(p, retry)
	if e != nil || r.Receipt != original.Receipt || r.SaveRequest || r.ContinuityEffect != nil || r.IdentityEffect != nil || f.OriginalWitness != "original-witness" {
		t.Fatalf("permanent retry: %+v %v", r, e)
	}
	var body IdentityContinuityBody
	_ = json.Unmarshal(d.Command.Body, &body)
	body.Parent.Birth = "new birth"
	retry.Command.Body, _ = json.Marshal(body)
	a, _ := DecodeAssignment(d)
	a.Continuity = &body.IdentityContinuity
	retry.Assignment, _ = json.Marshal(a)
	r, e = Reduce(p, retry)
	if e != nil || r.Receipt.Code != CodeIdempotencyConflict || r.ContinuityEffect != nil {
		t.Fatalf("changed retry: %+v %v", r, e)
	}
	p.Existing = nil
	d.Command.RequestID = "second-request"
	r, e = Reduce(p, d)
	if e != nil || r.Receipt.OperationID != "attach-op" || r.Receipt.RequestID != "second-request" || r.ContinuityEffect != nil || r.Receipt.ResourceUID != "original-uid" || !r.SaveRequest {
		t.Fatalf("identical attachment: %+v %v", r, e)
	}
	retry.Command.RequestID = "third-request"
	r, e = Reduce(p, retry)
	if e != nil || r.Receipt.Code != CodeOwnershipConflict || r.ContinuityEffect != nil || r.IdentityEffect != nil || *p.Continuity.Existing != f {
		t.Fatalf("conflict: %+v %v", r, e)
	}
	// Rebuild the original with a fresh predecessor, including its exact effect.
	d, p = continuityDecision(t, "principal")
	p.ReplayOriginal = true
	p.Existing = &Request{Identity: original.Identity, Receipt: original.Receipt}
	p.Operation = &original.Receipt
	r, e = Reduce(p, d)
	if e != nil || r.Receipt != original.Receipt || r.ContinuityEffect == nil {
		t.Fatalf("original replay: %+v %v", r, e)
	}
}

func TestContinuityUnavailablePredecessors(t *testing.T) {
	cases := map[string]func(*Projection){
		"missing-projection": func(p *Projection) { p.Continuity = nil }, "missing-identity": func(p *Projection) { p.Continuity.Identity = nil },
		"uninitialized": func(p *Projection) { p.Head.Sequence = 0 }, "head-cluster": func(p *Projection) { p.Head.ClusterUID = "other" }, "head-digest": func(p *Projection) { p.Head.Digest = "other" },
		"cluster": func(p *Projection) { p.Continuity.Identity.ClusterUID = "other" }, "kind": func(p *Projection) { p.Continuity.Identity.Kind = "project" }, "alias": func(p *Projection) { p.Continuity.Identity.Alias = "other" }, "uid": func(p *Projection) { p.Continuity.Identity.UID = "other" }, "generation": func(p *Projection) { p.Continuity.Identity.Generation++ }, "witness": func(p *Projection) { p.Continuity.Identity.Witness = "other" }, "ownership": func(p *Projection) { p.Continuity.Identity.ProjectUID = "other" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d, p := continuityDecision(t, "principal")
			change(&p)
			snapshot, _ := json.Marshal(p)
			r, e := Reduce(p, d)
			after, _ := json.Marshal(p)
			if Code(e) != CodeUnavailable || r.ContinuityEffect != nil || r.IdentityEffect != nil || !bytes.Equal(snapshot, after) {
				t.Fatalf("unsafe predecessor: %+v %v", r, e)
			}
		})
	}
	d, p := continuityDecision(t, "principal")
	p.Continuity.Identity.Retired = true
	old := *p.Continuity.Identity
	r, e := Reduce(p, d)
	if e != nil || r.Receipt.Code != CodeRetired || r.Receipt.State != "rejected" || r.ContinuityEffect != nil || r.IdentityEffect != nil || *p.Continuity.Identity != old {
		t.Fatalf("retired: %+v %v", r, e)
	}
}

func TestContinuityCorruptAttachments(t *testing.T) {
	cases := map[string]func(*IdentityContinuity){"cluster": func(f *IdentityContinuity) { f.ClusterUID = "other" }, "uid": func(f *IdentityContinuity) { f.UID = "other" }, "witness": func(f *IdentityContinuity) { f.OriginalWitness = "other" }, "generation": func(f *IdentityContinuity) { f.Generation++ }, "zero": func(f *IdentityContinuity) { f.Generation = 0 }, "kind": func(f *IdentityContinuity) { f.Parent.Kind = "project"; f.Parent.Realm = "" }, "alias": func(f *IdentityContinuity) { f.Parent.Alias = "other" }, "realm": func(f *IdentityContinuity) { f.Parent.Realm = "remote" }, "birth": func(f *IdentityContinuity) { f.Parent.Birth = "" }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d, p := continuityDecision(t, "principal")
			a, _ := DecodeAssignment(d)
			f := *a.Continuity
			change(&f)
			p.Continuity.Existing = &f
			old := f
			r, e := Reduce(p, d)
			if Code(e) != CodeUnavailable || r.ContinuityEffect != nil || r.IdentityEffect != nil || f != old {
				t.Fatalf("corrupt attachment: %+v %v", r, e)
			}
		})
	}
}

func TestContinuityClosedBodiesAndAssignments(t *testing.T) {
	for _, kind := range []string{"principal", "project"} {
		t.Run(kind, func(t *testing.T) {
			d, _ := continuityDecision(t, kind)
			body := string(d.Command.Body)
			malformed := []string{
				strings.Replace(body, `"kind":`, `"unknown":true,"kind":`, 1),
				strings.Replace(body, `"birth":`, `"birth":"duplicate","birth":`, 1),
				strings.Replace(body, `"realm":"local",`, ``, 1),
				strings.Replace(body, `"realm":"",`, ``, 1),
				strings.Replace(body, `"realm":"local"`, `"realm":null`, 1),
				strings.Replace(body, `"realm":""`, `"realm":null`, 1),
				strings.Replace(body, `"generation":7`, `"generation":0`, 1),
				strings.Replace(body, `"generation":7`, `"generation":9223372036854775808`, 1),
				strings.Replace(body, `"generation":7`, `"generation":18446744073709551616`, 1),
				strings.Replace(body, `"birth":"exact opaque birth"`, `"birth":null`, 1),
				strings.Replace(body, `"birth":"exact opaque birth"`, `"birth":""`, 1),
				strings.Replace(body, `"version":1`, `"version":2`, 1), body + ` {}`,
				strings.Replace(body, `"parent":`, `"extra":true,"parent":`, 1),
				strings.Replace(body, `"original-witness"`, `"`+strings.Repeat("x", MaxStringBytes+1)+`"`, 1),
				strings.Replace(body, `"alice"`, `"\ud800"`, 1),
			}
			for n, b := range malformed {
				if b == body {
					continue
				}
				bad := d
				bad.Command.Body = []byte(b)
				if e := ValidateSupportedCommand(bad.Command); Code(e) != CodeValidation {
					t.Fatalf("body %d accepted: %v %s", n, e, b)
				}
			}
			// Every required field must be present/non-null, including the empty project realm.
			for _, field := range []string{"version", "cluster_uid", "uid", "original_witness", "generation", "parent"} {
				var m map[string]json.RawMessage
				_ = json.Unmarshal(d.Command.Body, &m)
				delete(m, field)
				bad := d
				bad.Command.Body, _ = json.Marshal(m)
				if e := ValidateSupportedCommand(bad.Command); Code(e) != CodeValidation {
					t.Fatalf("missing %s: %v", field, e)
				}
			}
			for _, field := range []string{"kind", "alias", "realm", "birth"} {
				var m map[string]any
				_ = json.Unmarshal(d.Command.Body, &m)
				delete(m["parent"].(map[string]any), field)
				bad := d
				bad.Command.Body, _ = json.Marshal(m)
				if e := ValidateSupportedCommand(bad.Command); Code(e) != CodeValidation {
					t.Fatalf("missing parent %s: %v", field, e)
				}
			}
			assignment := string(d.Assignment)
			for _, badText := range []string{strings.Replace(assignment, `"birth":`, `"unknown":true,"birth":`, 1), strings.Replace(assignment, `"birth":`, `"birth":"duplicate","birth":`, 1), strings.Replace(assignment, `"continuity":`, `"identity":{},"continuity":`, 1), strings.Replace(assignment, `"original-witness"`, `"altered"`, 1), strings.Replace(assignment, `"generation":7`, `"generation":8`, 1), strings.Replace(assignment, `"realm":"",`, ``, 1), strings.Replace(assignment, `"cluster_uid":"cluster"`, `"cluster_uid":"wrong"`, 1)} {
				if badText == assignment {
					continue
				}
				bad := d
				bad.Assignment = []byte(badText)
				if e := ValidateSupportedDecision(bad); Code(e) != CodeValidation {
					t.Fatalf("assignment accepted: %v %s", e, badText)
				}
			}
		})
	}
}

func TestContinuityCommandScopeAndBounds(t *testing.T) {
	changes := map[string]func(*Command){"cluster": func(c *Command) { c.ClusterUID = "other" }, "uid": func(c *Command) { c.ResourceUID = "other" }, "generation": func(c *Command) { c.Generation++ }, "actor": func(c *Command) { c.PrincipalID = "other" }, "project": func(c *Command) { c.ProjectUID = "other" }, "request": func(c *Command) { c.RequestID = "" }, "owner": func(c *Command) { c.OwnerID = "owner" }, "management": func(c *Command) { c.ManagementKey = "key" }, "session": func(c *Command) { c.Session = 1 }, "session-id": func(c *Command) { c.SessionID = "sid" }, "revision": func(c *Command) { c.ExpectedRevision = 1 }, "ciphertext": func(c *Command) { c.Ciphertext = []byte{1} }, "secret": func(c *Command) { c.SecretIntentTag = []byte{1} }, "epoch": func(c *Command) { c.SecretKeyEpoch = "epoch" }, "long-request": func(c *Command) { c.RequestID = strings.Repeat("x", MaxStringBytes+1) }, "invalid-actor": func(c *Command) { c.PrincipalID = string([]byte{255}) }}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			d, _ := continuityDecision(t, "principal")
			change(&d.Command)
			if e := ValidateSupportedCommand(d.Command); Code(e) != CodeValidation {
				t.Fatalf("invalid command accepted: %v", e)
			}
		})
	}
	d, _ := continuityDecision(t, "principal")
	if Scope(d) != `["cluster","","identity-continuity","original-uid","7"]` {
		t.Fatal(Scope(d))
	}
	for _, kind := range []string{"assign_identity", "ensure_owner", OrdinaryCreateCommand, "initialize_cluster", "read_barrier"} {
		other := d
		other.Command.Kind = kind
		if Scope(other) == Scope(d) {
			t.Fatalf("scope collision %s", kind)
		}
	}
	d, _ = continuityDecision(t, "project")
	if Scope(d) != `["cluster","original-uid","identity-continuity","original-uid","7"]` {
		t.Fatal(Scope(d))
	}
	before, _ := CanonicalCommand(d.Command)
	d.Command.PrincipalID = "second-actor"
	after, _ := CanonicalCommand(d.Command)
	if bytes.Equal(before, after) {
		t.Fatal("actor missing from retry identity")
	}
	if e := ValidateSupportedCommand(d.Command); e != nil {
		t.Fatal(e)
	}
	d.Command.ProjectUID = ""
	if e := ValidateSupportedCommand(d.Command); Code(e) != CodeValidation {
		t.Fatal("project target scope missing", e)
	}
	d, _ = continuityDecision(t, "principal")
	var b IdentityContinuityBody
	_ = json.Unmarshal(d.Command.Body, &b)
	b.Generation = math.MaxInt64
	b.Parent.Birth = strings.Repeat("b", MaxStringBytes)
	d.Command.Generation = b.Generation
	d.Command.RequestID = strings.Repeat("r", MaxStringBytes)
	d.Command.Body, _ = json.Marshal(b)
	if e := ValidateSupportedCommand(d.Command); e != nil {
		t.Fatal("inclusive bounds", e)
	}
}

func TestContinuityPreservesLegacyBytesAndFieldSets(t *testing.T) {
	for _, kind := range []string{"assign_identity", "initialize_cluster", "ensure_owner"} {
		c := Command{Kind: kind, RequestID: "old-request", Body: []byte(`{"version":1}`)}
		got, e := CanonicalCommand(c)
		if e != nil {
			t.Fatal(e)
		}
		want := "litevirt/automation/command/v1\x00" + `{"Kind":"` + kind + `","ClusterUID":"","ProjectUID":"","PrincipalID":"","OwnerID":"","ManagementKey":"","RequestID":"old-request","ResourceUID":"","Generation":0,"ExpectedRevision":0,"Body":{"version":1},"SecretIntentTag":null,"SecretKeyEpoch":""}`
		if string(got) != want {
			t.Fatalf("old %s canonical bytes changed: %q", kind, got)
		}
		a := Assignment{Version: 1, ClusterUID: "old-cluster", OperationID: "old-op", RecordedAt: "2026-10-22T00:00:00Z"}
		raw, _ := json.Marshal(a)
		if string(raw) != `{"version":1,"cluster_uid":"old-cluster","operation_id":"old-op","recorded_at":"2026-10-22T00:00:00Z"}` {
			t.Fatal("old assignment bytes changed", string(raw))
		}
		d := Decision{Command: c, Assignment: raw}
		if _, e := DecodeAssignment(d); e != nil {
			t.Fatal(e)
		}
		for _, field := range []string{"unknown", "continuity"} {
			var fields map[string]any
			_ = json.Unmarshal(raw, &fields)
			fields[field] = map[string]any{}
			d.Assignment, _ = json.Marshal(fields)
			if _, e := DecodeAssignment(d); Code(e) != CodeValidation {
				t.Fatalf("old %s accepts %s: %v", kind, field, e)
			}
		}
	}
	// Explicit lower-case tags preserve the exact four semantic P1 fields.
	p := ParentLifetime{Kind: "principal", Alias: "alice", Realm: "local", Birth: "literal"}
	var round ParentLifetime
	b, _ := json.Marshal(p)
	_ = json.Unmarshal(b, &round)
	if !reflect.DeepEqual(round, p) || string(b) != `{"kind":"principal","alias":"alice","realm":"local","birth":"literal"}` {
		t.Fatal(string(b))
	}
}

func TestContinuitySupportRED(t *testing.T) {
	c := Command{Kind: "attach_identity_lifetime", ClusterUID: "cluster", PrincipalID: "principal-uid", ResourceUID: "principal-uid", Generation: 1, RequestID: "attach-request", Body: []byte(`{"version":1,"cluster_uid":"cluster","uid":"principal-uid","original_witness":"original-witness","generation":1,"parent":{"kind":"principal","alias":"alice","realm":"local","birth":"birth-1"}}`)}
	d := Decision{Sequence: 3, Command: c, Assignment: []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"attach-op","recorded_at":"2026-10-22T00:00:00Z","continuity":{"cluster_uid":"cluster","uid":"principal-uid","original_witness":"original-witness","generation":1,"parent":{"kind":"principal","alias":"alice","realm":"local","birth":"birth-1"}}}`)}
	t.Run("supported-command", func(t *testing.T) {
		if e := ValidateSupportedCommand(c); e != nil {
			t.Fatalf("valid new continuity command must be supported: %v", e)
		}
	})
	t.Run("canonical-command", func(t *testing.T) {
		if _, e := CanonicalCommand(c); e != nil {
			t.Fatalf("valid new continuity canonical identity must be supported: %v", e)
		}
	})
	t.Run("typed-assignment", func(t *testing.T) {
		if _, e := DecodeAssignment(d); e != nil {
			t.Fatalf("valid new continuity assignment must be supported: %v", e)
		}
	})
	t.Run("supported-decision", func(t *testing.T) {
		if e := ValidateSupportedDecision(d); e != nil {
			t.Fatalf("valid new continuity decision must be supported: %v", e)
		}
	})
}
