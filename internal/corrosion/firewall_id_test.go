package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

// Firewall identity at the writers (spec §4.3). Every writer of vms.spec and
// containers.create_spec keeps fw_id as the §4.3 table says: an insert strips
// an incoming one unless it carries a token, an update keeps the current one, a
// carry insert keeps the source's and ReplaceVM the replacement's.
//
// Mutation (spec §4.9): let an insert keep the incoming fw_id — the insert
// cases go red.

// identityReads is the identity every decoder the tree uses on the column
// reads from doc: the exact-key reader the member query uses, encoding/json
// (into pb.VMSpec for a VM, the fw_id field for a container) and, for a VM,
// protojson. A decoder that cannot parse doc reads "".
func identityReads(kind, doc string) map[string]string {
	out := map[string]string{"exact": jsonExactString(doc, firewallIDKey(kind))}
	if kind == TagMemberVM {
		var s pb.VMSpec
		_ = json.Unmarshal([]byte(doc), &s)
		out["encoding/json"] = s.FirewallId
		var p pb.VMSpec
		if (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal([]byte(doc), &p) == nil {
			out["protojson"] = p.FirewallId
		} else {
			out["protojson"] = ""
		}
		return out
	}
	var s struct {
		FWID string `json:"fw_id"`
	}
	_ = json.Unmarshal([]byte(doc), &s)
	out["encoding/json"] = s.FWID
	return out
}

// assertIdentity fails unless every decoder reads exactly want from doc.
func assertIdentity(t *testing.T, what, kind, doc, want string) {
	t.Helper()
	for reader, got := range identityReads(kind, doc) {
		if got != want {
			t.Errorf("%s: %s reads identity %q from %s, want %q", what, reader, got, doc, want)
		}
	}
}

func storedVMSpec(t *testing.T, c *Client, name string) string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT spec FROM vms WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read vm %s: %v (%d rows)", name, err, len(rows))
	}
	return rows[0].String("spec")
}

func storedCreateSpec(t *testing.T, c *Client, host, name string) string {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT COALESCE(create_spec, '') AS create_spec FROM containers WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		host, name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read container %s/%s: %v (%d rows)", host, name, err, len(rows))
	}
	return rows[0].String("create_spec")
}

// rawVM stores a live VM row exactly as given, as a build before D2a could.
func rawVM(t *testing.T, c *Client, name, spec string) {
	t.Helper()
	mustExec(t, c, `INSERT INTO vms (name, stack_name, host_name, spec, state, created_at, updated_at)
		VALUES (?, 's', 'h1', ?, 'stopped', 'c-'||?, '1')`, name, spec, name)
}

// rawContainer stores a live container row exactly as given.
func rawContainer(t *testing.T, c *Client, host, name, createSpec string) {
	t.Helper()
	mustExec(t, c, `INSERT INTO containers (host_name, name, state, image, create_spec, created_at, updated_at)
		VALUES (?, ?, 'running', 'alpine', ?, 'c-'||?, '1')`, host, name, createSpec, name)
}

// vmIDVariants are incoming VM specs whose identity a decoder reads, keyed by
// how they spell it: none may survive an insert. Each also holds cpu, which
// must survive.
func vmIDVariants(id string) map[string]string {
	return map[string]string{
		"canonical":      fmt.Sprintf(`{"cpu":2,"firewall_id":%q}`, id),
		"case":           fmt.Sprintf(`{"cpu":2,"Firewall_ID":%q}`, id),
		"upper":          fmt.Sprintf(`{"cpu":2,"FIREWALL_ID":%q}`, id),
		"escaped":        fmt.Sprintf(`{"cpu":2,"firewall_id":%q}`, id),
		"protojson name": fmt.Sprintf(`{"cpu":2,"firewallId":%q}`, id),
		"duplicate":      fmt.Sprintf(`{"cpu":2,"firewall_id":"junk","firewall_id":%q}`, id),
		"two spellings":  fmt.Sprintf(`{"cpu":2,"FireWall_Id":%q,"firewall_id":%q}`, id, id),
	}
}

// ctIDVariants are vmIDVariants for a container create_spec.
func ctIDVariants(id string) map[string]string {
	return map[string]string{
		"canonical":     fmt.Sprintf(`{"template":"debian","fw_id":%q}`, id),
		"case":          fmt.Sprintf(`{"template":"debian","FW_ID":%q}`, id),
		"mixed":         fmt.Sprintf(`{"template":"debian","Fw_Id":%q}`, id),
		"escaped":       fmt.Sprintf(`{"template":"debian","fw_id":%q}`, id),
		"duplicate":     fmt.Sprintf(`{"template":"debian","fw_id":"junk","fw_id":%q}`, id),
		"two spellings": fmt.Sprintf(`{"template":"debian","fW_iD":%q,"fw_id":%q}`, id, id),
	}
}

// TestKeepFirewallID_StripsByTheDecoderNotTheSpelling (D1 review I-3): the
// identity is removed wherever a decoder would read it, whatever the key's
// spelling, and kept members survive. A key no decoder reads (a dotless i, a
// Kelvin sign) is not an identity and is left alone.
//
// Mutation: strip only the exact canonical key — every variant but the
// canonical and duplicate goes red.
func TestKeepFirewallID_StripsByTheDecoderNotTheSpelling(t *testing.T) {
	keep := tgID(9)
	for kind, variants := range map[string]map[string]string{
		TagMemberVM: vmIDVariants(tgID(1)),
		TagMemberCT: ctIDVariants(tgID(1)),
	} {
		for name, in := range variants {
			for _, want := range []string{"", keep} {
				out, err := keepFirewallID(kind, in, want)
				if err != nil {
					t.Fatalf("%s %s: %v", kind, name, err)
				}
				assertIdentity(t, kind+" "+name, kind, out, want)
				var m map[string]json.RawMessage
				if json.Unmarshal([]byte(out), &m) != nil || (m["cpu"] == nil && m["template"] == nil) {
					t.Errorf("%s %s: kept members lost: %s", kind, name, out)
				}
			}
		}
	}
	// Not an identity to any decoder: untouched, byte for byte.
	for kind, in := range map[string]string{
		TagMemberVM: `{"cpu":2,"firewall_ıd":"x","Kfirewall_id":"y","firewall id":"z"}`,
		TagMemberCT: `{"template":"debian","fw_ıd":"x","Kfw_id":"y"}`,
	} {
		assertIdentity(t, kind+" lookalikes", kind, in, "")
		if out, err := keepFirewallID(kind, in, ""); err != nil || out != in {
			t.Errorf("%s lookalikes rewritten: %q (%v)", kind, out, err)
		}
	}
	// Already holding exactly keep: byte for byte (no spurious generation bump).
	in := fmt.Sprintf(`{"cpu":2,  "firewall_id":%q}`, keep)
	if out, _ := keepFirewallID(TagMemberVM, in, keep); out != in {
		t.Errorf("canonical spec rewritten: %q", out)
	}
	// Not a JSON object: nothing reads an identity from it, and none can be kept in it.
	if out, err := keepFirewallID(TagMemberVM, "not json", ""); err != nil || out != "not json" {
		t.Errorf("non-object without identity: %q %v", out, err)
	}
	if _, err := keepFirewallID(TagMemberVM, "[1]", keep); !errors.Is(err, errFirewallIDSpec) {
		t.Errorf("non-object keeping an identity: %v, want errFirewallIDSpec", err)
	}
	if _, err := keepFirewallID(TagMemberVM, "{}", "not-an-id"); err == nil {
		t.Error("an invalid identity was kept")
	}
	if out, _ := keepFirewallID(TagMemberCT, "", keep); firewallIDOf(TagMemberCT, out) != keep {
		t.Errorf("empty create spec keeping %s: %q", keep, out)
	}
}

// TestFirewallIDWriters_InsertsStripUnlessCarried: every row-INSERT for a new
// workload stores no identity, whatever spelling the incoming spec uses, and
// keeps exactly the carried one when the caller passes a token.
func TestFirewallIDWriters_InsertsStripUnlessCarried(t *testing.T) {
	ctx := context.Background()
	carried := tgID(7)
	vmCarry := CarryFirewallID(TagMemberVM, fmt.Sprintf(`{"firewall_id":%q}`, carried))
	ctCarry := CarryFirewallID(TagMemberCT, fmt.Sprintf(`{"fw_id":%q}`, carried))

	vmWriters := map[string]func(c *Client, vm VMRecord) error{
		"InsertVM": func(c *Client, vm VMRecord) error { return InsertVM(ctx, c, vm, nil, nil) },
		"InsertVMWithHardware": func(c *Client, vm VMRecord) error {
			return InsertVMWithHardware(ctx, c, vm, nil, nil, nil, nil, true)
		},
		"BeginVMCreateOperation+Commit": func(c *Client, vm VMRecord) error {
			op := createOp("op-"+vm.Name, "vm", vm.Name, "hash", "", 3)
			vm.OwnerEpoch, vm.State, vm.Project = 3, "creating", "p1"
			if applied, err := c.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
				return fmt.Errorf("begin: applied=%v err=%w", applied, err)
			}
			if applied, err := c.CommitVMCreateOperation(ctx, op.ID, 3, vm, nil, nil, nil, nil); err != nil || !applied {
				return fmt.Errorf("commit: applied=%v err=%w", applied, err)
			}
			return nil
		},
	}
	for wname, write := range vmWriters {
		for vname, spec := range vmIDVariants(tgID(1)) {
			for _, carry := range []bool{false, true} {
				c := testClient(t)
				vm := VMRecord{Name: "vm1", HostName: "h1", Spec: spec, State: "stopped"}
				want := ""
				if carry {
					vm.FirewallCarry, want = vmCarry, carried
				}
				if err := write(c, vm); err != nil {
					t.Fatalf("%s %s carry=%v: %v", wname, vname, carry, err)
				}
				assertIdentity(t, fmt.Sprintf("%s %s carry=%v", wname, vname, carry), TagMemberVM, storedVMSpec(t, c, "vm1"), want)
			}
		}
	}

	ctWriters := map[string]func(c *Client, ct ContainerRecord) error{
		"CreateContainerAtomic": func(c *Client, ct ContainerRecord) error { return CreateContainerAtomic(ctx, c, ct, nil) },
		"UpsertContainer (no row)": func(c *Client, ct ContainerRecord) error {
			ct.FirewallCarry = FirewallIDCarry{} // an upsert takes no token: it keeps the live row's
			return UpsertContainer(ctx, c, ct)
		},
		"BeginContainerCreateOperation+Commit": func(c *Client, ct ContainerRecord) error {
			op := createOp("op-"+ct.Name, "container", ct.Name, "hash", "", 3)
			ct.OwnerEpoch, ct.State, ct.Project = 3, "creating", "p1"
			if applied, err := c.BeginContainerCreateOperation(ctx, op, ct); err != nil || !applied {
				return fmt.Errorf("begin: applied=%v err=%w", applied, err)
			}
			if applied, err := c.CommitContainerCreateOperation(ctx, op.ID, 3, ct, nil); err != nil || !applied {
				return fmt.Errorf("commit: applied=%v err=%w", applied, err)
			}
			return nil
		},
	}
	for wname, write := range ctWriters {
		for vname, cs := range ctIDVariants(tgID(1)) {
			for _, carry := range []bool{false, true} {
				if carry && strings.HasPrefix(wname, "UpsertContainer") {
					continue
				}
				c := testClient(t)
				ct := ContainerRecord{HostName: "h1", Name: "ct1", State: "running", Image: "alpine", CreateSpec: cs}
				want := ""
				if carry {
					ct.FirewallCarry, want = ctCarry, carried
				}
				if err := write(c, ct); err != nil {
					t.Fatalf("%s %s carry=%v: %v", wname, vname, carry, err)
				}
				assertIdentity(t, fmt.Sprintf("%s %s carry=%v", wname, vname, carry), TagMemberCT, storedCreateSpec(t, c, "h1", "ct1"), want)
			}
		}
	}

	// A token for the other kind carries nothing.
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm2", HostName: "h1", Spec: `{}`, FirewallCarry: ctCarry}, nil, nil); err != nil {
		t.Fatal(err)
	}
	assertIdentity(t, "container token on a VM", TagMemberVM, storedVMSpec(t, c, "vm2"), "")
}

// TestFirewallIDWriters_UpdatesKeepTheCurrentValue: the mutate, operation
// begin, network rename, rename and upsert writers store the current row's
// identity, whatever the new value says — they can neither set, change nor drop
// one.
func TestFirewallIDWriters_UpdatesKeepTheCurrentValue(t *testing.T) {
	ctx := context.Background()
	cur, other := tgID(1), tgID(2)
	withID := func(id string) string { return fmt.Sprintf(`{"cpu":4,"firewall_id":%q}`, id) }

	t.Run("MutateDesiredSpec", func(t *testing.T) {
		for _, tc := range []struct{ stored, next, want string }{
			{withID(cur), withID(other), cur},
			{withID(cur), `{"cpu":4}`, cur},
			{withID(cur), fmt.Sprintf(`{"cpu":4,"FIREWALL_ID":%q}`, other), cur},
			{`{"cpu":2}`, withID(other), ""},
			{`{"cpu":2}`, fmt.Sprintf(`{"cpu":4,"firewallId":%q}`, other), ""},
		} {
			c := testClient(t)
			rawVM(t, c, "vm1", tc.stored)
			if applied, _, err := MutateDesiredSpec(ctx, c, "vm1", func(string) (string, error) { return tc.next, nil }); err != nil || !applied {
				t.Fatalf("MutateDesiredSpec: applied=%v err=%v", applied, err)
			}
			assertIdentity(t, "MutateDesiredSpec "+tc.next, TagMemberVM, storedVMSpec(t, c, "vm1"), tc.want)
		}
	})

	t.Run("BeginVMOperation", func(t *testing.T) {
		for _, tc := range []struct{ stored, next, want string }{
			{withID(cur), fmt.Sprintf(`{"cpu":8,"firewall_id":%q}`, other), cur},
			{withID(cur), `{"cpu":8}`, cur},
			{`{"cpu":2}`, withID(other), ""},
		} {
			c := testClient(t)
			rawVM(t, c, "vm1", tc.stored)
			op := OperationRecord{ID: "op1", Method: "UpdateVM", Principal: "alice", ResourceKind: "vm", ResourceID: "vm1"}
			if applied, err := c.BeginVMOperation(ctx, op, tc.next, 0, 0); err != nil || !applied {
				t.Fatalf("BeginVMOperation: applied=%v err=%v", applied, err)
			}
			got := storedVMSpec(t, c, "vm1")
			if !strings.Contains(got, `"cpu":8`) && !strings.Contains(got, `"cpu":4`) || got == tc.stored {
				t.Fatalf("operation begin did not write its spec: %s", got)
			}
			assertIdentity(t, "BeginVMOperation "+tc.next, TagMemberVM, got, tc.want)
		}
	})

	t.Run("network rename", func(t *testing.T) {
		c := testClient(t)
		// A row a build before D2a stored with a second spelling: the rewrite
		// keeps the identity the row holds and drops the other.
		rawVM(t, c, "vm1", fmt.Sprintf(`{"network":[{"name":"web"}],"firewall_id":%q,"FIREWALL_ID":%q}`, cur, other))
		if err := migrateVMSpecNetworkNames(ctx, c, map[string]string{"web": "s_web"}, map[string]bool{"s_web": true}); err != nil {
			t.Fatal(err)
		}
		got := storedVMSpec(t, c, "vm1")
		if !strings.Contains(got, `"s_web"`) {
			t.Fatalf("rename not applied: %s", got)
		}
		assertIdentity(t, "network rename", TagMemberVM, got, cur)
	})

	t.Run("RenameVM", func(t *testing.T) {
		c := testClient(t)
		rawVM(t, c, "vm1", fmt.Sprintf(`{"name":"vm1","firewall_id":%q,"Firewall_Id":%q}`, cur, other))
		if err := RenameVM(ctx, c, "vm1", "vm9"); err != nil {
			t.Fatal(err)
		}
		assertIdentity(t, "RenameVM", TagMemberVM, storedVMSpec(t, c, "vm9"), cur)
	})

	t.Run("UpsertContainer", func(t *testing.T) {
		for _, tc := range []struct{ next, want string }{
			{fmt.Sprintf(`{"template":"alpine","fw_id":%q}`, other), cur},
			{fmt.Sprintf(`{"template":"alpine","FW_ID":%q}`, other), cur},
			{`{"template":"alpine"}`, cur},
			{"", cur}, // the statement keeps the stored create_spec
		} {
			c := testClient(t)
			rawContainer(t, c, "h1", "ct1", fmt.Sprintf(`{"template":"debian","fw_id":%q}`, cur))
			if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h1", Name: "ct1", State: "running", Image: "alpine", CreateSpec: tc.next}); err != nil {
				t.Fatal(err)
			}
			assertIdentity(t, "UpsertContainer "+tc.next, TagMemberCT, storedCreateSpec(t, c, "h1", "ct1"), tc.want)
		}
	})

	t.Run("UpsertContainer over a tombstone", func(t *testing.T) {
		// The statement's conflict arm revives the tombstone and keeps its
		// create_spec when the new one is empty: the revived row must not
		// carry the deleted container's identity.
		c := testClient(t)
		rawContainer(t, c, "h1", "ct1", fmt.Sprintf(`{"template":"debian","fw_id":%q}`, cur))
		mustExec(t, c, `UPDATE containers SET deleted_at = 'gone' WHERE host_name = 'h1' AND name = 'ct1'`)
		if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h1", Name: "ct1", State: "running", Image: "alpine"}); err != nil {
			t.Fatal(err)
		}
		got := storedCreateSpec(t, c, "h1", "ct1")
		assertIdentity(t, "revived tombstone", TagMemberCT, got, "")
		if !strings.Contains(got, `"debian"`) {
			t.Errorf("the stored create spec was not kept: %q", got)
		}
	})
}

// TestFirewallIDWriters_CarryInsertsKeepTheSource: the container re-key (both
// envelopes), the relocation (both shapes) and a new placement store the
// source row's identity; ReplaceVM stores the replacement VM's own, never the
// replaced VM's.
func TestFirewallIDWriters_CarryInsertsKeepTheSource(t *testing.T) {
	ctx := context.Background()
	id := tgID(5)
	sourceSpec := fmt.Sprintf(`{"template":"debian","fw_id":%q}`, id)

	t.Run("RekeyContainerOwner", func(t *testing.T) {
		c := testClient(t)
		if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h1", Name: "ct1", State: "running", Image: "alpine", Project: "p1"}); err != nil {
			t.Fatal(err)
		}
		mustExec(t, c, `UPDATE containers SET create_spec = ? WHERE host_name = 'h1' AND name = 'ct1'`, sourceSpec)
		src, err := GetContainer(ctx, c, "h1", "ct1")
		if err != nil || src == nil {
			t.Fatalf("source: %+v %v", src, err)
		}
		if applied, err := RekeyContainerOwner(ctx, c, *src, "h2"); err != nil || !applied {
			t.Fatalf("rekey: applied=%v err=%v", applied, err)
		}
		assertIdentity(t, "legacy rekey", TagMemberCT, storedCreateSpec(t, c, "h2", "ct1"), id)
	})

	t.Run("RekeyContainerOwnerGuarded", func(t *testing.T) {
		c := testClient(t)
		op := createOp("op-rk", "container", "ct1", "hash", "", 3)
		rec := ContainerRecord{HostName: "h1", Name: "ct1", Image: "alpine", Project: "p1", OwnerEpoch: 3, SpecGeneration: 5,
			CreateSpec: sourceSpec, FirewallCarry: CarryFirewallID(TagMemberCT, sourceSpec)}
		if applied, err := c.BeginContainerCreateOperation(ctx, op, rec); err != nil || !applied {
			t.Fatalf("begin: applied=%v err=%v", applied, err)
		}
		if applied, err := c.CommitContainerCreateOperation(ctx, op.ID, 3, rec, nil); err != nil || !applied {
			t.Fatalf("commit: applied=%v err=%v", applied, err)
		}
		src, err := GetContainer(ctx, c, "h1", "ct1")
		if err != nil || src == nil {
			t.Fatalf("source: %+v %v", src, err)
		}
		if applied, err := RekeyContainerOwnerGuarded(ctx, c, *src, "h2"); err != nil || !applied {
			t.Fatalf("guarded rekey: applied=%v err=%v", applied, err)
		}
		assertIdentity(t, "guarded rekey", TagMemberCT, storedCreateSpec(t, c, "h2", "ct1"), id)
	})

	for _, lifecycle := range []bool{false, true} {
		t.Run(fmt.Sprintf("RelocateContainerWithToken lifecycle=%v", lifecycle), func(t *testing.T) {
			c := newTestDB(t)
			seedRelocatableContainer(t, c, "host-a", "web", lifecycle)
			mustExec(t, c, `UPDATE containers SET create_spec = ? WHERE host_name = 'host-a' AND name = 'web'`, sourceSpec)
			if err := RelocateContainerWithToken(ctx, c, "host-a", "web", "host-b", "tok"); err != nil {
				t.Fatal(err)
			}
			got := storedCreateSpec(t, c, "host-b", "web")
			assertIdentity(t, "relocation", TagMemberCT, got, id)
			if PlacementOf(got) == "" {
				t.Errorf("relocation minted no placement: %s", got)
			}
		})
	}

	t.Run("WithNewPlacement", func(t *testing.T) {
		got, placement := WithNewPlacement(sourceSpec)
		assertIdentity(t, "WithNewPlacement", TagMemberCT, got, id)
		c := testClient(t)
		c.SetRepointReady(func(context.Context) bool { return true })
		rawContainer(t, c, "h1", "ct1", sourceSpec)
		next, applied, err := MintContainerPlacementSpec(ctx, c, "h1", "ct1", sourceSpec)
		if err != nil || !applied {
			t.Fatalf("MintContainerPlacementSpec: applied=%v err=%v", applied, err)
		}
		assertIdentity(t, "MintContainerPlacementSpec", TagMemberCT, storedCreateSpec(t, c, "h1", "ct1"), id)
		if PlacementOf(next) == "" || PlacementOf(next) == placement {
			t.Errorf("no new placement: %s", next)
		}
	})

	t.Run("ReplaceVM", func(t *testing.T) {
		c := testClientVMReplace(t)
		replaced, replacement := tgID(3), tgID(4)
		mustInsertVM(t, c, VMRecord{Name: "app", HostName: "h1", State: "stopped",
			Spec:          fmt.Sprintf(`{"name":"app","firewall_id":%q}`, replaced),
			FirewallCarry: CarryFirewallID(TagMemberVM, fmt.Sprintf(`{"firewall_id":%q}`, replaced))}, nil, nil)
		mustInsertVM(t, c, VMRecord{Name: "app-next", HostName: "h1", State: "stopped",
			Spec:          fmt.Sprintf(`{"name":"app-next","firewall_id":%q}`, replacement),
			FirewallCarry: CarryFirewallID(TagMemberVM, fmt.Sprintf(`{"firewall_id":%q}`, replacement))}, nil, nil)
		if err := DeleteVM(ctx, c, "app"); err != nil {
			t.Fatal(err)
		}
		if err := ReplaceVM(ctx, c, "app-next", "app", prepareCutover(t, c, "app", "app-next")); err != nil {
			t.Fatalf("ReplaceVM: %v", err)
		}
		assertIdentity(t, "ReplaceVM", TagMemberVM, storedVMSpec(t, c, "app"), replacement)
	})
}

// TestFirewallIDWriters_AStrippedCopyGrantsNothing: a new workload given a
// tagged workload's identity in its spec (a clone, a crafted request) is
// stored without it, so the victim's tags row never makes it a member — not
// even once the victim is deleted and its row was not cleared.
func TestFirewallIDWriters_AStrippedCopyGrantsNothing(t *testing.T) {
	ctx := context.Background()
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	victim := tgID(11)
	f.vm("victim", victim, "running")
	f.tags(TagMemberVM, victim, `{"tags":{"role":"web"}}`)
	if err := InsertVM(ctx, f.c, VMRecord{Name: "copy", HostName: "h1", State: "running",
		Spec: fmt.Sprintf(`{"name":"copy","firewall_id":%q}`, victim)}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := DeleteVM(ctx, f.c, "victim"); err != nil {
		t.Fatal(err)
	}
	if got := groupMembers(t, f.members(), "web"); len(got) != 0 {
		t.Fatalf("web members = %+v, want none", got)
	}
}

// groupMembers is the members of the group named name.
func groupMembers(t *testing.T, m *TagGroupMembership, name string) []TagGroupMember {
	t.Helper()
	for _, g := range m.Groups {
		if g.Group.Name == name {
			return g.Members
		}
	}
	t.Fatalf("no group %q in %+v", name, m.Groups)
	return nil
}

func mintGrant(t *testing.T) capabilities.FeatureGrant { return tagGroupGrant(t) }

// TestMintFirewallID: it takes the firewall_tag_groups grant and is listed as
// that feature's writer (m-2); it mints a well-formed identity only where the
// row has none, through the VM's spec writer (one generation bump) or the
// container's create_spec compare-and-set, and keeps one the row holds alone.
func TestMintFirewallID(t *testing.T) {
	ctx := context.Background()
	info, ok := capabilities.LookupFeature(capabilities.FeatureFirewallTagGroups)
	if !ok || !slices.Contains(info.Writers, "internal/corrosion.MintFirewallID") {
		t.Fatalf("firewall_tag_groups writers %v: MintFirewallID is not listed", info.Writers)
	}

	c := testClient(t)
	c.SetRepointReady(func(context.Context) bool { return true })
	rawVM(t, c, "vm1", `{"cpu":2}`)
	rawContainer(t, c, "h1", "ct1", `{"template":"debian"}`)
	for name, g := range map[string]capabilities.FeatureGrant{
		"no grant":          {},
		"another feature's": capabilities.GrantForTest(t, capabilities.FeatureFirewallLog),
	} {
		for _, kind := range []string{TagMemberVM, TagMemberCT} {
			if id, err := MintFirewallID(ctx, c, g, kind, "h1", map[string]string{TagMemberVM: "vm1", TagMemberCT: "ct1"}[kind]); !errors.Is(err, capabilities.ErrNoFeatureGrant) || id != "" {
				t.Errorf("%s %s: id=%q err=%v, want ErrNoFeatureGrant", name, kind, id, err)
			}
		}
	}
	assertIdentity(t, "refused VM mint", TagMemberVM, storedVMSpec(t, c, "vm1"), "")
	assertIdentity(t, "refused container mint", TagMemberCT, storedCreateSpec(t, c, "h1", "ct1"), "")

	vm, _ := GetVM(ctx, c, "vm1")
	id, err := MintFirewallID(ctx, c, mintGrant(t), TagMemberVM, "", "vm1")
	if err != nil || !ValidFirewallID(id) {
		t.Fatalf("VM mint: %q %v", id, err)
	}
	assertIdentity(t, "minted VM", TagMemberVM, storedVMSpec(t, c, "vm1"), id)
	after, _ := GetVM(ctx, c, "vm1")
	if after.SpecGeneration != vm.SpecGeneration+1 {
		t.Errorf("VM mint generation %d -> %d, want one bump", vm.SpecGeneration, after.SpecGeneration)
	}
	if again, err := MintFirewallID(ctx, c, mintGrant(t), TagMemberVM, "", "vm1"); err != nil || again != id {
		t.Errorf("second VM mint: %q %v, want the existing %q", again, err, id)
	}
	if again, _ := GetVM(ctx, c, "vm1"); again.SpecGeneration != after.SpecGeneration {
		t.Error("a mint of an existing identity wrote")
	}

	cid, err := MintFirewallID(ctx, c, mintGrant(t), TagMemberCT, "h1", "ct1")
	if err != nil || !ValidFirewallID(cid) || cid == id {
		t.Fatalf("container mint: %q %v", cid, err)
	}
	cs := storedCreateSpec(t, c, "h1", "ct1")
	assertIdentity(t, "minted container", TagMemberCT, cs, cid)
	if !strings.Contains(cs, `"debian"`) {
		t.Errorf("container mint lost the create spec: %s", cs)
	}
	if again, err := MintFirewallID(ctx, c, mintGrant(t), TagMemberCT, "h1", "ct1"); err != nil || again != cid {
		t.Errorf("second container mint: %q %v, want %q", again, err, cid)
	}

	// Refused: an operation holds the container; the container or VM is gone;
	// the latch has not formed.
	rawContainer(t, c, "h1", "busy", `{"template":"debian"}`)
	mustExec(t, c, `UPDATE containers SET active_operation_id = 'op' WHERE name = 'busy'`)
	for what, call := range map[string]func() (string, error){
		"busy container":    func() (string, error) { return MintFirewallID(ctx, c, mintGrant(t), TagMemberCT, "h1", "busy") },
		"missing container": func() (string, error) { return MintFirewallID(ctx, c, mintGrant(t), TagMemberCT, "h1", "nope") },
		"missing VM":        func() (string, error) { return MintFirewallID(ctx, c, mintGrant(t), TagMemberVM, "", "nope") },
	} {
		if id, err := call(); !errors.Is(err, ErrFirewallIDNotMinted) || id != "" {
			t.Errorf("%s: %q %v, want ErrFirewallIDNotMinted", what, id, err)
		}
	}
	assertIdentity(t, "busy container", TagMemberCT, storedCreateSpec(t, c, "h1", "busy"), "")
	mustExec(t, c, `UPDATE vms SET active_operation_id = 'op' WHERE name = 'vm1'`)
	rawVM(t, c, "vm2", `{}`)
	mustExec(t, c, `UPDATE vms SET active_operation_id = 'op' WHERE name = 'vm2'`)
	if id, err := MintFirewallID(ctx, c, mintGrant(t), TagMemberVM, "", "vm2"); !errors.Is(err, ErrFirewallIDNotMinted) || id != "" {
		t.Errorf("busy VM: %q %v, want ErrFirewallIDNotMinted", id, err)
	}
	rawContainer(t, c, "h1", "legacy", "")
	if id, err := MintFirewallID(ctx, c, mintGrant(t), TagMemberCT, "h1", "legacy"); !errors.Is(err, ErrFirewallIDNoCreateSpec) || id != "" {
		t.Errorf("container with no create spec: %q %v, want ErrFirewallIDNoCreateSpec", id, err)
	}
	if cs := storedCreateSpec(t, c, "h1", "legacy"); cs != "" {
		t.Errorf("container with no create spec now holds %q", cs)
	}
	c2 := testClient(t)
	rawContainer(t, c2, "h1", "ct1", `{"template":"debian"}`)
	if id, err := MintFirewallID(ctx, c2, mintGrant(t), TagMemberCT, "h1", "ct1"); !errors.Is(err, ErrFirewallIDNotMinted) || id != "" {
		t.Errorf("before the latch: %q %v, want ErrFirewallIDNotMinted", id, err)
	}
}

// TestMintFirewallID_CopiedIdentityChainGrantsNothing (D1 review I-2): an
// identity stored verbatim before the writers kept it — the victim's, copied
// into another workload's spec — must not let the copy inherit membership. The
// chain: the copy holds the victim's id, the victim is tagged, the victim is
// deleted and the clear of its tags row fails. Tagging the victim mints it a
// FRESH identity, because another row holds the one it has, so the copy never
// holds the tags row's id.
//
// Mutation: keep the existing identity without checking another row holds it
// — after the delete the copy is the sole holder of the tagged id, and a member.
func TestMintFirewallID_CopiedIdentityChainGrantsNothing(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{TagMemberVM, TagMemberCT} {
		t.Run(kind, func(t *testing.T) {
			f := newTagGroupFixture(t)
			f.c.SetRepointReady(func(context.Context) bool { return true })
			f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
			copied := tgID(21)
			host, victim, copyName := "", "victim", "copy"
			if kind == TagMemberVM {
				f.vm(victim, copied, "running")
				f.vmNIC("vm_nics", victim, "prod", "52:54:00:aa:00:01", "")
				f.lease("prod", "10.0.0.5", "52:54:00:aa:00:01", "vm", "", victim)
				f.vm(copyName, copied, "running")
				f.vmNIC("vm_nics", copyName, "prod", "52:54:00:aa:00:02", "")
				f.lease("prod", "10.0.0.6", "52:54:00:aa:00:02", "vm", "", copyName)
			} else {
				host = "h1"
				f.ct(host, victim, copied, "running")
				f.ctNIC(host, victim, "prod", "52:54:00:aa:00:01", "")
				f.lease("prod", "10.0.0.5", "52:54:00:aa:00:01", "ct", host, victim)
				f.ct("h2", copyName, copied, "running")
				f.ctNIC("h2", copyName, "prod", "52:54:00:aa:00:02", "")
				f.lease("prod", "10.0.0.6", "52:54:00:aa:00:02", "ct", "h2", copyName)
			}

			// tag set: mint (or reuse) the victim's identity, then write its row.
			id, err := MintFirewallID(ctx, f.c, mintGrant(t), kind, host, victim)
			if err != nil {
				t.Fatalf("mint: %v", err)
			}
			f.tags(kind, id, `{"tags":{"role":"web"}}`)
			if id == copied {
				t.Errorf("the victim kept the identity another row holds (%s)", copied)
			}
			if got := groupMembers(t, f.members(), "web"); len(got) != 1 || got[0].Name != victim {
				t.Errorf("before the delete, web members = %+v, want only the victim", got)
			}

			// The victim is deleted; the clear of its tags row fails (not called).
			if kind == TagMemberVM {
				err = DeleteVM(ctx, f.c, victim)
			} else {
				err = DeleteContainer(ctx, f.c, host, victim)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := groupMembers(t, f.members(), "web"); len(got) != 0 {
				t.Fatalf("after the delete, web members = %+v, want none: the copy inherited membership", got)
			}
		})
	}
}
