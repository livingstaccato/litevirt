package corrosion

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// The firewall-tags store (spec §4.3, plan D2c): one cluster_policies row per
// workload identity, firewall_tags/<kind>/<fw_id>, written only through
// SetFirewallTags with the firewall_tag_groups grant AND the sg.write authority
// the gRPC layer mints, and cleared only through ClearFirewallTags, which can
// write nothing but "".

func tagsAuthority(t *testing.T) FWTagAuthority { return FWTagAuthorityForTest(t) }

// SetFirewallTags refuses the zero authority and a missing (or wrong) grant,
// and writes nothing when it refuses.
//
// Mutations: accept the zero authority; skip the grant check — red.
func TestSetFirewallTags_RefusesWithoutAuthorityOrGrant(t *testing.T) {
	f := newTagGroupFixture(t)
	id := tgID(1)
	tags := map[string]string{"role": "web"}

	if err := SetFirewallTags(f.ctx, f.c, tagGroupGrant(t), FWTagAuthority{}, TagMemberVM, id, tags, "web", "", "alice"); !errors.Is(err, ErrNoFWTagAuthority) {
		t.Errorf("zero authority: err = %v, want ErrNoFWTagAuthority", err)
	}
	if err := SetFirewallTags(f.ctx, f.c, capabilities.FeatureGrant{}, tagsAuthority(t), TagMemberVM, id, tags, "web", "", "alice"); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Errorf("zero grant: err = %v, want ErrNoFeatureGrant", err)
	}
	wrong := capabilities.GrantForTest(t, capabilities.FeatureFirewallLog)
	if err := SetFirewallTags(f.ctx, f.c, wrong, tagsAuthority(t), TagMemberVM, id, tags, "web", "", "alice"); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Errorf("another feature's grant: err = %v, want ErrNoFeatureGrant", err)
	}
	if _, ok, err := ResolveFirewallTags(f.ctx, f.c, TagMemberVM, id); err != nil || ok {
		t.Fatalf("a refused write left a row: ok=%v err=%v", ok, err)
	}

	if err := SetFirewallTags(f.ctx, f.c, tagGroupGrant(t), tagsAuthority(t), TagMemberVM, id, tags, "web", "", "alice"); err != nil {
		t.Fatalf("authorised write: %v", err)
	}
	rec, ok, err := ResolveFirewallTags(f.ctx, f.c, TagMemberVM, id)
	if err != nil || !ok || !reflect.DeepEqual(rec.Tags, tags) || rec.Name != "web" || rec.SetBy != "alice" {
		t.Fatalf("after the write: %+v ok=%v err=%v", rec, ok, err)
	}
}

// The grammar: a key and a value are [a-z0-9][a-z0-9_.-]{0,62}, the identity
// is 32 lower-case hex, the kind is vm or ct. A refusal writes nothing.
func TestSetFirewallTags_Grammar(t *testing.T) {
	f := newTagGroupFixture(t)
	for name, tc := range map[string]struct {
		kind, id string
		tags     map[string]string
	}{
		"upper key":    {TagMemberVM, tgID(1), map[string]string{"Role": "web"}},
		"empty value":  {TagMemberVM, tgID(1), map[string]string{"role": ""}},
		"space value":  {TagMemberVM, tgID(1), map[string]string{"role": "a b"}},
		"long key":     {TagMemberVM, tgID(1), map[string]string{strings.Repeat("a", 64): "x"}},
		"bad identity": {TagMemberVM, "web", map[string]string{"role": "web"}},
		"upper id":     {TagMemberVM, strings.ToUpper(tgID(10)), map[string]string{"role": "web"}},
		"bad kind":     {"lxc", tgID(1), map[string]string{"role": "web"}},
	} {
		if err := SetFirewallTags(f.ctx, f.c, tagGroupGrant(t), tagsAuthority(t), tc.kind, tc.id, tc.tags, "w", "", "alice"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	rows, err := ListFirewallTagsRows(f.ctx, f.c)
	if err != nil || len(rows) != 0 {
		t.Fatalf("refused writes left rows: %+v %v", rows, err)
	}
}

// Round trip: the row holds the tags and, for display only, the workload's
// name and a container's host; an empty set stores "" (no tags).
func TestSetFirewallTags_RoundTripAndEmptyIsNone(t *testing.T) {
	f := newTagGroupFixture(t)
	id := tgID(2)
	want := map[string]string{"role": "web", "env": "prod"}
	if err := SetFirewallTags(f.ctx, f.c, tagGroupGrant(t), tagsAuthority(t), TagMemberCT, id, want, "cache", "node-2", "alice"); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := ResolveFirewallTags(f.ctx, f.c, TagMemberCT, id)
	if err != nil || !ok || !reflect.DeepEqual(rec.Tags, want) || rec.Name != "cache" || rec.Host != "node-2" ||
		rec.Kind != TagMemberCT || rec.FWID != id || rec.Unreadable {
		t.Fatalf("round trip: %+v ok=%v err=%v", rec, ok, err)
	}
	if err := SetFirewallTags(f.ctx, f.c, tagGroupGrant(t), tagsAuthority(t), TagMemberCT, id, nil, "cache", "node-2", "alice"); err != nil {
		t.Fatal(err)
	}
	if v := policyValue(t, f, FirewallTagsKeyPrefix+"ct/"+id); v != "" {
		t.Errorf("an empty set stored %q, want \"\"", v)
	}
	rec, ok, _ = ResolveFirewallTags(f.ctx, f.c, TagMemberCT, id)
	if !ok || len(rec.Tags) != 0 || rec.Unreadable {
		t.Errorf("after the empty set: %+v ok=%v", rec, ok)
	}
}

func policyValue(t *testing.T, f *tagGroupFixture, key string) string {
	t.Helper()
	rows, err := f.c.Query(f.ctx, `SELECT value FROM cluster_policies WHERE key = ?`, key)
	if err != nil || len(rows) != 1 {
		t.Fatalf("row %s: %v %v", key, rows, err)
	}
	return rows[0].String("value")
}

// Decoding is lenient (m-6): an unknown field is ignored; malformed JSON, a
// field of the wrong type, and a JSON null tag value are unreadable.
//
// Mutation: decode strictly (DisallowUnknownFields) — the unknown-field row
// reads unreadable: red.
func TestResolveFirewallTags_Lenient(t *testing.T) {
	f := newTagGroupFixture(t)
	for i, tc := range []struct {
		value      string
		unreadable bool
		tags       map[string]string
	}{
		{`{"tags":{"role":"web"},"name":"w","later":{"x":1}}`, false, map[string]string{"role": "web"}},
		{`{"tags":{"role":"web"`, true, nil},
		{`{"tags":["role"]}`, true, nil},
		{`{"tags":{"role":null}}`, true, nil},
		{`{"tags":{"role":"web"},"name":7}`, true, nil},
	} {
		id := tgID(100 + i)
		f.tags(TagMemberVM, id, tc.value)
		rec, ok, err := ResolveFirewallTags(f.ctx, f.c, TagMemberVM, id)
		if err != nil || !ok || rec.Unreadable != tc.unreadable || (!tc.unreadable && !reflect.DeepEqual(rec.Tags, tc.tags)) {
			t.Errorf("%s: %+v ok=%v err=%v, want unreadable=%v tags=%v", tc.value, rec, ok, err, tc.unreadable, tc.tags)
		}
	}
}

// ClearFirewallTags writes "" and nothing else: its signature takes no value,
// and it needs the grant (it is a writer of the feature's data) but no
// authority.
//
// Mutations: let ClearFirewallTags take a value (the signature check is red);
// skip its grant check — red.
func TestClearFirewallTags_OnlyEverWritesEmpty(t *testing.T) {
	want := reflect.TypeOf(func(context.Context, *Client, capabilities.FeatureGrant, string, string) error { return nil })
	if got := reflect.TypeOf(ClearFirewallTags); got != want {
		t.Fatalf("ClearFirewallTags is %v, want %v: a clear takes no value to write", got, want)
	}
	f := newTagGroupFixture(t)
	id := tgID(3)
	if err := SetFirewallTags(f.ctx, f.c, tagGroupGrant(t), tagsAuthority(t), TagMemberVM, id, map[string]string{"role": "web"}, "web", "", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := ClearFirewallTags(f.ctx, f.c, capabilities.FeatureGrant{}, TagMemberVM, id); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Errorf("a clear without the grant: %v", err)
	}
	if err := ClearFirewallTags(f.ctx, f.c, tagGroupGrant(t), TagMemberVM, id); err != nil {
		t.Fatal(err)
	}
	if v := policyValue(t, f, FirewallTagsKeyPrefix+"vm/"+id); v != "" {
		t.Errorf("after a clear the row holds %q", v)
	}
	// A clear of a row that never existed writes "" (unconditional: the
	// delete does not look at the local replica first).
	other := tgID(4)
	if err := ClearFirewallTags(f.ctx, f.c, tagGroupGrant(t), TagMemberCT, other); err != nil {
		t.Fatal(err)
	}
	if v := policyValue(t, f, FirewallTagsKeyPrefix+"ct/"+other); v != "" {
		t.Errorf("a clear of an absent row stored %q", v)
	}
}

// Both writers stay behind the cluster-policy gate.
func TestFirewallTagsWriters_RefuseWithTheGateClosed(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if err := SetFirewallTags(ctx, c, tagGroupGrant(t), tagsAuthority(t), TagMemberVM, tgID(1), map[string]string{"a": "b"}, "w", "", "x"); !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Errorf("set with the gate closed: %v", err)
	}
	if err := ClearFirewallTags(ctx, c, tagGroupGrant(t), TagMemberVM, tgID(1)); !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Errorf("clear with the gate closed: %v", err)
	}
}

// A second claim of the authority minter panics: only the gRPC layer's one
// claim (internal/grpcapi, after sg.write) can mint an authority.
//
// Mutation: drop the claimed flag — no panic: red.
func TestFWTagAuthorityMinter_SecondClaimPanics(t *testing.T) {
	func() {
		defer func() { _ = recover() }() // already claimed by an earlier run of this test
		ClaimFWTagAuthorityMinter()
	}()
	defer func() {
		if recover() == nil {
			t.Fatal("a second claim of the firewall-tags authority minter did not panic")
		}
	}()
	ClaimFWTagAuthorityMinter()
}

// A row whose fw_id no live workload carries grants nothing: membership is
// decided by the identity alone.
func TestSetFirewallTags_ARowNoWorkloadCarriesGrantsNothing(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	f.vm("live", tgID(7), "running")
	if err := SetFirewallTags(f.ctx, f.c, tagGroupGrant(t), tagsAuthority(t), TagMemberVM, tgID(8), map[string]string{"role": "web"}, "live", "", "alice"); err != nil {
		t.Fatal(err)
	}
	if got := f.members().viewFor(t, "web").memberNames(); len(got) != 0 {
		t.Fatalf("an orphan row (named for a live VM) made members %v", got)
	}
}

// The tags rows are firewall_tag_groups data: both writers are listed under
// the feature (release_guard_test checks each takes and Checks the grant).
func TestFirewallTagsWriters_ListedAsFeatureWriters(t *testing.T) {
	info, _ := capabilities.LookupFeature(capabilities.FeatureFirewallTagGroups)
	for _, w := range []string{"internal/corrosion.SetFirewallTags", "internal/corrosion.ClearFirewallTags"} {
		if !slices.Contains(info.Writers, w) {
			t.Errorf("firewall_tag_groups writers %v: %s is not listed", info.Writers, w)
		}
	}
}

// SetClusterPolicy refuses the firewall-tags and tag-group prefixes at
// runtime (m-1): those rows have their own writers.
//
// Mutation: drop the runtime prefix refusal — red.
func TestSetClusterPolicy_RefusesTheFirewallTagPrefixes(t *testing.T) {
	f := newTagGroupFixture(t)
	for _, key := range []string{FirewallTagsKeyPrefix + "vm/" + tgID(1), FirewallTagGroupKeyPrefix + "web"} {
		if err := SetClusterPolicy(f.ctx, f.c, key, `{"tags":{"role":"web"}}`, "x"); !errors.Is(err, ErrReservedClusterPolicyKey) {
			t.Errorf("SetClusterPolicy(%s): %v, want ErrReservedClusterPolicyKey", key, err)
		}
		rows, _ := f.c.Query(f.ctx, `SELECT 1 AS one FROM cluster_policies WHERE key = ?`, key)
		if len(rows) != 0 {
			t.Errorf("SetClusterPolicy(%s) wrote the row", key)
		}
	}
	if err := SetClusterPolicy(f.ctx, f.c, TrunkVLANsRecordedKey, "{}", "x"); err != nil {
		t.Errorf("an ordinary key: %v", err)
	}
}

// Every writer of a caller-chosen cluster_policies key refuses the reserved
// prefixes, not only SetClusterPolicy (D2c review I-1): SetPoolRecord and
// WriteNetworkVLANsCAS too, writing nothing.
//
// Mutation: drop the refusal from either writer — red.
func TestReservedPrefixesRefusedByEveryArbitraryKeyWriter(t *testing.T) {
	f := newTagGroupFixture(t)
	for _, key := range []string{FirewallTagsKeyPrefix + "vm/" + tgID(1), FirewallTagGroupKeyPrefix + "web"} {
		if err := SetPoolRecord(f.ctx, f.c, key, `{"tags":{"role":"web"}}`, "x"); !errors.Is(err, ErrReservedClusterPolicyKey) {
			t.Errorf("SetPoolRecord(%s): %v, want ErrReservedClusterPolicyKey", key, err)
		}
		applied, err := WriteNetworkVLANsCAS(f.ctx, f.c, VLANSnapshot{Keys: map[string]PolicyValue{}}, nil,
			map[string]string{key: `{"tags":{"role":"web"}}`}, "x")
		if applied || !errors.Is(err, ErrReservedClusterPolicyKey) {
			t.Errorf("WriteNetworkVLANsCAS(%s): applied=%v err=%v, want ErrReservedClusterPolicyKey", key, applied, err)
		}
		rows, _ := f.c.Query(f.ctx, `SELECT 1 AS one FROM cluster_policies WHERE key = ?`, key)
		if len(rows) != 0 {
			t.Errorf("%s was written", key)
		}
	}
	if err := SetPoolRecord(f.ctx, f.c, PoolUploadKeyPrefix+"x", "{}", "x"); err != nil {
		t.Errorf("an ordinary pool record: %v", err)
	}
}

// A tags row is bounded (D2c review M-5): at most MaxFirewallTags tags; the
// display name and host are each at most 253 bytes of printable,
// non-space characters (a name is required).
//
// Mutations: drop the tag cap — red; drop the name check — red.
func TestSetFirewallTags_BoundsTheRow(t *testing.T) {
	f := newTagGroupFixture(t)
	many := map[string]string{}
	for i := 0; i <= MaxFirewallTags; i++ {
		many[fmt.Sprintf("k%d", i)] = "v"
	}
	if err := SetFirewallTags(f.ctx, f.c, tagGroupGrant(t), tagsAuthority(t), TagMemberVM, tgID(1), many, "w", "", "x"); err == nil {
		t.Errorf("%d tags accepted", len(many))
	}
	delete(many, "k0")
	if err := SetFirewallTags(f.ctx, f.c, tagGroupGrant(t), tagsAuthority(t), TagMemberVM, tgID(1), many, "w", "", "x"); err != nil {
		t.Errorf("%d tags refused: %v", len(many), err)
	}
	for what, nh := range map[string][2]string{
		"no name":    {"", ""},
		"long name":  {strings.Repeat("a", 254), ""},
		"name space": {"a b", ""},
		"name ctl":   {"a\x01", ""},
		"long host":  {"w", strings.Repeat("h", 254)},
		"host space": {"w", "h h"},
	} {
		if err := SetFirewallTags(f.ctx, f.c, tagGroupGrant(t), tagsAuthority(t), TagMemberCT, tgID(2), map[string]string{"a": "b"}, nh[0], nh[1], "x"); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
}

// The member query and the store's listing agree: a key whose identity is
// not well formed is dropped by both (D2c review M-7).
//
// Mutation: keep malformed identities in the member query's read — red.
func TestReadFirewallTagsRows_DropsAMalformedIdentity(t *testing.T) {
	f := newTagGroupFixture(t)
	f.tags(TagMemberVM, "not-an-id", `{"tags":{"role":"web"}}`)
	f.tags(TagMemberVM, tgID(1), `{"tags":{"role":"web"}}`)
	rows, err := readFirewallTagsRows(f.ctx, f.c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rows["vm/not-an-id"]; ok || len(rows) != 1 {
		t.Fatalf("member read kept %v", rows)
	}
}
