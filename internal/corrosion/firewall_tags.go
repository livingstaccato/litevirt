package corrosion

// The firewall-tags store (firewall extras spec §4.3): a workload's firewall
// tags are one cluster_policies row keyed by its firewall identity,
// firewall_tags/vm/<fw_id> or firewall_tags/ct/<fw_id>, holding
// {"tags":{...},"name":"<workload>","host":"<container host>"} ("" for no
// tags). name and host are for display only and never matched. No spec or
// container write reads or writes the row, so a lagging replica, a backup's
// old spec or a copy cannot carry a stale set back.
//
// Two writers, through the table's one upsert (no new statement shape):
//
//   - SetFirewallTags, which needs the firewall_tag_groups grant AND an
//     FWTagAuthority, which only the gRPC layer mints, after it has checked
//     sg.write at the cluster root (grpcapi.Server.fwTagAuthority);
//   - ClearFirewallTags, which needs the grant only and can write nothing
//     but "": a delete's hygiene and the orphan sweep.
//
// firewall_tags_guard_test.go fails on any other non-test code writing a
// firewall_tags/ or firewall_tag_group/ key, and SetClusterPolicy refuses
// both prefixes at runtime.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// FWTagAuthority is the proof that the caller of SetFirewallTags holds
// sg.write at the cluster root. The zero value authorises nothing. Only the
// function ClaimFWTagAuthorityMinter hands out mints one; the gRPC layer
// claims it once and mints only after its sg.write check.
type FWTagAuthority struct{ minted bool }

// ErrNoFWTagAuthority refuses a firewall-tags write made without an
// FWTagAuthority.
var ErrNoFWTagAuthority = errors.New("firewall tags write without the sg.write authority")

// ErrReservedClusterPolicyKey refuses a SetClusterPolicy of a key that only
// the firewall-tags store and the tag-group writer write.
var ErrReservedClusterPolicyKey = errors.New("this cluster policy key has its own writer")

var fwTagAuthorityMinterClaimed atomic.Bool

// ClaimFWTagAuthorityMinter hands out the only function that mints an
// FWTagAuthority. internal/grpcapi claims it in a package variable; a second
// claim panics, so no other package can mint one without the binary failing
// at start, and firewall_tags_guard_test.go fails the build on any other
// claim.
func ClaimFWTagAuthorityMinter() func() FWTagAuthority {
	if !fwTagAuthorityMinterClaimed.CompareAndSwap(false, true) {
		panic("corrosion: the firewall-tags authority minter is already claimed (by internal/grpcapi); " +
			"a firewall-tags write must go through its sg.write check")
	}
	return newFWTagAuthority
}

// newFWTagAuthority is the only builder of a non-zero FWTagAuthority (the
// authority guard flags any other non-zero literal).
func newFWTagAuthority() FWTagAuthority { return FWTagAuthority{minted: true} }

// FWTagAuthorityForTest mints an authority for a test. Test code only: the
// authority guard fails the build on any non-test caller.
func FWTagAuthorityForTest(t TestingT) FWTagAuthority {
	t.Helper()
	return newFWTagAuthority()
}

// refuseReservedPolicyKey refuses a cluster_policies key under
// firewall_tags/ or firewall_tag_group/ for every writer that takes a key
// its caller chooses (SetClusterPolicy, SetPoolRecord, WriteNetworkVLANsCAS):
// those rows have their own writers, which check the sg.write authority, the
// grant and the grammar.
func refuseReservedPolicyKey(key string) error {
	if strings.HasPrefix(key, FirewallTagsKeyPrefix) || strings.HasPrefix(key, FirewallTagGroupKeyPrefix) {
		return fmt.Errorf("%w: %s", ErrReservedClusterPolicyKey, key)
	}
	return nil
}

// MaxFirewallTags is the most tags one workload may hold, and
// maxFirewallTagsLabel the longest display name or host a tags row keeps:
// together they bound every replica's row.
const (
	MaxFirewallTags      = 64
	maxFirewallTagsLabel = 253
)

// validTagsLabel reports whether s is a display name or host a tags row may
// keep: at most maxFirewallTagsLabel bytes of printable, non-space ASCII.
func validTagsLabel(s string) bool {
	if len(s) > maxFirewallTagsLabel {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// FirewallTagsRecord is one firewall-tags row as this replica holds it.
type FirewallTagsRecord struct {
	Kind string // TagMemberVM or TagMemberCT
	FWID string
	// Tags is empty for a removed row ("") and for an unreadable one.
	Tags map[string]string
	// Name and Host are the workload's name, and a container's host, when the
	// tags were last set: for display only.
	Name, Host       string
	SetBy, UpdatedAt string
	// Unreadable: malformed JSON or a field of the wrong type (a JSON null
	// tag value included). An unknown field is ignored.
	Unreadable bool
}

// storedFirewallTags is a tags row's value as written.
type storedFirewallTags struct {
	Tags map[string]string `json:"tags"`
	Name string            `json:"name,omitempty"`
	Host string            `json:"host,omitempty"`
}

func firewallTagsKey(kind, fwID string) (string, error) {
	if kind != TagMemberVM && kind != TagMemberCT {
		return "", fmt.Errorf("firewall tags: unknown workload kind %q", kind)
	}
	if !ValidFirewallID(fwID) {
		return "", fmt.Errorf("firewall tags: %q is not a firewall identity", fwID)
	}
	return FirewallTagsKeyPrefix + kind + "/" + fwID, nil
}

// SetFirewallTags replaces the firewall tags of the workload whose identity is
// fwID (kind TagMemberVM or TagMemberCT) with tags; none stores "". name and
// host (a container's) are kept for display. It takes the firewall_tag_groups
// grant and the sg.write authority, refuses a key or value outside
// [a-z0-9][a-z0-9_.-]{0,62}, and refuses with ErrClusterPolicyGateClosed
// until this node may write cluster_policies. The caller owns minting the
// identity, merging, audit and re-rendering.
func SetFirewallTags(ctx context.Context, c *Client, g capabilities.FeatureGrant, auth FWTagAuthority,
	kind, fwID string, tags map[string]string, name, host, setBy string) error {
	if err := g.Check(capabilities.FeatureFirewallTagGroups); err != nil {
		return err
	}
	if !auth.minted {
		return ErrNoFWTagAuthority
	}
	key, err := firewallTagsKey(kind, fwID)
	if err != nil {
		return err
	}
	if len(tags) > MaxFirewallTags {
		return fmt.Errorf("%d firewall tags: a workload holds at most %d", len(tags), MaxFirewallTags)
	}
	if name == "" || !validTagsLabel(name) || !validTagsLabel(host) {
		return fmt.Errorf("firewall tags of %q on %q: the name (required) and the host are each at most %d printable, non-space characters",
			name, host, maxFirewallTagsLabel)
	}
	for k, v := range tags {
		if !ValidFirewallTagWord(k) {
			return fmt.Errorf("firewall tag key %q: want [a-z0-9][a-z0-9_.-]{0,62}", k)
		}
		if !ValidFirewallTagWord(v) {
			return fmt.Errorf("firewall tag %s value %q: want [a-z0-9][a-z0-9_.-]{0,62}", k, v)
		}
	}
	value := ""
	if len(tags) > 0 {
		b, err := json.Marshal(storedFirewallTags{Tags: tags, Name: name, Host: host})
		if err != nil {
			return err
		}
		value = string(b)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, key, value, setBy, c.NowTS())
}

// ClearFirewallTags writes "" (no tags) to the tags row of identity fwID,
// whether or not this replica holds one: a delete clears unconditionally, and
// the orphan sweep clears what it found. It can write nothing else. It takes
// the firewall_tag_groups grant (the row is the feature's data) but no
// authority.
func ClearFirewallTags(ctx context.Context, c *Client, g capabilities.FeatureGrant, kind, fwID string) error {
	if err := g.Check(capabilities.FeatureFirewallTagGroups); err != nil {
		return err
	}
	key, err := firewallTagsKey(kind, fwID)
	if err != nil {
		return err
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, key, "", "litevirt", c.NowTS())
}

// decodeFirewallTags reads one row's value, leniently: an unknown field is
// ignored; malformed JSON or a field of the wrong type is unreadable.
func decodeFirewallTags(kind, fwID, value, setBy, updatedAt string) FirewallTagsRecord {
	rec := FirewallTagsRecord{Kind: kind, FWID: fwID, SetBy: setBy, UpdatedAt: updatedAt}
	if value == "" {
		return rec
	}
	var v struct {
		Tags map[string]*string `json:"tags"`
		Name string             `json:"name"`
		Host string             `json:"host"`
	}
	if json.Unmarshal([]byte(value), &v) != nil {
		rec.Unreadable = true
		return rec
	}
	tags, ok := nonNullStrings(v.Tags)
	if !ok {
		rec.Unreadable = true
		return rec
	}
	rec.Tags, rec.Name, rec.Host = tags, v.Name, v.Host
	return rec
}

// ResolveFirewallTags returns the tags row of identity fwID; ok is false when
// this replica holds none.
func ResolveFirewallTags(ctx context.Context, c *Client, kind, fwID string) (FirewallTagsRecord, bool, error) {
	key, err := firewallTagsKey(kind, fwID)
	if err != nil {
		return FirewallTagsRecord{}, false, err
	}
	rows, err := c.Query(ctx,
		`SELECT value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, key)
	if err != nil || len(rows) == 0 {
		return FirewallTagsRecord{}, false, err
	}
	r := rows[0]
	return decodeFirewallTags(kind, fwID, r.String("value"), r.String("set_by"), r.String("updated_at")), true, nil
}

// ListFirewallTagsRows returns every tags row this replica holds, removed
// ones ("") included, sorted by kind and identity. A key that names no kind
// or no well-formed identity is left out: it matches no workload.
func ListFirewallTagsRows(ctx context.Context, c *Client) ([]FirewallTagsRecord, error) {
	lo, hi := keyRange(FirewallTagsKeyPrefix)
	rows, err := c.Query(ctx,
		`SELECT key, value, set_by, updated_at FROM cluster_policies
		 WHERE key >= ? AND key < ? AND deleted_at IS NULL ORDER BY key`, lo, hi)
	if err != nil {
		return nil, err
	}
	var out []FirewallTagsRecord
	for _, r := range rows {
		kind, id, ok := strings.Cut(strings.TrimPrefix(r.String("key"), FirewallTagsKeyPrefix), "/")
		if !ok || (kind != TagMemberVM && kind != TagMemberCT) || !ValidFirewallID(id) {
			continue
		}
		out = append(out, decodeFirewallTags(kind, id, r.String("value"), r.String("set_by"), r.String("updated_at")))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind > out[j].Kind // VMs first
		}
		return out[i].FWID < out[j].FWID
	})
	return out, nil
}

// FirewallIDOf is the firewall identity a stored VM spec (kind TagMemberVM)
// or container create_spec (TagMemberCT) holds, read as every reader reads
// it; "" when it holds none.
func FirewallIDOf(kind, doc string) string { return firewallIDOf(kind, doc) }

// FirewallTagsOrphans returns the non-empty tags rows the orphan sweep clears
// at now (spec §4.3, m-4): those whose fw_id no LIVE workload of the row's
// kind holds, and EITHER the newest tombstone holding it was deleted more
// than grace ago, OR no row of the kind holds it at all and the tags row was
// last written more than grace ago. The grace covers a move or re-create in
// flight, which leaves no live row for a moment. A timestamp that does not
// parse keeps the row.
//
// A row is kept at any age while its display name matches a live workload of
// its kind that has no identity (TagGroupMembership.IdentityLost: the loader
// holds that workload while the row remains), or a workload of its kind with
// a relocation or move still in flight (a live container marked relocating,
// or an open relocation, reschedule or promote proof naming it).
func FirewallTagsOrphans(ctx context.Context, c *Client, now time.Time, grace time.Duration) ([]FirewallTagsRecord, error) {
	rows, err := ListFirewallTagsRows(ctx, c)
	if err != nil {
		return nil, err
	}
	var pending []FirewallTagsRecord
	for _, r := range rows {
		if r.Unreadable || len(r.Tags) > 0 {
			pending = append(pending, r)
		}
	}
	if len(pending) == 0 {
		return nil, nil
	}
	type holders struct {
		live       bool
		tombstones int
		// newest is the newest tombstone's deletion; ok false when one
		// did not parse.
		newest time.Time
		ok     bool
	}
	// spared are kind/name of each live workload with no identity, and of
	// each workload with a move in flight.
	spared := map[string]bool{}
	read := func(kind, q string) (map[string]*holders, error) {
		rs, err := c.Query(ctx, q)
		if err != nil {
			return nil, err
		}
		out := map[string]*holders{}
		for _, r := range rs {
			id := firewallIDOf(kind, r.String("doc"))
			if r.String("deleted_at") == "" {
				_, _, relocating := RelocateRestoreMarker(r.String("state"), r.String("state_detail"))
				if id == "" || relocating {
					spared[kind+"/"+r.String("name")] = true
				}
			}
			if id == "" {
				continue
			}
			h := out[id]
			if h == nil {
				h = &holders{ok: true}
				out[id] = h
			}
			del := r.String("deleted_at")
			if del == "" {
				h.live = true
				continue
			}
			h.tombstones++
			t, ok := ParseUpdatedAt(del)
			if !ok {
				h.ok = false
				continue
			}
			if t.After(h.newest) {
				h.newest = t
			}
		}
		return out, nil
	}
	byKind := map[string]map[string]*holders{}
	if byKind[TagMemberVM], err = read(TagMemberVM,
		`SELECT name, spec AS doc, '' AS state, '' AS state_detail, COALESCE(deleted_at, '') AS deleted_at FROM vms`); err != nil {
		return nil, err
	}
	if byKind[TagMemberCT], err = read(TagMemberCT,
		`SELECT name, COALESCE(create_spec, '') AS doc, COALESCE(state, '') AS state, COALESCE(state_detail, '') AS state_detail,
		        COALESCE(deleted_at, '') AS deleted_at FROM containers`); err != nil {
		return nil, err
	}
	open, err := c.Query(ctx,
		`SELECT target_kind, target_name FROM runtime_action_proofs
		  WHERE action IN (?, ?, ?) AND status IN (?, ?) AND deleted_at IS NULL`,
		ActionRelocate, ActionReschedule, ActionPromote, ProofPrepared, ProofInProgress)
	if err != nil {
		return nil, err
	}
	for _, r := range open {
		switch r.String("target_kind") {
		case "vm":
			spared[TagMemberVM+"/"+r.String("target_name")] = true
		case "container":
			spared[TagMemberCT+"/"+r.String("target_name")] = true
		}
	}
	var out []FirewallTagsRecord
	for _, r := range pending {
		h := byKind[r.Kind][r.FWID]
		switch {
		case h != nil && h.live:
		case r.Name != "" && spared[r.Kind+"/"+r.Name]:
		case h != nil && h.tombstones > 0:
			if h.ok && now.Sub(h.newest) > grace {
				out = append(out, r)
			}
		default:
			if t, ok := ParseUpdatedAt(r.UpdatedAt); ok && now.Sub(t) > grace {
				out = append(out, r)
			}
		}
	}
	return out, nil
}
