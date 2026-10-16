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
	"testing"

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
	return func() FWTagAuthority { return FWTagAuthority{minted: true} }
}

// FWTagAuthorityForTest mints an authority for a test. Test code only: the
// authority guard fails the build on any non-test caller.
func FWTagAuthorityForTest(t testing.TB) FWTagAuthority {
	t.Helper()
	return FWTagAuthority{minted: true}
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
