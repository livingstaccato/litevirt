package corrosion

// Cluster-wide replicated policy (schema v58, cluster_policies).
//
// One row per policy key, written by an operator through a gRPC handler and
// read by every node from its own replica. Its keys are failover_scope and
// the ISO library's (iso_library.go: iso_library_mode, one iso_library/<file>
// row per sync-mode library file and one iso_library_host/<host> row per
// host), all written through clusterPolicyUpsertSQL.
// failover_scope says whether a host is fenced and its workloads recovered by a
// quorum of the whole cluster (the default, and what every cluster did before
// v58) or by a quorum of its own region's voters
// (docs/design/region-scoped-failover.md, colonelpanik/litevirt#265).
//
// WHY A REPLICATED ROW AND NOT CONFIG. The guarantee region scoping gives is
// only as good as the coordinator that happens to hold the failover lease, and
// the lease moves. A per-node YAML flag would let two coordinators disagree
// about it indefinitely; a replicated row converges.
//
// WHY A GATE. cluster_policies' statements are the first replicated shapes the
// table has ever had, and a previous-release peer's apply fails closed on an
// unregistered shape and stalls its whole stream. So nothing writes the table
// until failover_scope_v1 has DURABLY latched, which cannot happen while any
// replication recipient runs a build that does not decode it — or does not
// honour the policy it carries.

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

const (
	// FailoverScopeCluster is one quorum over the whole voter set: today's
	// behaviour, and the answer when no row exists.
	FailoverScopeCluster = "cluster"
	// FailoverScopeRegion scopes fencing, host re-admission, the recovery
	// decision and execution gates, and recovery targets to the failed host's
	// region.
	FailoverScopeRegion = "region"

	clusterPolicyFailoverScope = "failover_scope"

	// MinRegionVoters is the smallest region that can fence one of its own
	// hosts. A fence of h in region R needs floor(|V_R|/2)+1 observers from
	// V_R \ {h}, which has |V_R|-1 members; that is reachable only when
	// |V_R| >= 3.
	MinRegionVoters = 3
)

// ErrClusterPolicyGateClosed is returned by a policy write attempted before
// failover_scope_v1 has durably latched on this node.
var ErrClusterPolicyGateClosed = errors.New("cluster policy table not writable until failover_scope_v1 has latched on every host")

// ErrUnknownFailoverScope is returned when the stored scope is not one this
// build implements — a later release's value, arriving by replication. Every
// caller fails CLOSED on it: guessing "cluster" would re-enable cross-region
// fencing the operator turned off, and guessing "region" would do the reverse.
var ErrUnknownFailoverScope = errors.New("unknown failover scope")

// clusterPolicyUpsertSQL is the one writer. Explicit on the primary key, so
// the origin applies it whether or not it holds the row, and a receiver
// LWW-gates it on updated_at (DispExplicitUpsert).
const clusterPolicyUpsertSQL = `INSERT INTO cluster_policies (key, value, set_by, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, NULL)
	 ON CONFLICT(key) DO UPDATE SET value = excluded.value, set_by = excluded.set_by,
	   updated_at = excluded.updated_at, deleted_at = NULL`

// SetClusterPolicyGate injects the predicate that permits WRITING
// cluster_policies, wired at daemon start to the durable failover_scope_v1
// latch. Nil-safe and FAIL CLOSED: an unset gate refuses every write.
func (c *Client) SetClusterPolicyGate(fn func() bool) {
	if fn == nil {
		c.clusterPolicyGate.Store(nil)
		return
	}
	c.clusterPolicyGate.Store(&fn)
}

// MayWriteClusterPolicy reports whether this node may write cluster_policies
// (nil-safe, fail closed).
func (c *Client) MayWriteClusterPolicy() bool {
	fn := c.clusterPolicyGate.Load()
	return fn != nil && (*fn)()
}

// FailoverScopePolicy is the failover_scope row as this node's replica holds
// it. SetBy and UpdatedAt are empty when no row exists.
type FailoverScopePolicy struct {
	Value     string
	SetBy     string
	UpdatedAt string
}

// Region reports whether failover is scoped to regions.
func (p FailoverScopePolicy) Region() bool { return p.Value == FailoverScopeRegion }

// ValidFailoverScope reports whether s is a scope this build implements.
func ValidFailoverScope(s string) bool {
	return s == FailoverScopeCluster || s == FailoverScopeRegion
}

// GetFailoverScope reads the failover scope from this node's replica. No row
// (or a tombstoned one) is FailoverScopeCluster. A stored value this build
// does not implement returns the policy AND ErrUnknownFailoverScope; callers
// fail closed on the error.
func GetFailoverScope(ctx context.Context, c *Client) (FailoverScopePolicy, error) {
	rows, err := c.Query(ctx,
		`SELECT value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		clusterPolicyFailoverScope)
	if err != nil {
		return FailoverScopePolicy{}, err
	}
	if len(rows) == 0 {
		return FailoverScopePolicy{Value: FailoverScopeCluster}, nil
	}
	p := FailoverScopePolicy{
		Value:     rows[0].String("value"),
		SetBy:     rows[0].String("set_by"),
		UpdatedAt: rows[0].String("updated_at"),
	}
	if !ValidFailoverScope(p.Value) {
		return p, fmt.Errorf("%w %q", ErrUnknownFailoverScope, p.Value)
	}
	return p, nil
}

// SetFailoverScope writes the failover scope. It refuses with
// ErrClusterPolicyGateClosed until failover_scope_v1 has latched. The caller —
// the gRPC handler — owns the operator-facing preconditions (role, every voter
// reachable); this function owns only what keeps a peer's stream alive.
func SetFailoverScope(ctx context.Context, c *Client, scope, setBy string) error {
	if !ValidFailoverScope(scope) {
		return fmt.Errorf("%w %q (valid: %s, %s)", ErrUnknownFailoverScope, scope, FailoverScopeCluster, FailoverScopeRegion)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyFailoverScope, scope, setBy, c.NowTS())
}

// VoterRegionSets is the voter set with every host's region: what a
// region-scoped quorum counts over.
type VoterRegionSets struct {
	// Voters is VoterSet, unchanged.
	Voters map[string]bool
	// RegionOf maps every non-deleted host, voter or not, to its region
	// ("default" when unset). A fence target need not be a voter.
	RegionOf map[string]string
}

// VoterRegions reads VoterSet and every host's region. It depends on
// VoterSet's contract alone — a set of names — so it keeps working when that
// set becomes an explicit voter configuration (colonelpanik/litevirt#251).
func VoterRegions(ctx context.Context, c *Client) (VoterRegionSets, error) {
	voters, err := VoterSet(ctx, c)
	if err != nil {
		return VoterRegionSets{}, err
	}
	rows, err := c.Query(ctx, `SELECT name, region FROM hosts WHERE deleted_at IS NULL`)
	if err != nil {
		return VoterRegionSets{}, err
	}
	regionOf := make(map[string]string, len(rows))
	for _, r := range rows {
		regionOf[r.String("name")] = regionOrDefault(r.String("region"))
	}
	return VoterRegionSets{Voters: voters, RegionOf: regionOf}, nil
}

// Region returns h's region, "default" for a host this set does not know.
func (v VoterRegionSets) Region(h string) string {
	if r, ok := v.RegionOf[h]; ok {
		return r
	}
	return regionOrDefault("")
}

// In returns the voters whose region is region.
func (v VoterRegionSets) In(region string) map[string]bool {
	out := map[string]bool{}
	for name := range v.Voters {
		if v.Region(name) == region {
			out[name] = true
		}
	}
	return out
}

// Regions returns every region that holds at least one host, sorted.
func (v VoterRegionSets) Regions() []string {
	seen := map[string]bool{}
	for _, r := range v.RegionOf {
		seen[r] = true
	}
	for name := range v.Voters {
		seen[v.Region(name)] = true
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// LabelFailoverAnyRegion, when "true" in a VM spec's labels, lets region-scoped
// failover recover that VM onto a host in ANOTHER region — and auto-promote a
// replica held there — when its own region has fenced its host but has no
// room for it. It widens where the VM may go, never who decides: the fence is
// still decided by the VM's home region's quorum. Absent, or anything else,
// keeps recovery in region. It means nothing under the cluster scope, where
// recovery targets are cluster-wide anyway.
const LabelFailoverAnyRegion = "litevirt.failover_any_region"

// RegionQuorum is one region's voting strength, as `lv cluster failover-scope`
// prints it and the coordinator's regions-without-quorum gauge counts it.
type RegionQuorum struct {
	Region string
	// Hosts is every non-deleted host in the region, whatever its state.
	Hosts int
	// Workers is the hosts that can hold workloads (not witnesses).
	Workers int
	// Voters is the region's members of VoterSet; VotingWitnesses the
	// witnesses among them.
	Voters          int
	VotingWitnesses int
	// Quorum is a majority of Voters: floor(Voters/2)+1.
	Quorum int
}

// CanFenceOwn reports whether the region can fence one of its own hosts: a
// fence needs Quorum observers other than the target, so at least
// MinRegionVoters voters.
func (r RegionQuorum) CanFenceOwn() bool { return r.Voters >= MinRegionVoters }

// RegionQuorumReport is every region's voting strength, sorted by region.
func RegionQuorumReport(ctx context.Context, c *Client) ([]RegionQuorum, error) {
	voters, err := VoterSet(ctx, c)
	if err != nil {
		return nil, err
	}
	hosts, err := ListHosts(ctx, c)
	if err != nil {
		return nil, err
	}
	by := map[string]*RegionQuorum{}
	for _, h := range hosts {
		r := by[h.Region]
		if r == nil {
			r = &RegionQuorum{Region: h.Region}
			by[h.Region] = r
		}
		r.Hosts++
		if !h.IsWitness() {
			r.Workers++
		}
		if voters[h.Name] {
			r.Voters++
			if h.IsWitness() {
				r.VotingWitnesses++
			}
		}
	}
	out := make([]RegionQuorum, 0, len(by))
	for _, r := range by {
		r.Quorum = r.Voters/2 + 1
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Region < out[j].Region })
	return out, nil
}
