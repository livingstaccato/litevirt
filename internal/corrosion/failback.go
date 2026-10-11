package corrosion

// Failback after maintenance (docs/migration-failover.md, "Failback"): the
// replicated state behind it. It lives in cluster_policies, written through its
// one upsert (clusterPolicyUpsertSQL) and so behind the same failover_scope_v1
// gate — no new table and no new statement shape. The policy and the drain
// records are the data of the drain_failback release feature, so their writers
// also take that feature's grant; the placement generation below is not. The
// rows:
//
//   - failback: the cluster policy, "on" or "off" (no row is off). With it on,
//     an undrain moves back every VM a drain of that host moved away.
//   - drain_origin/<vm>: written when a drain moves a VM off a host. It names
//     the host it left, the host it went to, and the VM's identity at that
//     moment: its creation time and its ownership epoch. That is everything
//     failback needs to tell "the drain put it there and nothing has touched it
//     since" from every other case. Every ownership transfer — a migration by
//     hand, a failover, a later drain — bumps the epoch, so a record whose
//     epoch no longer matches means the VM was moved for another reason and is
//     left where it is; a VM deleted and created again has another creation
//     time. A record with no content ("{}") is a collected one.
//
// cluster_policies has no statement that deletes a row, and adding one is a
// new replicated shape, so a collected record stays as an empty row.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
)

const (
	clusterPolicyFailback = "failback"
	drainOriginKeyPrefix  = "drain_origin/"

	// FailbackOn and FailbackOff are the policy values.
	FailbackOn  = "on"
	FailbackOff = "off"
)

// FailbackPolicy is the failback row as this node's replica holds it. SetBy
// and UpdatedAt are empty when no row exists.
type FailbackPolicy struct {
	Enabled   bool
	SetBy     string
	UpdatedAt string
}

// GetFailbackPolicy reads the policy. No row, a tombstoned one, or a value this
// build does not implement is off: failback moves VMs, so it never guesses "on".
func GetFailbackPolicy(ctx context.Context, c *Client) (FailbackPolicy, error) {
	rows, err := c.Query(ctx,
		`SELECT value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		clusterPolicyFailback)
	if err != nil {
		return FailbackPolicy{}, err
	}
	if len(rows) == 0 {
		return FailbackPolicy{}, nil
	}
	return FailbackPolicy{
		Enabled:   rows[0].String("value") == FailbackOn,
		SetBy:     rows[0].String("set_by"),
		UpdatedAt: rows[0].String("updated_at"),
	}, nil
}

// SetFailbackPolicy writes the policy. It is data of the drain_failback release
// feature, so it takes the grant of that feature's gate
// (grpcapi.Server.WithReleaseFeature). It refuses with ErrClusterPolicyGateClosed
// until failover_scope_v1 has latched.
func SetFailbackPolicy(ctx context.Context, c *Client, g capabilities.FeatureGrant, enabled bool, setBy string) error {
	if err := g.Check(capabilities.FeatureDrainFailback); err != nil {
		return err
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	v := FailbackOff
	if enabled {
		v = FailbackOn
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyFailback, v, setBy, c.NowTS())
}

// DrainOrigin is one VM a drain moved off a host.
type DrainOrigin struct {
	VM string `json:"-"`
	// From is the drained host; To is the host the drain put the VM on.
	From string `json:"from"`
	To   string `json:"to"`
	// Epoch and CreatedAt are the VM's ownership epoch and creation time right
	// after the move: the identity a later failback checks it still has.
	Epoch     int64  `json:"epoch"`
	CreatedAt string `json:"created_at"`
	// Gen is the VM's placement generation right after the drain's move
	// (GetPlacementGen). Failback proceeds only while the owner's generation is
	// still this one, which does not depend on whether any other record
	// replicated.
	Gen int64 `json:"gen"`
}

// PutDrainOrigin records that a drain moved o.VM from o.From to o.To. A later
// drain of the same VM replaces the record. The record is data of the
// drain_failback release feature, so it takes the grant of that feature's gate
// (grpcapi.Server.WithReleaseFeature): once any record exists, a rollback below
// the release token quarantines rather than run a build that moves VMs without
// advancing their placement generation. It refuses with
// ErrClusterPolicyGateClosed until failover_scope_v1 has latched.
func PutDrainOrigin(ctx context.Context, c *Client, g capabilities.FeatureGrant, o DrainOrigin, setBy string) error {
	if err := g.Check(capabilities.FeatureDrainFailback); err != nil {
		return err
	}
	if o.VM == "" || o.From == "" || o.To == "" || strings.ContainsAny(o.VM, "/%") {
		return fmt.Errorf("invalid drain origin %+v", o)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, drainOriginKeyPrefix+o.VM, string(b), setBy, c.NowTS())
}

// ListDrainOrigins returns the records of VMs a drain moved off host, by VM
// name. Collected records and values that do not decode (a later release's) are
// skipped.
func ListDrainOrigins(ctx context.Context, c *Client, host string) ([]DrainOrigin, error) {
	lo, hi := keyRange(drainOriginKeyPrefix)
	rows, err := c.Query(ctx,
		`SELECT key, value FROM cluster_policies WHERE key >= ? AND key < ? AND deleted_at IS NULL`, lo, hi)
	if err != nil {
		return nil, err
	}
	var out []DrainOrigin
	for _, r := range rows {
		var o DrainOrigin
		if json.Unmarshal([]byte(r.String("value")), &o) != nil || o.From == "" || o.To == "" {
			continue
		}
		if o.From != host {
			continue
		}
		o.VM = strings.TrimPrefix(r.String("key"), drainOriginKeyPrefix)
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VM < out[j].VM })
	return out, nil
}

// CollectDrainOrigin empties a VM's record (see the file comment): it was
// failed back, or can never be. It takes no grant: it writes no new data, only
// empties a record that exists because the feature was used, and it runs inside
// writers that move a VM (SpendDrainOrigin), which must never be refused.
func CollectDrainOrigin(ctx context.Context, c *Client, vm, setBy string) error {
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, drainOriginKeyPrefix+vm, "{}", setBy, c.NowTS())
}

// GetLiveDrainOrigin returns vm's drain record on this node's replica, and
// whether it holds a live one (a collected record is not).
func GetLiveDrainOrigin(ctx context.Context, c *Client, vm string) (DrainOrigin, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, drainOriginKeyPrefix+vm)
	if err != nil || len(rows) == 0 {
		return DrainOrigin{}, false, err
	}
	var o DrainOrigin
	if json.Unmarshal([]byte(rows[0].String("value")), &o) != nil || o.From == "" || o.To == "" {
		return DrainOrigin{}, false, nil
	}
	o.VM = vm
	return o, true, nil
}

// SpendDrainOrigin cancels vm's drain record, if it has a live one: the VM's
// host has just changed, so the record no longer describes it. It is called by
// every writer that changes a VM's host, after the change landed (no record
// exists before the drain_failback release feature is used, and the release
// token keeps a build that does not spend it off the cluster from then on). A read first, so moving a VM no
// drain moved writes nothing, and best effort: a record that stays behind is
// caught by the owner-side check failback makes, and by the owner epoch where
// the writer bumps it.
func SpendDrainOrigin(ctx context.Context, c *Client, vm string) {
	if _, live, err := GetLiveDrainOrigin(ctx, c, vm); err != nil || !live {
		return
	}
	_ = CollectDrainOrigin(ctx, c, vm, "moved")
}

// The placement generation: a per-VM counter, kept in cluster_policies
// (placement_gen/<vm>), that every writer which changes a VM's host advances IN
// THE SAME BATCH as the host change. Replication is ordered per origin, so a
// host that has received the batch that made it the VM's owner has the
// generation of that move, and the next move reads it and writes the next
// number. A hand move out and back therefore leaves a generation two higher than
// any drain record, whether or not that record ever reached the movers.
//
// Like every cluster_policies write it waits for the cluster-policy gate; with
// the gate closed no generation is kept, and neither is any drain record. It is
// NOT behind the drain_failback release feature: the generation is advanced by
// every move whether or not failback is ever used, and it must already be
// counting when the first drain record is written.
const placementGenKeyPrefix = "placement_gen/"

// GetPlacementGen returns vm's placement generation on this node's replica; a VM
// that has never been moved has 0.
func GetPlacementGen(ctx context.Context, c *Client, vm string) (int64, error) {
	rows, err := c.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, placementGenKeyPrefix+vm)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	var n int64
	if _, serr := fmt.Sscanf(rows[0].String("value"), "%d", &n); serr != nil || n < 0 {
		return 0, nil
	}
	return n, nil
}

// placementGenStmts is the statement that advances vm's placement generation,
// for the batch that changes its host; none while the gate is closed.
func placementGenStmts(ctx context.Context, c *Client, vm string) []Statement {
	if !c.MayWriteClusterPolicy() {
		return nil
	}
	n, err := GetPlacementGen(ctx, c, vm)
	if err != nil {
		return nil
	}
	return []Statement{{
		SQL:    clusterPolicyUpsertSQL,
		Params: []interface{}{placementGenKeyPrefix + vm, fmt.Sprintf("%d", n+1), "placement", c.NowTS()},
	}}
}
