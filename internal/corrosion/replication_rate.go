package corrosion

// Per-schedule replication bandwidth limits (docs/backups.md, "Replication
// bandwidth limit"): one cluster_policies row per limited schedule, keyed
// replication_rate/<schedule row vm_name>/<schedule row repo> with both parts
// path-escaped (a container schedule's key and a repo may hold '/'). The value
// is bytes per second as a decimal string; "" is a cleared limit, since
// cluster_policies has no delete statement. Written through
// clusterPolicyUpsertSQL behind the failover_scope_v1 gate, and the data of
// the replication_rate release feature, so the writer takes its grant.

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
)

const replicationRateKeyPrefix = "replication_rate/"

// ReplicationRateID names one replication schedule row: its vm_name (a VM, a
// fan-out sentinel or a container key) and its repo.
type ReplicationRateID struct {
	Schedule string
	Repo     string
}

// ReplicationRateKey is the cluster_policies key of a schedule's limit.
func ReplicationRateKey(schedule, repo string) string {
	return replicationRateKeyPrefix + url.PathEscape(schedule) + "/" + url.PathEscape(repo)
}

// ParseReplicationRateKey is the inverse of ReplicationRateKey.
func ParseReplicationRateKey(key string) (schedule, repo string, ok bool) {
	rest, found := strings.CutPrefix(key, replicationRateKeyPrefix)
	if !found {
		return "", "", false
	}
	es, er, found := strings.Cut(rest, "/")
	if !found || strings.Contains(er, "/") {
		return "", "", false
	}
	s, err1 := url.PathUnescape(es)
	r, err2 := url.PathUnescape(er)
	if err1 != nil || err2 != nil || s == "" || r == "" {
		return "", "", false
	}
	return s, r, true
}

// SetReplicationRate stores the bandwidth limit of the schedule row (schedule,
// repo) in bytes per second; 0 clears it (writes ""). It takes the
// replication_rate grant, and refuses with ErrClusterPolicyGateClosed until
// failover_scope_v1 has latched. The caller owns the operator-facing minimum.
func SetReplicationRate(ctx context.Context, c *Client, g capabilities.FeatureGrant, schedule, repo string, bps int64, setBy string) error {
	if err := g.Check(capabilities.FeatureReplicationRate); err != nil {
		return err
	}
	if schedule == "" || repo == "" {
		return fmt.Errorf("replication rate needs a schedule and a repo")
	}
	if bps < 0 {
		return fmt.Errorf("invalid replication rate %d", bps)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	v := ""
	if bps > 0 {
		v = strconv.FormatInt(bps, 10)
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, ReplicationRateKey(schedule, repo), v, setBy, c.NowTS())
}

// parseReplicationRate reads a stored value: "" or a value this build cannot
// read (a later release's) is no limit.
func parseReplicationRate(v string) int64 {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// GetReplicationRate reads the schedule row's limit from this node's replica,
// in bytes per second; 0 is none.
func GetReplicationRate(ctx context.Context, c *Client, schedule, repo string) (int64, error) {
	v, err := replicationRateValue(ctx, c, schedule, repo)
	if err != nil {
		return 0, err
	}
	return parseReplicationRate(v), nil
}

// HasReplicationRate reports whether the schedule row has a stored limit that
// is not cleared, whether or not this build can read it.
func HasReplicationRate(ctx context.Context, c *Client, schedule, repo string) (bool, error) {
	v, err := replicationRateValue(ctx, c, schedule, repo)
	return v != "", err
}

func replicationRateValue(ctx context.Context, c *Client, schedule, repo string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, ReplicationRateKey(schedule, repo))
	if err != nil || len(rows) == 0 {
		return "", err
	}
	return rows[0].String("value"), nil
}

// ListReplicationRates returns every limited schedule's rate. Cleared and
// unreadable values are left out.
func ListReplicationRates(ctx context.Context, c *Client) (map[ReplicationRateID]int64, error) {
	lo, hi := keyRange(replicationRateKeyPrefix)
	rows, err := c.Query(ctx,
		`SELECT key, value FROM cluster_policies WHERE key >= ? AND key < ? AND deleted_at IS NULL`, lo, hi)
	if err != nil {
		return nil, err
	}
	out := map[ReplicationRateID]int64{}
	for _, r := range rows {
		s, repo, ok := ParseReplicationRateKey(r.String("key"))
		if !ok {
			continue
		}
		if bps := parseReplicationRate(r.String("value")); bps > 0 {
			out[ReplicationRateID{Schedule: s, Repo: repo}] = bps
		}
	}
	return out, nil
}
