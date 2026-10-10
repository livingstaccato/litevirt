package corrosion

// Health-aware relay election (colonelpanik/litevirt#175).
//
// Relays used to be chosen by hosts.state and then by name, so an `active`
// host behind a degraded link carried the cluster's push mesh whenever its
// name sorted early. The failover lease holder now watches the probe verdicts
// every voter already publishes (host_health) and, when a host's probes keep
// failing from enough of them, DEMOTES it: it writes a relay_demoted/<host>
// row in cluster_policies, and RelayEligibleHosts treats that host as
// ineligible. It stays a LEAF and keeps receiving replication; only the relay
// role is withheld.
//
// WHY A REPLICATED ROW. The relay set is only useful if every node computes
// the same one (ComputeRelays), so the health input must be one every node
// reads identically. A node's own probe view differs by who is asking. One
// node decides — the failover lease holder, which already reads every voter's
// verdicts for fencing — and the decision replicates.
//
// WHY THE EXISTING TABLE AND SHAPE. The row goes through
// clusterPolicyUpsertSQL, the same statement the failover scope, the ISO
// library and the pool records use, so no new table and no new statement
// shape exist: a peer that decodes cluster_policies decodes this.
//
// WHY A TOKEN AS WELL. A previous-release peer decodes the row but ignores the
// key, and would keep the demoted host in its relay set while every upgraded
// node dropped it — the disagreement ComputeRelays forbids. So nothing writes
// a demotion until relay_health_v1 (mandatory, replication-gated) has DURABLY
// latched: every host still receiving replication runs a build that reads it.
// The cluster_policies gate (failover_scope_v1) must hold too, because that is
// the latch that proves every recipient decodes the shape.
//
// cluster_policies has no statement that deletes a row, so a restore writes
// the row again with demoted=false, like iso_library's "{}" removal. Rows are
// bounded by host names, never by history.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// RelayDemotedKeyPrefix is the cluster_policies key prefix of the demotion
// rows: relay_demoted/<host>.
const RelayDemotedKeyPrefix = "relay_demoted/"

// ErrRelayHealthGateClosed is returned by a demotion write attempted before
// relay_health_v1 (and failover_scope_v1) have durably latched on this node.
var ErrRelayHealthGateClosed = errors.New("relay demotions not writable until relay_health_v1 has latched on every host")

// RelayDemotion is the value of a relay_demoted/<host> row.
type RelayDemotion struct {
	// Demoted is true while the host is withheld from relay duty. A restore
	// writes the row again with false.
	Demoted bool `json:"demoted"`
	// Since is when the current state began (RFC 3339, the deciding lease
	// holder's clock).
	Since string `json:"since"`
	// Reason says why, for the operator.
	Reason string `json:"reason"`
}

// SetRelayHealthGate injects the predicate that permits writing demotion
// rows, wired at daemon start to the durable relay_health_v1 latch. Nil-safe
// and FAIL CLOSED: an unset gate refuses every write.
func (c *Client) SetRelayHealthGate(fn func() bool) {
	if fn == nil {
		c.relayHealthGate.Store(nil)
		return
	}
	c.relayHealthGate.Store(&fn)
}

// MayWriteRelayDemotion reports whether this node may write a demotion row:
// relay_health_v1 has latched (every recipient reads the key) and the
// cluster_policies gate is open (every recipient decodes the shape).
func (c *Client) MayWriteRelayDemotion() bool {
	fn := c.relayHealthGate.Load()
	return fn != nil && (*fn)() && c.MayWriteClusterPolicy()
}

// SetRelayDemotion writes host's demotion row. It refuses with
// ErrRelayHealthGateClosed until the gates are open.
func SetRelayDemotion(ctx context.Context, c *Client, host string, d RelayDemotion, setBy string) error {
	if !c.MayWriteRelayDemotion() {
		return ErrRelayHealthGateClosed
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, RelayDemotedKeyPrefix+host, string(b), setBy, c.NowTS())
}

// ListRelayDemotions returns every host whose row says it is demoted. A row
// whose value does not parse, or says demoted=false, is not a demotion: the
// bytes are replicated, so every node reaches the same answer about it.
func ListRelayDemotions(ctx context.Context, c *Client) (map[string]RelayDemotion, error) {
	rows, err := c.Query(ctx,
		`SELECT key, value FROM cluster_policies WHERE key >= ? AND key < ? AND deleted_at IS NULL`,
		RelayDemotedKeyPrefix, RelayDemotedKeyPrefix+"\xff")
	if err != nil {
		return nil, err
	}
	out := make(map[string]RelayDemotion, len(rows))
	for _, r := range rows {
		k := r.String("key")
		if !strings.HasPrefix(k, RelayDemotedKeyPrefix) {
			continue
		}
		var d RelayDemotion
		if json.Unmarshal([]byte(r.String("value")), &d) != nil || !d.Demoted {
			continue
		}
		out[strings.TrimPrefix(k, RelayDemotedKeyPrefix)] = d
	}
	return out, nil
}
