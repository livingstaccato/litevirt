package corrosion

// The cluster HA policy (docs/migration-failover.md, "Disarming HA for planned
// maintenance"): the cluster_policies row `ha`, written only by an operator
// through `lv cluster ha` and read by every node from its own replica. While it
// says disarmed, the failover coordinator decides no fence and no recovery.
//
// No row is armed, and nothing writes a default one: an automatic write could
// overwrite an operator's choice. The row is data of the ha_disarm release
// feature, so its writer takes that feature's grant.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/hlc"
)

const (
	clusterPolicyHA = "ha"

	// HAArmed and HADisarmed are the policy's states.
	HAArmed    = "armed"
	HADisarmed = "disarmed"

	// HADisarmEvaluator is the health-condition evaluator of the HA policy.
	// Every row is written by the host it is about (subject host/<name>).
	HADisarmEvaluator = "ha_disarm"
	// CondHADisarmed: this host's replica holds a disarm. Warning.
	CondHADisarmed = "ha_disarmed"
	// CondHAPolicyUnreadable: this host cannot read the policy, or its cache
	// of it keeps failing to load. Its coordinator decides nothing and its
	// Ready answer vetoes every peer coordinator. Critical.
	CondHAPolicyUnreadable = "ha_policy_unreadable"
	// CondHAPeerVeto: the lease holder's own replica says armed, and a live
	// voter's answer held a fence or a recovery back. Warning.
	CondHAPeerVeto = "ha_disarm_peer_veto"

	// RefusalHADisarmed: a claim voter whose replica says HA is disarmed (or
	// cannot read the policy) does not accept an automatic recovery value.
	RefusalHADisarmed = "recovery_claim_ha_disarmed"
)

// ErrUnreadableHAPolicy is returned with a policy this build cannot read: a
// value that is not JSON, or a state it does not know. The policy then reads
// as disarmed, so nothing automatic acts on a guess.
var ErrUnreadableHAPolicy = errors.New("unreadable HA policy")

// ErrHAStampSkewed refuses a write whose timestamp would have to follow a row
// stamped implausibly far in the future: receivers quarantine such a row's
// successor as skewed too.
var ErrHAStampSkewed = errors.New("the newest HA policy timestamp seen is future-skewed")

// HAPolicy is the `ha` row as this node's replica holds it. SetBy and
// UpdatedAt are empty when there is no row.
type HAPolicy struct {
	State  string
	Reason string
	SetBy  string
	// UpdatedAt is the row's updated_at exactly as stored. Compare it with
	// LWWNewer, never as a string: it can be HLC or RFC3339.
	UpdatedAt string
	// Unreadable: the stored value could not be read. State is then
	// HADisarmed.
	Unreadable bool
}

// Disarmed reports whether automatic fencing and recovery are held: the state
// is disarmed, or the row cannot be read.
func (p HAPolicy) Disarmed() bool { return p.Unreadable || p.State != HAArmed }

type haPolicyValue struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// ValidHAState reports whether s is a state this build implements.
func ValidHAState(s string) bool { return s == HAArmed || s == HADisarmed }

// GetHAPolicy reads the policy from this node's replica. No row (or a
// tombstoned one) is armed. A value that cannot be read returns a disarmed
// policy with Unreadable set AND ErrUnreadableHAPolicy.
func GetHAPolicy(ctx context.Context, c *Client) (HAPolicy, error) {
	rows, err := c.Query(ctx,
		`SELECT value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		clusterPolicyHA)
	if err != nil {
		return HAPolicy{}, err
	}
	if len(rows) == 0 {
		return HAPolicy{State: HAArmed}, nil
	}
	p := HAPolicy{SetBy: rows[0].String("set_by"), UpdatedAt: rows[0].String("updated_at")}
	var v haPolicyValue
	if jerr := json.Unmarshal([]byte(rows[0].String("value")), &v); jerr != nil || !ValidHAState(v.State) {
		p.State, p.Unreadable = HADisarmed, true
		if jerr != nil {
			return p, fmt.Errorf("%w: %v", ErrUnreadableHAPolicy, jerr)
		}
		return p, fmt.Errorf("%w: unknown state %q", ErrUnreadableHAPolicy, v.State)
	}
	p.State, p.Reason = v.State, v.Reason
	return p, nil
}

// SetHAPolicy writes the policy and returns the updated_at it stamped. The
// stamp is strictly newer than after (the newest policy timestamp the caller
// has seen, "" for none), so a write cannot lose last-writer-wins to an older
// row stamped by a clock running ahead of this one. It refuses with
// ErrHAStampSkewed when after is itself future-skewed, and with
// ErrClusterPolicyGateClosed until failover_scope_v1 has latched. It is data
// of the ha_disarm release feature, so it takes that feature's grant.
func SetHAPolicy(ctx context.Context, c *Client, g capabilities.FeatureGrant, state, reason, setBy, after string) (string, error) {
	if err := g.Check(capabilities.FeatureHADisarm); err != nil {
		return "", err
	}
	if !ValidHAState(state) {
		return "", fmt.Errorf("unknown HA state %q (valid: %s, %s)", state, HAArmed, HADisarmed)
	}
	if !c.MayWriteClusterPolicy() {
		return "", ErrClusterPolicyGateClosed
	}
	ts, err := c.stampAfter(after, time.Now())
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(haPolicyValue{State: state, Reason: reason})
	if err != nil {
		return "", err
	}
	if err := c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyHA, string(b), setBy, ts); err != nil {
		return "", err
	}
	return ts, nil
}

// HATimestampSkewed reports whether ts is stamped implausibly far ahead of
// now: a receiver's skew guard would quarantine it, and a row stamped after it.
func HATimestampSkewed(ts string, now time.Time) bool { return tsFutureSkewed(ts, now) }

// stampAfter is an updated_at for a new write, strictly newer than after.
func (c *Client) stampAfter(after string, now time.Time) (string, error) {
	ts := c.NowTS()
	if after == "" || LWWNewer(ts, after) {
		return ts, nil
	}
	if tsFutureSkewed(after, now) {
		return "", fmt.Errorf("%w (%s)", ErrHAStampSkewed, after)
	}
	// An HLC key past after: the clock adopts after's physical time and
	// counts past it, so this node's later keys stay ordered after it too.
	if hlc.IsHLC(ts) && hlc.IsHLC(after) && c.clock != nil {
		if p, ok := hlc.Parse(after); ok {
			if next := c.clock.Update(p).String(); LWWNewer(next, after) {
				return next, nil
			}
		}
	}
	inst, ok := tsInstant(after)
	if !ok {
		return "", fmt.Errorf("cannot order a write after the unreadable timestamp %q", after)
	}
	next := inst.Add(time.Millisecond).UTC().Format(time.RFC3339Nano)
	if !LWWNewer(next, after) {
		return "", fmt.Errorf("cannot order a write after %q", after)
	}
	return next, nil
}
