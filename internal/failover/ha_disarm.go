package failover

import "time"

// PeerHAAnswer is a peer's latest answer to the health probe about the cluster
// HA policy (ReadyResponse.ha_known, ha_disarmed, ha_policy_at).
type PeerHAAnswer struct {
	Asked    time.Time // when the probe that carried it was sent, on this node's monotonic clock
	Known    bool
	Disarmed bool
	PolicyAt string // the policy row's updated_at as the peer stores it; "" when it has none
}
