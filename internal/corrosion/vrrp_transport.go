package corrosion

// The load balancers' VRRP transport, cluster-wide (capabilities.VRRPUnicastV1).
//
// Two cluster_policies keys, both written through clusterPolicyUpsertSQL:
//
//   - vrrp_transport is the operator's choice, `lv cluster vrrp-transport`:
//     "unicast" or "multicast". When set it decides for every host.
//   - vrrp_transport_latched is written by the first host whose
//     vrrp_unicast_v1 latch becomes durable. Every host renders unicast from
//     the moment it reads it, whether or not its own latch has formed yet, so
//     the switch follows replication rather than each host's latch schedule.
//
// The transport is one value per cluster, read from each host's replica: an
// LB's hosts render the same transport whatever their own config says.

import (
	"context"
	"fmt"
)

const (
	// VRRPTransportUnicast and VRRPTransportMulticast are the two transports.
	VRRPTransportUnicast   = "unicast"
	VRRPTransportMulticast = "multicast"

	clusterPolicyVRRPTransport        = "vrrp_transport"
	clusterPolicyVRRPTransportLatched = "vrrp_transport_latched"
)

// VRRPTransportPolicy is the VRRP transport rows as this node's replica holds
// them. Operator is "" when no operator choice is recorded (or it is a value
// this build does not know); Latched reports the latch row.
type VRRPTransportPolicy struct {
	Operator  string
	SetBy     string
	UpdatedAt string
	Unknown   string // a stored operator value this build does not implement
	Latched   bool
	LatchedBy string
}

// ValidVRRPTransport reports whether t is a transport this build implements.
func ValidVRRPTransport(t string) bool {
	return t == VRRPTransportUnicast || t == VRRPTransportMulticast
}

// GetVRRPTransport reads both rows from this node's replica.
func GetVRRPTransport(ctx context.Context, c *Client) (VRRPTransportPolicy, error) {
	rows, err := c.Query(ctx,
		`SELECT key, value, set_by, updated_at FROM cluster_policies WHERE key IN (?, ?) AND deleted_at IS NULL`,
		clusterPolicyVRRPTransport, clusterPolicyVRRPTransportLatched)
	if err != nil {
		return VRRPTransportPolicy{}, err
	}
	var p VRRPTransportPolicy
	for _, r := range rows {
		switch r.String("key") {
		case clusterPolicyVRRPTransport:
			if v := r.String("value"); ValidVRRPTransport(v) {
				p.Operator = v
			} else {
				p.Unknown = v
			}
			p.SetBy, p.UpdatedAt = r.String("set_by"), r.String("updated_at")
		case clusterPolicyVRRPTransportLatched:
			p.Latched, p.LatchedBy = true, r.String("set_by")
		}
	}
	return p, nil
}

// SetVRRPTransport records the operator's transport. It refuses with
// ErrClusterPolicyGateClosed until failover_scope_v1 has latched; the gRPC
// handler owns the operator-facing preconditions.
func SetVRRPTransport(ctx context.Context, c *Client, transport, setBy string) error {
	if !ValidVRRPTransport(transport) {
		return fmt.Errorf("unknown VRRP transport %q (valid: %s, %s)", transport, VRRPTransportUnicast, VRRPTransportMulticast)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyVRRPTransport, transport, setBy, c.NowTS())
}

// MarkVRRPUnicastLatched records that host's vrrp_unicast_v1 latch has become
// durable, so every host renders unicast from its own replica.
func MarkVRRPUnicastLatched(ctx context.Context, c *Client, host string) error {
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyVRRPTransportLatched, "1", host, c.NowTS())
}
