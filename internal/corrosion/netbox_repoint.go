package corrosion

import (
	"context"
	"errors"
	"fmt"
)

// A lease names its NetBox address object by id. When that object is deleted
// in NetBox by hand, the lease goes on naming the dead id, and the inventory
// mirror cannot give the NIC its address. The repair re-creates the address
// and re-points the lease at the new object, which is the one statement below.
//
// It is a statement shape a previous-release peer has no ledger entry for, so
// it is written only once netbox_ip_repoint_v1 has durably latched — on every
// host the cluster replicates to, a maintenance host included.

// ErrNetBoxRepointGateClosed is returned by RepointNetBoxLease until
// netbox_ip_repoint_v1 has durably latched on this node.
var ErrNetBoxRepointGateClosed = errors.New(
	"lease re-point not writable until netbox_ip_repoint_v1 has latched on every host")

// netboxRepointSQL moves one LIVE lease from the dead address object to the
// new one. Guarded on the dead id, so a lease that was released, re-claimed or
// re-pointed by another node meanwhile is left alone: the read-back then
// reports that this call did not move it.
const netboxRepointSQL = `UPDATE ip_allocations SET netbox_ip_id = ?, updated_at = ?
	 WHERE network = ? AND ip = ? AND netbox_ip_id = ? AND deleted_at IS NULL`

// SetNetBoxRepointGate injects the predicate that permits re-pointing a lease,
// wired at daemon start to the durable netbox_ip_repoint_v1 latch. Nil-safe and
// FAIL CLOSED: an unset gate refuses every re-point.
func (c *Client) SetNetBoxRepointGate(fn func() bool) {
	if fn == nil {
		c.netboxRepointGate.Store(nil)
		return
	}
	c.netboxRepointGate.Store(&fn)
}

// MayRepointNetBoxLease reports whether this node may re-point a lease.
func (c *Client) MayRepointNetBoxLease() bool {
	fn := c.netboxRepointGate.Load()
	return fn != nil && (*fn)()
}

// RepointNetBoxLease moves the live lease (network, ip) from NetBox address
// object fromID to toID, and reports whether this call moved it.
//
// false with no error means the lease no longer names fromID — it was
// released or moved by someone else — and nothing was changed. An error may
// follow a committed update (ErrNetBoxRepointUnconfirmed, or a failed write
// whose outcome is unknown): it never means nothing was changed. It refuses with
// ErrNetBoxRepointGateClosed, writing nothing, until the gate is open.
func RepointNetBoxLease(ctx context.Context, c *Client, network, ip string, fromID, toID int) (bool, error) {
	if !c.MayRepointNetBoxLease() {
		return false, ErrNetBoxRepointGateClosed
	}
	if fromID == 0 || toID == 0 || fromID == toID {
		return false, fmt.Errorf("re-point lease %s on %s: invalid address ids %d -> %d", ip, network, fromID, toID)
	}
	// STRICT: a re-point whose guard matched nothing must not be relayed. A peer
	// that has not yet received the release that moved this row past the guard
	// still holds it live under fromID, would apply the re-point, and LWW would
	// then carry it over the older release — a released lease brought back.
	n, err := c.ExecuteRowsStrict(ctx, netboxRepointSQL, toID, c.NowTS(), network, ip, fromID)
	if err != nil {
		return false, fmt.Errorf("re-point lease %s on %s: %w", ip, network, err)
	}
	if n == 0 {
		return false, nil
	}
	// The read-back is what says the lease now names the new object. The
	// update has committed by now: a failed or negative read-back is not a
	// guard miss, and is reported as unconfirmed rather than as false.
	ok, err := confirmNetBoxRepoint(ctx, c, network, ip, toID)
	if err != nil {
		return false, fmt.Errorf("confirm re-point of lease %s on %s: %w: %w", ip, network, ErrNetBoxRepointUnconfirmed, err)
	}
	if !ok {
		return false, fmt.Errorf("re-point of lease %s on %s to %d: %w: the lease no longer names it",
			ip, network, toID, ErrNetBoxRepointUnconfirmed)
	}
	return true, nil
}

// ErrNetBoxRepointUnconfirmed is RepointNetBoxLease's answer when its update
// committed but could not be confirmed. The lease may name the new object, so
// nothing may treat that object as unreferenced.
var ErrNetBoxRepointUnconfirmed = errors.New("lease re-point committed but not confirmed")

// confirmNetBoxRepoint reads back whether the live lease names toID. A var so
// a test can fail it.
var confirmNetBoxRepoint = func(ctx context.Context, c *Client, network, ip string, toID int) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT 1 AS ok FROM ip_allocations
		 WHERE network = ? AND ip = ? AND netbox_ip_id = ? AND deleted_at IS NULL`,
		network, ip, toID)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}
