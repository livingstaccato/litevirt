package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// VMNICRowModels is the model of each live vm_nics row of vmName, keyed by
// its lower-cased MAC. vm_interfaces rows are not read: they have no model
// column.
func VMNICRowModels(ctx context.Context, c *Client, vmName string) (map[string]string, error) {
	rows, err := GetVMNICsRaw(ctx, c, "vm_nics", vmName)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		if r.DeletedAt == "" {
			out[strings.ToLower(r.MAC)] = r.Model
		}
	}
	return out, nil
}

// NICDetachRequestHash is the request hash a NIC detach of mac from vmName
// records on its operation: the mac alone names the NIC.
func NICDetachRequestHash(vmName, mac string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("detach-nic|%s|%s", vmName, strings.ToLower(mac))))
	return hex.EncodeToString(sum[:])
}

// DetachedNICMACs reports which of macs a NIC detach was ever recorded for
// on vmName, keyed by lower-cased MAC. A live NIC with such a MAC was
// attached again after that detach, so it is not the NIC the create recorded
// under the MAC. Operation headers are soft-deleted when reaped, never
// removed, so a reaped detach still counts: nothing may hard-delete them
// (TestOperationHeadersAreNeverHardDeleted).
func DetachedNICMACs(ctx context.Context, c *Client, vmName string, macs []string) (map[string]bool, error) {
	rows, err := c.Query(ctx,
		`SELECT request_hash FROM operations WHERE resource_kind = 'vm' AND resource_id = ? AND operation_kind = ?`,
		vmName, string(OpDeviceDetach))
	if err != nil {
		return nil, err
	}
	hashes := make(map[string]bool, len(rows))
	for _, r := range rows {
		hashes[r.String("request_hash")] = true
	}
	out := map[string]bool{}
	for _, mac := range macs {
		if hashes[NICDetachRequestHash(vmName, mac)] {
			out[strings.ToLower(mac)] = true
		}
	}
	return out, nil
}

// NICModelSources reads what a domain builder needs to give each of vmName's
// live NICs its recorded model (compose.NICModels): the vm_nics models and
// which NICs were detached and attached again under the same MAC.
// specModels is the spec's model per MAC (compose.SpecNICModelsByMAC). The
// operations are read only for a NIC whose row and spec entry disagree on
// its model — the only case the answer changes — so a render of an ordinary
// VM reads no operations at all.
func NICModelSources(ctx context.Context, c *Client, vmName string, nics []NICRecord, specModels map[string]string) (rowModels map[string]string, reattached map[string]bool, err error) {
	if rowModels, err = VMNICRowModels(ctx, c, vmName); err != nil {
		return nil, nil, err
	}
	var macs []string
	for _, n := range nics {
		k := strings.ToLower(n.MAC)
		sm, rm := specModels[k], rowModels[k]
		if sm != "" && rm != "" && !strings.EqualFold(sm, rm) {
			macs = append(macs, n.MAC)
		}
	}
	if len(macs) == 0 {
		return rowModels, map[string]bool{}, nil
	}
	if reattached, err = DetachedNICMACs(ctx, c, vmName, macs); err != nil {
		return nil, nil, err
	}
	return rowModels, reattached, nil
}
