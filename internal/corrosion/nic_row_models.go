package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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

// nicDetachCompletion binds a successful detach to the VM incarnation that
// executed it. The epoch is historical execution evidence, not current ownership.
type nicDetachCompletion struct {
	Version     int    `json:"version"`
	VMCreatedAt string `json:"vm_created_at"`
	MAC         string `json:"mac"`
	OwnerEpoch  int64  `json:"owner_epoch"`
}

func decodeNICDetachCompletion(raw string) (nicDetachCompletion, error) {
	var f nicDetachCompletion
	d := json.NewDecoder(strings.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return f, fmt.Errorf("invalid NIC detach provenance object")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return f, err
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return f, fmt.Errorf("duplicate NIC detach provenance field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return f, err
		}
		if string(value) == "null" {
			return f, fmt.Errorf("null NIC detach provenance field %q", key)
		}
		switch key {
		case "version":
			err = json.Unmarshal(value, &f.Version)
		case "vm_created_at":
			err = json.Unmarshal(value, &f.VMCreatedAt)
		case "mac":
			err = json.Unmarshal(value, &f.MAC)
		case "owner_epoch":
			err = json.Unmarshal(value, &f.OwnerEpoch)
		default:
			return f, fmt.Errorf("unknown NIC detach provenance field %q", key)
		}
		if err != nil {
			return f, err
		}
	}
	if _, err = d.Token(); err != nil {
		return f, err
	}
	if _, err = d.Token(); err != io.EOF {
		return f, fmt.Errorf("trailing NIC detach provenance")
	}
	mac, err := net.ParseMAC(f.MAC)
	if len(seen) != 4 || f.Version != 1 || f.VMCreatedAt == "" || f.OwnerEpoch < 0 || err != nil || len(mac) != 6 || mac.String() != f.MAC {
		return f, fmt.Errorf("incomplete or unsupported NIC detach provenance")
	}
	return f, nil
}

// CompleteVMNICDetach commits incarnation evidence and barrier release together.
// A stale incarnation, owner, generation, or operation cannot publish evidence.
func (c *Client) CompleteVMNICDetach(ctx context.Context, vmName, operationID string, ownerEpoch, expectedSpecGen int64, createdAt, mac string) (bool, error) {
	f := nicDetachCompletion{1, createdAt, strings.ToLower(mac), ownerEpoch}
	raw, err := json.Marshal(f)
	if err != nil {
		return false, err
	}
	if _, err := decodeNICDetachCompletion(string(raw)); err != nil {
		return false, err
	}
	now := c.NowTS()
	guard := func(tx *sql.Tx) (bool, error) {
		var oe, sg int64
		var active, stamp string
		err := tx.QueryRowContext(ctx, `SELECT vm_owner_epoch, spec_generation, active_operation_id, created_at FROM vms WHERE name = ? AND deleted_at IS NULL`, vmName).Scan(&oe, &sg, &active, &stamp)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if active != operationID || oe != ownerEpoch || sg != expectedSpecGen || stamp != createdAt {
			return false, nil
		}
		var resourceKind, resourceID, kind, hash string
		err = tx.QueryRowContext(ctx, `SELECT resource_kind, resource_id, operation_kind, request_hash FROM operations WHERE id = ? AND deleted_at IS NULL`, operationID).Scan(&resourceKind, &resourceID, &kind, &hash)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if resourceKind != "vm" || resourceID != vmName || kind != string(OpDeviceDetach) || hash != NICDetachRequestHash(vmName, f.MAC) {
			return false, nil
		}
		var terminal int
		err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_steps WHERE operation_id = ? AND owner_epoch = ? AND step_name IN ('completed','failed','cancelled','superseded')`, operationID, ownerEpoch).Scan(&terminal)
		return terminal == 0, err
	}
	stmts := []Statement{
		{SQL: vmOperationClearSQL, Params: []interface{}{now, vmName, operationID, ownerEpoch, expectedSpecGen}},
		operationStepInsertStatement(operationID, ownerEpoch, OpStepCompleted, string(raw), nowRFC3339(), now, nil),
	}
	return c.ExecuteBatchGuarded(ctx, guard, stmts)
}

// DetachedNICMACs recognizes only successful detaches bound to this incarnation.
// Reaped headers AND steps remain evidence. Admission and failed operations are
// not successful swaps. A completed legacy record without binding is ambiguous.
func DetachedNICMACs(ctx context.Context, c *Client, vmName string, macs []string) (map[string]bool, error) {
	vm, err := GetVM(ctx, c, vmName)
	if err != nil {
		return nil, err
	}
	if vm == nil || vm.CreatedAt == "" {
		return nil, fmt.Errorf("NIC provenance unavailable for VM %q", vmName)
	}
	rows, err := c.Query(ctx, `SELECT o.id, o.request_hash, s.owner_epoch, s.step_name, s.facts FROM operations o JOIN operation_steps s ON s.operation_id = o.id WHERE o.resource_kind = 'vm' AND o.resource_id = ? AND o.operation_kind = ?`, vmName, string(OpDeviceDetach))
	if err != nil {
		return nil, err
	}
	type key struct {
		id    string
		epoch int64
	}
	type history struct {
		hash  string
		names []string
		facts string
	}
	histories := map[key]*history{}
	requested := map[string]string{}
	for _, mac := range macs {
		requested[NICDetachRequestHash(vmName, mac)] = strings.ToLower(mac)
	}
	for _, row := range rows {
		hash := row.String("request_hash")
		if _, ok := requested[hash]; !ok {
			continue
		}
		k := key{row.String("id"), row.Int64("owner_epoch")}
		h := histories[k]
		if h == nil {
			h = &history{hash: hash}
			histories[k] = h
		}
		h.names = append(h.names, row.String("step_name"))
		if row.String("step_name") == OpStepCompleted {
			h.facts = row.String("facts")
		}
	}
	out, ambiguous := map[string]bool{}, map[string]bool{}
	for k, h := range histories {
		state, faulted := ReduceOperationState(OpDeviceDetach, h.names)
		if state != OpStepCompleted {
			continue
		}
		mac := requested[h.hash]
		if faulted {
			return nil, fmt.Errorf("NIC provenance conflict for VM %q MAC %s operation %s", vmName, mac, k.id)
		}
		if h.facts == "" {
			ambiguous[mac] = true
			continue
		}
		f, err := decodeNICDetachCompletion(h.facts)
		if err != nil || f.OwnerEpoch != k.epoch || f.MAC != mac {
			return nil, fmt.Errorf("invalid NIC provenance for VM %q MAC %s operation %s: %v", vmName, mac, k.id, err)
		}
		if f.VMCreatedAt == vm.CreatedAt {
			out[mac] = true
		}
	}
	for mac := range ambiguous {
		if !out[mac] {
			return nil, fmt.Errorf("unresolved NIC provenance for VM %q MAC %s: completed legacy detach lacks incarnation evidence; reconcile the intended NIC model before regeneration", vmName, mac)
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
