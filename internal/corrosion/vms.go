package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// encodeSGs turns a list of security-group names into JSON (or empty
// string when the list is nil/empty so SQLite stores NULL via the
// caller's COALESCE).
func encodeSGs(sgs []string) (string, error) {
	if len(sgs) == 0 {
		return "", nil
	}
	b, err := json.Marshal(sgs)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodeSecurityGroups decodes a stored security_groups column (the JSON list
// NICRecord.SecurityGroups carries verbatim); empty or invalid returns nil.
func DecodeSecurityGroups(raw string) []string { return decodeSGs(raw) }

// decodeSGs is the inverse — empty string or invalid JSON returns nil.
func decodeSGs(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// VMRecord represents a VM in corrosion state.
type VMRecord struct {
	Name        string
	StackName   string
	HostName    string
	Spec        string // JSON blob
	State       string
	StateDetail string
	CPUActual   int
	MemActual   int
	// Project is the tenancy bucket. Empty → "_default".
	Project   string
	CreatedAt string
	UpdatedAt string
	// IsTemplate marks a VM that can't start; its disks are immutable clone
	// sources (Proxmox-style template).
	IsTemplate bool
	// PendingActionID links a state='pending' transition to the
	// runtime_action_proofs row authorizing the start (split-brain hardening,
	// v38). Empty when no proof-gated action is in flight.
	PendingActionID string
	// OwnerEpoch, SpecGeneration, and ActiveOperationID are the v41 F1 operation-
	// protocol columns: OwnerEpoch bumps on every ownership transfer (ABA-proof
	// recovery), SpecGeneration bumps on every desired-spec mutation, and
	// ActiveOperationID is the VM-wide mutation barrier (non-empty ⇒ an operation
	// holds the VM). All three are populated by GetVM; SpecGeneration and
	// ActiveOperationID are omitted by BOTH list projections, while OwnerEpoch
	// rides the unpaginated ListVMs read only (not ListVMsPage) — see scanVMRow.
	OwnerEpoch        int64
	SpecGeneration    int64
	ActiveOperationID string
}

// InterfaceRecord represents a VM network interface.
type InterfaceRecord struct {
	VMName      string
	NetworkName string
	Ordinal     int
	MAC         string
	IP          string
	TapDevice   string

	// SecurityGroups is the list of security-group names bound to this
	// NIC. distributed firewall — the firewall reconciler
	// uses these names to render per-NIC nftables chains.
	SecurityGroups []string
}

// DiskRecord represents a VM disk.
type DiskRecord struct {
	VMName        string
	DiskName      string
	HostName      string
	Path          string
	SizeBytes     int64
	BackingImage  string
	StorageType   string
	StorageVolume string
	TargetDev     string // libvirt target dev name (vdb, sdc, etc.)
	// BackingDisk is the source disk path this disk is a linked-clone overlay
	// of (empty for normal/full-clone disks). Used to refcount-guard the
	// source template/snapshot and host-pin local-storage linked clones.
	BackingDisk string
	// Bus is the libvirt disk bus (virtio, scsi, sata, ide, usb). Empty for
	// disks created before v42 (schema default is SQL NULL); the domain
	// generator falls back to its historical bus-inference logic when empty.
	Bus string
	// DeviceKind distinguishes a disk-shaped device from a hostdev-shaped one
	// (e.g. "disk" vs "cdrom"). Defaults to "disk" at both the DB column
	// default and here in Go so callers that don't set it get the historical
	// behavior.
	DeviceKind string
	// DeleteWithVM controls whether the backing file is removed when the VM
	// is deleted (vs. detached-and-kept, e.g. an adopted/foreign disk).
	DeleteWithVM bool
	// ControllerModel is the optional libvirt controller model override for
	// this disk's bus (e.g. "virtio-scsi"). Empty defers to libvirt/domain
	// defaults.
	ControllerModel string
}

// projectOrDefault normalises an empty project string to "_default"
// so existing single-tenant callers don't carry a blank label.
func projectOrDefault(p string) string {
	if p == "" {
		return DefaultProject
	}
	return p
}

// InsertVM creates a new VM record with its interfaces and disks. It is
// InsertVMWithHardware with no NIC/PCI-intent rows and adopt=false — kept as a
// separate, unchanged-signature entry point so the ~350 existing fixture-only
// callers across the tree (tests that just need a VM row to exist) don't need
// a mechanical signature-widening edit for a hardware-table concern they don't
// exercise. Its real producer-path callers (Clone/import/promote/live-restore)
// pass no hardware here even though they may have written real vm_interfaces
// rows elsewhere, so adopt=false leaves hardware_adoption_state at its schema
// default 'pending' for the Phase-6 backfill audit to reconcile.
func InsertVM(ctx context.Context, c *Client, vm VMRecord, ifaces []InterfaceRecord, disks []DiskRecord) error {
	return InsertVMWithHardware(ctx, c, vm, ifaces, disks, nil, nil, false)
}

// InsertVMWithHardware is InsertVM extended to also write the v42 typed-hardware
// tables (vm_nics, vm_pci_intent) and, when adopt is true, set the VM's
// hardware-adoption state to "adopted" — all in the SAME atomic batch as the
// vms/vm_interfaces/vm_disks inserts. CreateVM passes adopt=true: it has just
// recorded this VM's complete hardware (possibly an empty set, which for a VM
// with no NICs and no PCI devices IS the complete/accurate set) in this same
// transaction, so there is nothing left for the backfill audit to reconcile.
// Every other caller passes adopt=false and leaves hardware_adoption_state at
// its schema default 'pending', since it either supplies no hardware at all
// (the bare InsertVM wrapper) or is a producer path whose hardware this call
// doesn't fully account for — the Phase-6 backfill audit reconciles those.
//
// The vm_nics/vm_pci_intent statements reuse the EXACT shapes UpsertNIC/
// UpsertPCIIntent already register (see hardware.go), and the adoption update
// reuses SetHardwareAdoptionState's exact UPDATE shape — no new replicated
// statement shape is introduced.
func InsertVMWithHardware(ctx context.Context, c *Client, vm VMRecord, ifaces []InterfaceRecord, disks []DiskRecord, nics []NICRecord, pciIntents []PCIIntentRecord, adopt bool) error {
	now := nowRFC3339Nano() // created_at — fresh incarnation stamp (see nowRFC3339Nano)
	uts := c.NowTS()        // updated_at (monotonic LWW key)

	stmts := []Statement{
		// Purge any soft-deleted record with the same name so the INSERT succeeds.
		// full-state-delete-ok: these only drop an ALREADY-tombstoned row right
		// before re-inserting a fresh one — the new row's newer updated_at wins LWW,
		// so there is no cross-node resurrection window. (See the hard-delete guard
		// test; full-state tables must otherwise soft-delete.)
		//
		// The `vm_interfaces` purge is keyed on vm_name ALONE while the NetBox
		// mirror's NIC evidence is keyed (vm_name, mac) — and a re-create's MACs
		// are freshly randomised — so re-creating a VM under a previously-used
		// name takes the old incarnation's interface evidence with it. Bounded,
		// not a leak: the parent VM delete stays proven by NAME (the row below is
		// live under it) and a NetBox VM delete cascades its interfaces away. The
		// cost is a withheld interface delete logged for one sweep. See
		// MirrorEvidence.KnowsNIC.
		{SQL: `DELETE FROM vm_disks WHERE vm_name = ? AND deleted_at IS NOT NULL`, Params: []interface{}{vm.Name}},      // full-state-delete-ok
		{SQL: `DELETE FROM vm_interfaces WHERE vm_name = ? AND deleted_at IS NOT NULL`, Params: []interface{}{vm.Name}}, // full-state-delete-ok
		{SQL: `DELETE FROM vms WHERE name = ? AND deleted_at IS NOT NULL`, Params: []interface{}{vm.Name}},              // full-state-delete-ok
		{
			SQL: `INSERT INTO vms (name, stack_name, host_name, spec, state, state_detail,
				cpu_actual, mem_actual, project, is_template, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{
				vm.Name, vm.StackName, vm.HostName, vm.Spec, vm.State, vm.StateDetail,
				vm.CPUActual, vm.MemActual, projectOrDefault(vm.Project), boolToInt(vm.IsTemplate),
				now, uts,
			},
		},
	}

	for _, iface := range ifaces {
		sgsJSON, err := encodeSGs(iface.SecurityGroups)
		if err != nil {
			return err
		}
		stmts = append(stmts, Statement{
			SQL: `INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, ip, tap_device, security_groups, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{
				iface.VMName, iface.NetworkName, iface.Ordinal, iface.MAC,
				iface.IP, iface.TapDevice, sgsJSON, uts,
			},
		})
	}

	// The disk rows carry their bus from creation, so the startup hardware
	// backfill has nothing to fill for a VM this build created: a row it does
	// not write is a row it cannot write from a stale replica. They use
	// InsertDisk's whole-row shape (diskRowSQL) because the plain create INSERT
	// has no bus column, and a new shape would stall this node's stream to every
	// peer on the previous release. The other v42 columns get exactly what the
	// plain INSERT left them: the column defaults (device_kind 'disk',
	// delete_with_vm 1) and NULL. Tombstoned rows of the name were purged above,
	// so OR REPLACE can meet only a live row with no live VM above it.
	for _, disk := range disks {
		stmts = append(stmts, Statement{
			SQL: diskRowSQL,
			Params: []interface{}{
				disk.VMName, disk.DiskName, disk.HostName, disk.Path, disk.SizeBytes,
				disk.BackingImage, disk.StorageType, disk.StorageVolume, disk.TargetDev, nullIfEmpty(disk.BackingDisk),
				nullIfEmpty(disk.Bus), "disk", 1, nil, uts,
			},
		})
	}

	for _, nic := range nics {
		model := nic.Model
		if model == "" {
			model = "virtio"
		}
		stmts = append(stmts, Statement{
			SQL: `INSERT OR REPLACE INTO vm_nics
			 (vm_name, id, network_name, model, mac, ordinal, ip, tap_device, security_groups, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			Params: []interface{}{
				nic.VMName, nic.ID, nic.NetworkName, model, nic.MAC, nic.Ordinal,
				nullIfEmpty(nic.IP), nullIfEmpty(nic.TapDevice), nullIfEmpty(nic.SecurityGroups), uts,
			},
		})
	}

	for _, in := range pciIntents {
		var exclusiveKey interface{}
		if in.ExclusiveKey != nil {
			exclusiveKey = *in.ExclusiveKey
		}
		stmts = append(stmts, Statement{
			SQL: `INSERT OR REPLACE INTO vm_pci_intent
			 (vm_name, device_id, host_name, selector_kind, selector_payload, exclusive_key, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
			Params: []interface{}{
				in.VMName, in.DeviceID, in.HostName, in.SelectorKind, in.SelectorPayload, exclusiveKey, uts,
			},
		})
	}

	if adopt {
		stmts = append(stmts, Statement{
			SQL:    `UPDATE vms SET hardware_adoption_state = ?, hardware_adoption_error = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`,
			Params: []interface{}{"adopted", nullIfEmpty(""), uts, vm.Name},
		})
	}

	return c.ExecuteBatch(ctx, stmts)
}

// ListVMs returns VMs with optional filters.
func ListVMs(ctx context.Context, c *Client, stackName, hostName string) ([]VMRecord, error) {
	sql := `SELECT name, stack_name, host_name, spec, state, state_detail,
		cpu_actual, mem_actual, COALESCE(project, '_default') AS project,
		COALESCE(is_template, 0) AS is_template,
		COALESCE(pending_action_id, '') AS pending_action_id,
		COALESCE(vm_owner_epoch, 0) AS vm_owner_epoch, created_at, updated_at
		FROM vms WHERE deleted_at IS NULL`
	var params []interface{}

	if stackName != "" {
		sql += " AND stack_name = ?"
		params = append(params, stackName)
	}
	if hostName != "" {
		sql += " AND host_name = ?"
		params = append(params, hostName)
	}

	rows, err := c.Query(ctx, sql, params...)
	if err != nil {
		return nil, err
	}

	vms := make([]VMRecord, len(rows))
	for i, r := range rows {
		vms[i] = scanVMRow(r)
	}
	return vms, nil
}

// scanVMRow maps a row from a VM-list projection to a VMRecord. It reads the UNION of the
// columns its callers select, and an absent column reads as a ZERO VALUE, not an error
// (Row.String/Int64 on a missing column) — so a field is only trustworthy on the paths whose
// SELECT actually carries it:
//
//   - pending_action_id: carried by BOTH ListVMs and ListVMsPage. It must be, because
//     grpcapi's anyStrandedPending treats an empty marker on a pending VM as a stranded
//     transfer — an omission here reads as "markerless" and reports a legitimately-minted
//     transfer as stranded (fixed here; previously omitted by both).
//   - vm_owner_epoch: carried by ListVMs ONLY, so OwnerEpoch reads 0 through ListVMsPage.
//     Deliberate: the dual-run detector's index is built from the unpaginated ListVMs and no
//     ListVMsPage consumer reads OwnerEpoch. Anything that starts reading it on the
//     paginated path must add the column there first.
//   - spec_generation / active_operation_id: read by NEITHER list projection. Use GetVM or
//     ListVMsWithActiveOperation.
//
// Adding a field to this scanner therefore means adding its column to every caller whose
// consumers actually read that field.
func scanVMRow(r Row) VMRecord {
	return VMRecord{
		Name:            r.String("name"),
		StackName:       r.String("stack_name"),
		HostName:        r.String("host_name"),
		Spec:            r.String("spec"),
		State:           r.String("state"),
		StateDetail:     r.String("state_detail"),
		CPUActual:       r.Int("cpu_actual"),
		MemActual:       r.Int("mem_actual"),
		Project:         r.String("project"),
		IsTemplate:      r.Int("is_template") == 1,
		PendingActionID: r.String("pending_action_id"),
		// OwnerEpoch rides the list read because the dual-run detector's DB
		// index is built from ListVMs. Omitting it made every epoched running
		// VM read as marker-vs-0 and page a false owner_epoch_mismatch — a bug
		// the LAB caught, not the unit tests: the fixture VMs happened to be
		// epoch 0, so marker 0 == "missing epoch" 0 and nothing fired.
		OwnerEpoch: r.Int64("vm_owner_epoch"),
		CreatedAt:  r.String("created_at"),
		UpdatedAt:  r.String("updated_at"),
	}
}

// ListVMsPage returns up to limit VMs, ordered by name, whose name sorts strictly
// after afterName — keyset pagination for ListVMs. name is the primary key (unique
// cluster-wide) so it is a stable cursor. afterName "" starts at the beginning;
// limit <= 0 returns all matching rows (unpaginated).
func ListVMsPage(ctx context.Context, c *Client, stackName, hostName, afterName string, limit int) ([]VMRecord, error) {
	sql := `SELECT name, stack_name, host_name, spec, state, state_detail,
		cpu_actual, mem_actual, COALESCE(project, '_default') AS project,
		COALESCE(is_template, 0) AS is_template,
		COALESCE(pending_action_id, '') AS pending_action_id, created_at, updated_at
		FROM vms WHERE deleted_at IS NULL`
	var params []interface{}
	if stackName != "" {
		sql += " AND stack_name = ?"
		params = append(params, stackName)
	}
	if hostName != "" {
		sql += " AND host_name = ?"
		params = append(params, hostName)
	}
	if afterName != "" {
		sql += " AND name > ?"
		params = append(params, afterName)
	}
	sql += " ORDER BY name"
	if limit > 0 {
		sql += " LIMIT ?"
		params = append(params, limit)
	}
	rows, err := c.Query(ctx, sql, params...)
	if err != nil {
		return nil, err
	}
	vms := make([]VMRecord, len(rows))
	for i, r := range rows {
		vms[i] = scanVMRow(r)
	}
	return vms, nil
}

// GetVM returns a single VM by name.
func GetVM(ctx context.Context, c *Client, name string) (*VMRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, stack_name, host_name, spec, state, state_detail,
			cpu_actual, mem_actual, COALESCE(project, '_default') AS project,
			COALESCE(is_template, 0) AS is_template,
			COALESCE(pending_action_id, '') AS pending_action_id,
			vm_owner_epoch, spec_generation, active_operation_id, created_at, updated_at
		 FROM vms WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	r := rows[0]
	return &VMRecord{
		Name:              r.String("name"),
		StackName:         r.String("stack_name"),
		HostName:          r.String("host_name"),
		Spec:              r.String("spec"),
		State:             r.String("state"),
		StateDetail:       r.String("state_detail"),
		CPUActual:         r.Int("cpu_actual"),
		MemActual:         r.Int("mem_actual"),
		Project:           r.String("project"),
		IsTemplate:        r.Int("is_template") == 1,
		PendingActionID:   r.String("pending_action_id"),
		OwnerEpoch:        r.Int64("vm_owner_epoch"),
		SpecGeneration:    r.Int64("spec_generation"),
		ActiveOperationID: r.String("active_operation_id"),
		CreatedAt:         r.String("created_at"),
		UpdatedAt:         r.String("updated_at"),
	}, nil
}

// GetDeletedVM returns a soft-deleted VM by name, or nil if no deleted record
// exists. It carries the spec because a caller resuming an interrupted teardown
// needs the tombstone's firmware identity (its UUID) to free the state that
// teardown left behind — see CutoverVM.
func GetDeletedVM(ctx context.Context, c *Client, name string) (*VMRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, host_name, state, spec FROM vms WHERE name = ? AND deleted_at IS NOT NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &VMRecord{
		Name:     r.String("name"),
		HostName: r.String("host_name"),
		State:    r.String("state"),
		Spec:     r.String("spec"),
	}, nil
}

// HasVMRecords reports whether the local `vms` table holds ANY row, TOMBSTONES
// INCLUDED.
//
// It is the difference between "this cluster has no VMs" and "this database has
// not been read yet". ListVMs filters tombstones and so answers the same empty
// list to both, but a VM that was deleted leaves its soft-deleted row behind
// (nothing prunes vms tombstones), while a node hydrating after a database loss
// or a fresh join has no row of any kind. Consumers that must not act on an
// empty read — the NetBox inventory mirror's delete half — use this as the
// corroborating evidence that the empty answer is a real one.
//
// The MIRROR'S CORRECTNESS THEREFORE DEPENDS ON `vms` TOMBSTONES SURVIVING.
// Retiring the last VM in a cluster is told apart from a database that has not
// hydrated by nothing else, and the same evidence keyed per name
// (ReadMirrorEvidence) is what authorizes every individual delete.
//
// THREE THINGS IN THE TREE TAKE A `vms` ROW AWAY FROM A NAME, and each one is
// safe only because the consumer fails CLOSED on missing evidence — withholding
// the removal, never performing it:
//
//   - the same-name re-create cleanup in InsertVMWithHardware (the
//     `full-state-delete-ok` DELETEs above the INSERT) drops the tombstone, but
//     leaves a LIVE row under the same name in the same batch, so the name never
//     stops being accounted for.
//   - DiscardReplicatedStateForReseed TRUNCATES `vms` outright, tombstones
//     included — `vms` is in tableNames and not in reseedKeepTables. Reseed is
//     self-consistent because the state dump merged straight afterwards carries
//     tombstones too (dumpTable is `SELECT *`, with no deleted_at predicate),
//     and the window in between is exactly what this function reports as "no
//     records".
//   - RenameVM is an `UPDATE vms SET name = ?`, so after it NO row of any kind
//     exists at the old name. The mirror is identity-keyed rather than
//     name-keyed, so a rename keeps the same NetBox object and computes no
//     delete; if one is ever computed against the old name it is withheld.
//
// Only the first is visible to the hard-delete tripwire, which regexes
// `DELETE FROM <literal table>` (hard_delete_guard_test.go): the reseed names
// its table through a variable, so the pattern finds no table there, and an
// UPDATE is not a DELETE at all. The tripwire is not where this invariant is
// enforced — the fail-closed consumer is.
//
// A general tombstone GC would NOT join that list: it would take the evidence
// away while leaving the NetBox objects behind, with no live row and no merge
// behind it, and the mirror would stop being able to distinguish "unhydrated"
// from "deleted" at all.
func HasVMRecords(ctx context.Context, c *Client) (bool, error) {
	rows, err := c.Query(ctx, `SELECT name FROM vms LIMIT 1`)
	if err != nil {
		return false, fmt.Errorf("check for local VM records: %w", err)
	}
	return len(rows) > 0, nil
}

// GetVMInterfaces returns all interfaces for a VM.
func GetVMInterfaces(ctx context.Context, c *Client, vmName string) ([]InterfaceRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, network_name, ordinal, mac, ip, tap_device,
		        COALESCE(security_groups, '') AS security_groups
		 FROM vm_interfaces WHERE vm_name = ? AND deleted_at IS NULL
		 ORDER BY ordinal`, vmName)
	if err != nil {
		return nil, err
	}

	ifaces := make([]InterfaceRecord, len(rows))
	for i, r := range rows {
		ifaces[i] = InterfaceRecord{
			VMName:         r.String("vm_name"),
			NetworkName:    r.String("network_name"),
			Ordinal:        r.Int("ordinal"),
			MAC:            r.String("mac"),
			IP:             r.String("ip"),
			TapDevice:      r.String("tap_device"),
			SecurityGroups: decodeSGs(r.String("security_groups")),
		}
	}
	return ifaces, nil
}

// ListVMInterfacesByHost returns every active NIC on this host. Used
// by the firewall reconciler to bind security groups to taps; cheaper
// than walking VMs one by one.
func ListVMInterfacesByHost(ctx context.Context, c *Client, hostName string) ([]InterfaceRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT i.vm_name, i.network_name, i.ordinal, i.mac, i.ip, i.tap_device,
		        COALESCE(i.security_groups, '') AS security_groups
		 FROM vm_interfaces i
		 JOIN vms v ON v.name = i.vm_name
		 WHERE v.host_name = ? AND v.deleted_at IS NULL AND i.deleted_at IS NULL`,
		hostName)
	if err != nil {
		return nil, err
	}
	out := make([]InterfaceRecord, len(rows))
	for i, r := range rows {
		out[i] = InterfaceRecord{
			VMName:         r.String("vm_name"),
			NetworkName:    r.String("network_name"),
			Ordinal:        r.Int("ordinal"),
			MAC:            r.String("mac"),
			IP:             r.String("ip"),
			TapDevice:      r.String("tap_device"),
			SecurityGroups: decodeSGs(r.String("security_groups")),
		}
	}
	return out, nil
}

// SetInterfaceSecurityGroups updates the SG binding on one VM NIC,
// keyed by (vm_name, network_name). Used by the BindSecurityGroups
// RPC for runtime mutations without redeploying the VM.
func SetInterfaceSecurityGroups(ctx context.Context, c *Client, vmName, networkName string, sgs []string) error {
	now := c.NowTS()
	sgsJSON, err := encodeSGs(sgs)
	if err != nil {
		return err
	}
	return c.Execute(ctx,
		`UPDATE vm_interfaces SET security_groups = ?, updated_at = ?
		 WHERE vm_name = ? AND network_name = ? AND deleted_at IS NULL`,
		sgsJSON, now, vmName, networkName)
}

// TombstonedDisksReferencingPath is DisksReferencingPath over SOFT-DELETED
// rows: a disk detached from its VM, or kept when the VM was deleted, still
// names the VM (and so the project) whose file it is.
func TombstonedDisksReferencingPath(ctx context.Context, c *Client, path string) ([]DiskRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, disk_name, host_name, path
		 FROM vm_disks
		 WHERE (path = ? OR backing_image = ? OR backing_disk = ?) AND deleted_at IS NOT NULL`,
		path, path, path)
	if err != nil {
		return nil, err
	}
	out := make([]DiskRecord, len(rows))
	for i, r := range rows {
		out[i] = DiskRecord{VMName: r.String("vm_name"), DiskName: r.String("disk_name"), HostName: r.String("host_name"), Path: r.String("path")}
	}
	return out, nil
}

// GetDeletedVMDisks returns a VM's SOFT-DELETED disk records. A teardown that
// tombstoned a VM and then failed before freeing its volumes leaves them
// recorded only here, and they still have to be freed — GetVMDisks hides them.
func GetDeletedVMDisks(ctx context.Context, c *Client, vmName string) ([]DiskRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, disk_name, host_name, path, size_bytes,
			backing_image, storage_type, storage_volume, target_dev,
			COALESCE(backing_disk, '') AS backing_disk,
			COALESCE(bus, '') AS bus,
			COALESCE(device_kind, 'disk') AS device_kind,
			COALESCE(delete_with_vm, 1) AS delete_with_vm,
			COALESCE(controller_model, '') AS controller_model
		 FROM vm_disks WHERE vm_name = ? AND deleted_at IS NOT NULL`, vmName)
	if err != nil {
		return nil, err
	}
	disks := make([]DiskRecord, len(rows))
	for i, r := range rows {
		disks[i] = DiskRecord{
			VMName:          r.String("vm_name"),
			DiskName:        r.String("disk_name"),
			HostName:        r.String("host_name"),
			Path:            r.String("path"),
			SizeBytes:       r.Int64("size_bytes"),
			BackingImage:    r.String("backing_image"),
			StorageType:     r.String("storage_type"),
			StorageVolume:   r.String("storage_volume"),
			TargetDev:       r.String("target_dev"),
			BackingDisk:     r.String("backing_disk"),
			Bus:             r.String("bus"),
			DeviceKind:      r.String("device_kind"),
			DeleteWithVM:    r.Int("delete_with_vm") == 1,
			ControllerModel: r.String("controller_model"),
		}
	}
	return disks, nil
}

// SoftDeletedDisk is a soft-deleted vm_disks row with the wall time it was
// soft-deleted at.
type SoftDeletedDisk struct {
	DiskRecord
	DeletedAt string // RFC3339 wall clock of the host that wrote the tombstone
}

// GetSoftDeletedVMDisks is GetDeletedVMDisks with each row's deleted_at.
//
// While the VM is live these rows are its DETACHED disks: detach soft-deletes
// the row and keeps the file, and a migration repoints only live rows
// (vmDiskHostMoveSQL), so a detached row still names the host the file is on.
// deleted_at is what tells this incarnation's detaches from a previous VM of
// the same name, while the VM is live: InsertVMWithHardware purges a name's
// tombstoned rows, but BeginVMCreateOperation re-stamps them with deleted_at
// equal to the new VM's created_at. Once the VM itself is tombstoned the
// stamp is gone too — the tombstone re-stamps every disk row of the name.
func GetSoftDeletedVMDisks(ctx context.Context, c *Client, vmName string) ([]SoftDeletedDisk, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, disk_name, host_name, path, storage_type, storage_volume,
			COALESCE(delete_with_vm, 1) AS delete_with_vm,
			COALESCE(deleted_at, '') AS deleted_at
		 FROM vm_disks WHERE vm_name = ? AND deleted_at IS NOT NULL`, vmName)
	if err != nil {
		return nil, err
	}
	out := make([]SoftDeletedDisk, len(rows))
	for i, r := range rows {
		out[i] = SoftDeletedDisk{
			DiskRecord: DiskRecord{
				VMName:        r.String("vm_name"),
				DiskName:      r.String("disk_name"),
				HostName:      r.String("host_name"),
				Path:          r.String("path"),
				StorageType:   r.String("storage_type"),
				StorageVolume: r.String("storage_volume"),
				DeleteWithVM:  r.Int("delete_with_vm") == 1,
			},
			DeletedAt: r.String("deleted_at"),
		}
	}
	return out, nil
}

// GetTombstonedVMCreatedAt returns the created_at of name's TOMBSTONED vms row
// — the incarnation a delete removed — or "" when there is none (no row, or a
// live one).
func GetTombstonedVMCreatedAt(ctx context.Context, c *Client, name string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT created_at FROM vms WHERE name = ? AND deleted_at IS NOT NULL`, name)
	if err != nil || len(rows) == 0 {
		return "", err
	}
	return rows[0].String("created_at"), nil
}

// GetVMDisks returns all disks for a VM.
func GetVMDisks(ctx context.Context, c *Client, vmName string) ([]DiskRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, disk_name, host_name, path, size_bytes,
			backing_image, storage_type, storage_volume, target_dev,
			COALESCE(backing_disk, '') AS backing_disk,
			COALESCE(bus, '') AS bus,
			COALESCE(device_kind, 'disk') AS device_kind,
			COALESCE(delete_with_vm, 1) AS delete_with_vm,
			COALESCE(controller_model, '') AS controller_model
		 FROM vm_disks WHERE vm_name = ? AND deleted_at IS NULL`, vmName)
	if err != nil {
		return nil, err
	}

	disks := make([]DiskRecord, len(rows))
	for i, r := range rows {
		disks[i] = DiskRecord{
			VMName:          r.String("vm_name"),
			DiskName:        r.String("disk_name"),
			HostName:        r.String("host_name"),
			Path:            r.String("path"),
			SizeBytes:       r.Int64("size_bytes"),
			BackingImage:    r.String("backing_image"),
			StorageType:     r.String("storage_type"),
			StorageVolume:   r.String("storage_volume"),
			TargetDev:       r.String("target_dev"),
			BackingDisk:     r.String("backing_disk"),
			Bus:             r.String("bus"),
			DeviceKind:      r.String("device_kind"),
			DeleteWithVM:    r.Int("delete_with_vm") == 1,
			ControllerModel: r.String("controller_model"),
		}
	}
	return disks, nil
}

// SetVMTemplate flips a VM's is_template flag (used by ConvertToTemplate and
// its revert).
func SetVMTemplate(ctx context.Context, c *Client, name string, isTemplate bool) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vms SET is_template = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`,
		boolToInt(isTemplate), now, name)
}

// SetHardwareAdoptionState updates a VM's hardware-adoption state and, when
// blocked, the human-readable reason. errReason "" clears any prior reason
// (e.g. on a transition back to a non-blocked state).
func SetHardwareAdoptionState(ctx context.Context, c *Client, vmName, state, errReason string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vms SET hardware_adoption_state = ?, hardware_adoption_error = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`,
		state, nullIfEmpty(errReason), now, vmName)
}

// GetHardwareAdoptionState returns a VM's hardware-adoption state and error
// reason (COALESCEd to "" when unset).
func GetHardwareAdoptionState(ctx context.Context, c *Client, vmName string) (state, errReason string, err error) {
	rows, qerr := c.Query(ctx,
		`SELECT hardware_adoption_state,
			COALESCE(hardware_adoption_error, '') AS hardware_adoption_error
		 FROM vms WHERE name = ? AND deleted_at IS NULL`, vmName)
	if qerr != nil {
		return "", "", qerr
	}
	if len(rows) == 0 {
		return "", "", nil
	}
	r := rows[0]
	return r.String("hardware_adoption_state"), r.String("hardware_adoption_error"), nil
}

// LinkedCloneNames returns the names of VMs that have a disk which is a
// linked-clone overlay backed by backingPath. Used to refuse deleting a
// template/snapshot disk that still backs live clones.
func LinkedCloneNames(ctx context.Context, c *Client, backingPath string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT DISTINCT vm_name FROM vm_disks WHERE backing_disk = ? AND deleted_at IS NULL`,
		backingPath)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("vm_name"))
	}
	return out, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nullIfEmpty returns nil for an empty string so the column stores SQL NULL
// (keeps COALESCE/refcount queries clean) rather than an empty string.
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// DisksReferencingPath returns every non-deleted disk record that references
// path — either as its own disk file (path) or as a backing image
// (backing_image). It is used to guard a source-disk delete after a volume
// move: a file is safe to remove only if no other disk still depends on it
// (a shared disk file, or a base/backing image other overlays read from).
func DisksReferencingPath(ctx context.Context, c *Client, path string) ([]DiskRecord, error) {
	// Three ways a row can depend on this path, and all three have to be here:
	// it IS the disk, it is the disk's backing_image (full-clone provenance), or
	// it is the disk's backing_disk (a linked-clone overlay). backing_disk was
	// missing, so a base whose only referrers were linked clones read as
	// unreferenced and its file was deleted — destroying every overlay's chain
	// at once, unrecoverably. LinkedCloneNames queries backing_disk correctly,
	// which is what this guard was meant to be consulting.
	rows, err := c.Query(ctx,
		`SELECT vm_name, disk_name, host_name, path, size_bytes,
			backing_image, storage_type, storage_volume, target_dev, backing_disk
		 FROM vm_disks
		 WHERE (path = ? OR backing_image = ? OR backing_disk = ?) AND deleted_at IS NULL`,
		path, path, path)
	if err != nil {
		return nil, err
	}
	disks := make([]DiskRecord, len(rows))
	for i, r := range rows {
		disks[i] = DiskRecord{
			VMName:        r.String("vm_name"),
			DiskName:      r.String("disk_name"),
			HostName:      r.String("host_name"),
			Path:          r.String("path"),
			SizeBytes:     r.Int64("size_bytes"),
			BackingImage:  r.String("backing_image"),
			StorageType:   r.String("storage_type"),
			StorageVolume: r.String("storage_volume"),
			TargetDev:     r.String("target_dev"),
			BackingDisk:   r.String("backing_disk"),
		}
	}
	return disks, nil
}

// DisksReferencingPathSuffix returns every non-deleted disk record whose
// path, backing_image or backing_disk ends in "/"+rel. It finds references to
// a file in a pool another host mounts at a different directory: the caller
// then decides, per row, whether the prefix is that host's mount of the same
// pool. rel is matched literally (LIKE wildcards in it are escaped).
func DisksReferencingPathSuffix(ctx context.Context, c *Client, rel string) ([]DiskRecord, error) {
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace("/" + rel)
	pat := "%" + esc
	rows, err := c.Query(ctx,
		`SELECT vm_name, disk_name, host_name, path, size_bytes,
			backing_image, storage_type, storage_volume, target_dev, backing_disk
		 FROM vm_disks
		 WHERE (path LIKE ? ESCAPE '\' OR backing_image LIKE ? ESCAPE '\' OR backing_disk LIKE ? ESCAPE '\')
		   AND deleted_at IS NULL`,
		pat, pat, pat)
	if err != nil {
		return nil, err
	}
	disks := make([]DiskRecord, len(rows))
	for i, r := range rows {
		disks[i] = DiskRecord{
			VMName:        r.String("vm_name"),
			DiskName:      r.String("disk_name"),
			HostName:      r.String("host_name"),
			Path:          r.String("path"),
			SizeBytes:     r.Int64("size_bytes"),
			BackingImage:  r.String("backing_image"),
			StorageType:   r.String("storage_type"),
			StorageVolume: r.String("storage_volume"),
			TargetDev:     r.String("target_dev"),
			BackingDisk:   r.String("backing_disk"),
		}
	}
	return disks, nil
}

// CountVMsByHost returns the number of active VMs per host in a single query.
func CountVMsByHost(ctx context.Context, c *Client) (map[string]int, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, COUNT(*) as cnt FROM vms WHERE deleted_at IS NULL GROUP BY host_name`)
	if err != nil {
		return nil, err
	}
	m := make(map[string]int, len(rows))
	for _, r := range rows {
		m[r.String("host_name")] = r.Int("cnt")
	}
	return m, nil
}

// HostResourceUsage holds aggregated CPU, memory, and disk allocated to VMs on a host.
type HostResourceUsage struct {
	CpuUsed    int
	MemUsedMiB int
	// DiskAllocatedGiB is the DECLARED size of every disk of every VM on the
	// host, stopped VMs included — what has been promised, not what is on disk.
	// Thin provisioning lets it exceed the host's capacity, so it is never a
	// numerator for a statfs total (colonelpanik/litevirt#142).
	DiskAllocatedGiB int
	// VMCount is how many RUNNING VMs the host carries. Capacity policy charges
	// a per-VM qemu overhead on top of configured guest memory, so the count is
	// part of usage, not a display detail.
	VMCount int
}

// SumVMResourcesByHost returns per-host CPU, memory, and disk totals for running VMs.
func SumVMResourcesByHost(ctx context.Context, c *Client) (map[string]HostResourceUsage, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, COALESCE(SUM(cpu_actual),0) as cpu, COALESCE(SUM(mem_actual),0) as mem,
		        COUNT(*) as vm_count
		 FROM vms WHERE deleted_at IS NULL AND state = 'running' GROUP BY host_name`)
	if err != nil {
		return nil, err
	}
	m := make(map[string]HostResourceUsage, len(rows))
	for _, r := range rows {
		m[r.String("host_name")] = HostResourceUsage{
			CpuUsed:    r.Int("cpu"),
			MemUsedMiB: r.Int("mem"),
			VMCount:    r.Int("vm_count"),
		}
	}

	// Sum disk allocations per host (all VMs, not just running — disk is allocated regardless of state).
	diskRows, err := c.Query(ctx,
		`SELECT host_name, COALESCE(SUM(size_bytes),0) as disk_bytes
		 FROM vm_disks WHERE deleted_at IS NULL GROUP BY host_name`)
	if err == nil {
		for _, r := range diskRows {
			host := r.String("host_name")
			usage := m[host]
			usage.DiskAllocatedGiB = r.Int("disk_bytes") / (1024 * 1024 * 1024)
			m[host] = usage
		}
	}
	return m, nil
}

// VMStateCount holds per-state VM counts.
type VMStateCount struct {
	Total, Running, Stopped, Error int
}

// CountVMsByStack returns per-stack VM counts and state breakdown in a single query.
func CountVMsByStack(ctx context.Context, c *Client) (map[string]VMStateCount, error) {
	rows, err := c.Query(ctx,
		`SELECT stack_name, state, COUNT(*) as cnt FROM vms
		 WHERE deleted_at IS NULL AND stack_name != ''
		 GROUP BY stack_name, state`)
	if err != nil {
		return nil, err
	}
	m := make(map[string]VMStateCount)
	for _, r := range rows {
		stack := r.String("stack_name")
		sc := m[stack]
		cnt := r.Int("cnt")
		sc.Total += cnt
		switch r.String("state") {
		case "running":
			sc.Running += cnt
		case "stopped":
			sc.Stopped += cnt
		case "error":
			sc.Error += cnt
		}
		m[stack] = sc
	}
	return m, nil
}

// BatchGetVMInterfaces returns interfaces for all active VMs in a single query,
// keyed by vm_name.
func BatchGetVMInterfaces(ctx context.Context, c *Client) (map[string][]InterfaceRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT i.vm_name, i.network_name, i.ordinal, i.mac, i.ip, i.tap_device
		 FROM vm_interfaces i
		 INNER JOIN vms v ON v.name = i.vm_name AND v.deleted_at IS NULL
		 WHERE i.deleted_at IS NULL
		 ORDER BY i.vm_name, i.ordinal`)
	if err != nil {
		return nil, err
	}
	m := make(map[string][]InterfaceRecord)
	for _, r := range rows {
		vmName := r.String("vm_name")
		m[vmName] = append(m[vmName], InterfaceRecord{
			VMName:      vmName,
			NetworkName: r.String("network_name"),
			Ordinal:     r.Int("ordinal"),
			MAC:         r.String("mac"),
			IP:          r.String("ip"),
			TapDevice:   r.String("tap_device"),
		})
	}
	return m, nil
}

// CountVMsByNetwork returns the number of active VMs per network in a single query.
func CountVMsByNetwork(ctx context.Context, c *Client) (map[string]int, error) {
	rows, err := c.Query(ctx,
		`SELECT i.network_name, COUNT(DISTINCT i.vm_name) as cnt
		 FROM vm_interfaces i
		 INNER JOIN vms v ON v.name = i.vm_name AND v.deleted_at IS NULL
		 WHERE i.deleted_at IS NULL
		 GROUP BY i.network_name`)
	if err != nil {
		return nil, err
	}
	m := make(map[string]int, len(rows))
	for _, r := range rows {
		m[r.String("network_name")] = r.Int("cnt")
	}
	return m, nil
}

// The VM state writers' statements. Their WHERE is the name (and, for the
// epoch form, the ownership generation) and nothing else — that is their wire
// shape, and a receiver on the previous release recognises no other. What makes
// them tombstone-safe is their ledger disposition, DispLiveRowUpdate: the origin
// and every receiver apply them through the `AND deleted_at IS NULL` form (see
// live_row_update.go).
const (
	vmStateUpdateSQL  = `UPDATE vms SET state = ?, state_detail = ?, updated_at = ? WHERE name = ?`
	vmStateAtEpochSQL = `UPDATE vms SET state = ?, state_detail = ?, updated_at = ? WHERE name = ? AND vm_owner_epoch = ?`
	vmHostStateSQL    = `UPDATE vms SET host_name = ?, state = ?, state_detail = '', updated_at = ? WHERE name = ?`
)

// UpdateVMState changes a VM's state.
func UpdateVMState(ctx context.Context, c *Client, name, state, detail string) error {
	now := c.NowTS()
	return c.Execute(ctx, vmStateUpdateSQL, state, detail, now, name)
}

// UpdateVMStateAtEpoch is UpdateVMState carrying the ownership generation the
// caller decided against. The epoch is part of the WHERE clause, so the
// statement REPLICATES with its own precondition: a peer whose row has moved
// to a newer generation matches nothing and keeps its state.
//
// This is what stops the rejoin fight observed live on 2026-08-01. A host that
// was down comes back with a stale replica, its reconciler syncs "this VM I own
// is not running" — and the name-only UPDATE that write used to be stomped the
// real owner's row on every node, flapping state until a manual repair-owner.
// The write still lands LOCALLY on the stale node (it is true of that node's
// own view, and its row is at the old generation); it simply cannot travel.
func UpdateVMStateAtEpoch(ctx context.Context, c *Client, name, state, detail string, expectedEpoch int64) error {
	now := c.NowTS()
	return c.Execute(ctx, vmStateAtEpochSQL, state, detail, now, name, expectedEpoch)
}

// UpdateVMStateStrict is UpdateVMState that reports a zero-row update as
// ErrNoRowsAffected instead of a silent success. Use it where the write's success
// GATES a subsequent action (an event, audit, LB refresh, hook, or ownership
// handoff) so a vanished/renamed VM row cannot be mistaken for a completed write.
func UpdateVMStateStrict(ctx context.Context, c *Client, name, state, detail string) error {
	now := c.NowTS()
	n, err := c.ExecuteRowsStrict(ctx, vmStateUpdateSQL, state, detail, now, name)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// UpdateVMHost moves a VM's host assignment and state after migration.
func UpdateVMHost(ctx context.Context, c *Client, name, hostName, state string) error {
	now := c.NowTS()
	return c.Execute(ctx, vmHostStateSQL, hostName, state, now, name)
}

// TransferVMOwner is the Phase 4 ownership-transition primitive: one guarded
// transaction that CASes on the expected owner epoch, increments it, and moves
// host/state together. A writer holding a stale expected epoch — a rejoined
// node still believing it owns the VM, a coordinator whose decision was
// superseded — changes nothing and gets ErrNoRowsAffected, instead of fighting
// the real owner with equal-timestamp LWW writes the resolver can only surface
// as an unresolved tie. Every genuine transfer (reschedule, promote, migrate,
// repair, owner-assert re-key, drain) routes through here; UpdateVMHost remains
// for same-host state changes only.
func TransferVMOwner(ctx context.Context, c *Client, name, hostName, state string, expectedEpoch int64) error {
	now := c.NowTS()
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		var epoch int64
		if err := tx.QueryRow(
			`SELECT vm_owner_epoch FROM vms WHERE name = ? AND deleted_at IS NULL`, name,
		).Scan(&epoch); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return false, err
		}
		return epoch == expectedEpoch, nil
	}, []Statement{{
		SQL: `UPDATE vms
		      SET host_name = ?, state = ?, state_detail = '',
		          vm_owner_epoch = vm_owner_epoch + 1, updated_at = ?
		      WHERE name = ? AND deleted_at IS NULL AND vm_owner_epoch = ?`,
		Params: []interface{}{hostName, state, now, name, expectedEpoch},
	}})
	if err != nil {
		return err
	}
	if !applied {
		return ErrNoRowsAffected
	}
	return nil
}

// TransferVMOwnerWithDisks is TransferVMOwner that moves the VM's disk rows to
// hostName in the same guarded batch. It is for the repairs that re-key a VM
// to the host proven to run it (repair-owner, owner-assert): that host uses the
// disks, so a disk row naming any other host is stale. A cold firmware
// migration commits its handoff through it too: its disks are on shared
// storage, so only their host moves, together with the VM, in one transaction.
func TransferVMOwnerWithDisks(ctx context.Context, c *Client, name, hostName, state string, expectedEpoch int64) error {
	disks, err := GetVMDisks(ctx, c, name)
	if err != nil {
		return err
	}
	now := c.NowTS()
	stmts := []Statement{{
		SQL: `UPDATE vms
		      SET host_name = ?, state = ?, state_detail = '',
		          vm_owner_epoch = vm_owner_epoch + 1, updated_at = ?
		      WHERE name = ? AND deleted_at IS NULL AND vm_owner_epoch = ?`,
		Params: []interface{}{hostName, state, now, name, expectedEpoch},
	}}
	for _, d := range disks {
		if d.HostName == hostName {
			continue
		}
		stmts = append(stmts, Statement{
			SQL:    vmDiskHostMoveSQL,
			Params: []interface{}{hostName, now, name, d.DiskName},
		})
	}
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		var epoch int64
		if err := tx.QueryRow(
			`SELECT vm_owner_epoch FROM vms WHERE name = ? AND deleted_at IS NULL`, name,
		).Scan(&epoch); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return false, err
		}
		return epoch == expectedEpoch, nil
	}, stmts)
	if err != nil {
		return err
	}
	if !applied {
		return ErrNoRowsAffected
	}
	return nil
}

// TransferVMOwnerFresh is TransferVMOwner for completion-style sites that do
// not carry a decision-time epoch: it reads the row and CASes on what it just
// read. The CAS still matters — between the read and the write a concurrent
// transition can land, and this loses cleanly instead of overwriting it.
func TransferVMOwnerFresh(ctx context.Context, c *Client, name, hostName, state string) error {
	vm, err := GetVM(ctx, c, name)
	if err != nil {
		return err
	}
	if vm == nil {
		return ErrNoRowsAffected
	}
	return TransferVMOwner(ctx, c, name, hostName, state, vm.OwnerEpoch)
}

// DeleteVM tombstones a VM and its interfaces/disks, plus the v42 hardware
// tables (vm_nics, vm_pci_intent, vm_pci_realizations) — mirroring the
// vm_interfaces/vm_disks bulk tombstone: vm_name is not the whole PK on any of
// these tables, so the WHERE vm_name = ? bulk form is applied by per-row LWW
// expansion on apply (safe because each statement binds updated_at). This does
// NOT release any host_pci_devices ownership/vfio-unbind lease — that is the
// grpcapi DeleteVM handler's releaseDevices call, out of scope here.
// It emits the AUTHORITY-BEARING tombstone (vmDeleteSQL) — the only VM delete
// shape litevirt emits. See DeleteContainer for why the pre-authority shape is
// receive-only: a peer admits it only while its own row has zero authority, so
// after the owner-epoch backfill it is silently dropped everywhere.
func DeleteVM(ctx context.Context, c *Client, name string) error {
	_, err := DeleteVMReporting(ctx, c, name)
	return err
}

// DeleteVMReporting is DeleteVM that also returns the row it tombstoned, as
// its guard saw it — nil when there was no live row to delete.
func DeleteVMReporting(ctx context.Context, c *Client, name string) (*VMRecord, error) {
	// Absent/already-tombstoned is the idempotent success callers expect; a row
	// still live after every fresh-guard retry means its authority keeps moving
	// under the CAS and the caller must not be told the delete landed.
	var deleted *VMRecord
	outcome, err := retriedDelete(func() (deleteOutcome, error) {
		vm, err := GetVM(ctx, c, name)
		if err != nil {
			return deleteContended, err
		}
		if vm == nil {
			return deleteAbsent, nil
		}
		out, err := deleteVMGuardedFrom(ctx, c, *vm)
		if err == nil && out == deleteApplied {
			deleted = vm
		}
		return out, err
	})
	if err != nil {
		return nil, err
	}
	if err := deleteOutcomeError(outcome, false); err != nil {
		return nil, err
	}
	return deleted, nil
}

// ErrVMIncarnationMismatch means the live row of a VM name is not one the
// caller's delete snapshot covers: another incarnation holds the name, or the
// row has moved past what the deleter saw.
var ErrVMIncarnationMismatch = errors.New("corrosion: the live VM row is not the one the delete saw")

// VMDeleteSnapshot is a VM row as a delete saw it: its incarnation
// (created_at) and the fields that delete's guard binds (vmDeleteMutationGuard).
type VMDeleteSnapshot struct {
	CreatedAt      string
	HostName       string
	OwnerEpoch     int64
	SpecGeneration int64
	IdentityHash   string
}

// SnapshotForDelete is vm as a delete of it sees it.
func SnapshotForDelete(vm VMRecord) VMDeleteSnapshot {
	return VMDeleteSnapshot{
		CreatedAt: vm.CreatedAt, HostName: vm.HostName, OwnerEpoch: vm.OwnerEpoch,
		SpecGeneration: vm.SpecGeneration, IdentityHash: vmCreateIdentityHash(vm),
	}
}

// Covers reports whether row is a copy of the snapshot's row that the delete
// it was taken for kills: the same incarnation, and not ahead of it on any
// authority axis. A row at the snapshot's own epoch and generation must be the
// snapshot's row exactly (host and identity); a row at a lower epoch or
// generation is an older copy of it. A row with a higher epoch (an ownership
// move the deleter had not seen) or a higher generation is not covered: the
// deleter's tombstone, guarded by its own view, would not have killed it.
func (s VMDeleteSnapshot) Covers(row VMRecord) bool {
	if s.CreatedAt == "" || row.CreatedAt != s.CreatedAt {
		return false
	}
	if row.OwnerEpoch > s.OwnerEpoch || row.SpecGeneration > s.SpecGeneration {
		return false
	}
	if row.OwnerEpoch == s.OwnerEpoch && row.SpecGeneration == s.SpecGeneration {
		return row.HostName == s.HostName && vmCreateIdentityHash(row) == s.IdentityHash
	}
	return true
}

// DeleteVMIncarnation is DeleteVM restricted to a row snap covers. It
// tombstones that row and nothing else — a live row snap does not cover is
// ErrVMIncarnationMismatch, and no live row is the idempotent nil. The
// statements are DeleteVM's own, so a receiver applies them exactly as it
// applies a DeleteVM.
//
// It is for a host whose replica still holds a VM that another host has
// already tombstoned, as that host saw it — a delete is terminal for its
// incarnation, so this host retiring its copy writes nothing the cluster has
// not already decided.
func DeleteVMIncarnation(ctx context.Context, c *Client, name string, snap VMDeleteSnapshot) error {
	if snap.CreatedAt == "" {
		return ErrVMIncarnationMismatch
	}
	mismatch := false
	outcome, err := retriedDelete(func() (deleteOutcome, error) {
		vm, err := GetVM(ctx, c, name)
		if err != nil {
			return deleteContended, err
		}
		mismatch = vm != nil && !snap.Covers(*vm)
		if vm == nil || mismatch {
			return deleteAbsent, nil
		}
		return deleteVMGuardedFrom(ctx, c, *vm)
	})
	if err != nil {
		return err
	}
	if mismatch {
		return ErrVMIncarnationMismatch
	}
	return deleteOutcomeError(outcome, false)
}

// deleteVMGuarded is the single VM delete emitter; every caller routes through
// DeleteVM's retry loop. It reports the tri-state outcome from its own guard
// read — see deleteOutcome for why absent and CAS-miss must not be conflated.
func deleteVMGuarded(ctx context.Context, c *Client, name string) (deleteOutcome, error) {
	vm, err := GetVM(ctx, c, name)
	if err != nil {
		return deleteContended, err
	}
	if vm == nil {
		return deleteAbsent, nil
	}
	return deleteVMGuardedFrom(ctx, c, *vm)
}

// deleteVMGuardedFrom runs the guarded CAS against the caller's row snapshot —
// split from the read for the same testability reason as its container twin.
func deleteVMGuardedFrom(ctx context.Context, c *Client, vm VMRecord) (deleteOutcome, error) {
	name := vm.Name
	guard := vmDeleteMutationGuard(vm)
	now := c.NowTS()     // LWW key (updated_at)
	wall := nowRFC3339() // deleted_at is a wall/display column, never the HLC key
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		return c.mutationGuardMatches(ctx, tx, guard)
	}, []Statement{
		// Children are fenced while the parent is still live; the parent
		// tombstone is the final semantic commit barrier.
		{SQL: vmInterfacesCreateCleanupSQL, Params: []interface{}{wall, now, name}, Guard: guard},
		{SQL: vmDisksCreateCleanupSQL, Params: []interface{}{wall, now, name}, Guard: guard},
		{SQL: vmNICsCreateCleanupSQL, Params: []interface{}{wall, now, name}, Guard: guard},
		{SQL: vmPCIIntentCreateCleanupSQL, Params: []interface{}{wall, now, name}, Guard: guard},
		{SQL: vmPCIRealCreateCleanupSQL, Params: []interface{}{wall, now, name}, Guard: guard},
		{SQL: vmDeleteSQL, Params: []interface{}{
			wall, now, name, vm.OwnerEpoch, vm.SpecGeneration,
		}, Guard: guard},
	})
	if err != nil {
		return deleteContended, err
	}
	if !applied {
		return deleteContended, nil
	}
	return deleteApplied, nil
}

// ErrRenameTargetOccupied means some row — LIVE OR TOMBSTONED — already holds a
// primary key a rekey would write. It is returned while the batch is still being
// built, so a caller that hits it has changed nothing.
//
// The obstruction is deliberately never PURGED. On a receiver a retention DELETE
// executes unconditionally, while the rekey UPDATE meant to replace the row is
// LWW-gated on the OLD name and matches nothing at all on a peer that never saw
// it — so a delayed replay erases the target's tombstone and writes nothing in
// its place, and the batch still commits. That tombstone is also the only thing
// standing between a stale pre-delete full-state copy and a resurrection:
// created_at is the incarnation identity the anti-entropy merge decides from,
// and a hard delete throws it away. Callers that need an occupied key MOVE the
// obstruction instead — see ReplaceVMName.
var ErrRenameTargetOccupied = errors.New("corrosion: rename target key already occupied")

// vmChildKey is one child row's identity under a VM name: the table it is in and
// the primary-key remainder (everything but vm_name) it holds, as one comparable
// key plus whichever raw components a rekey statement has to bind.
type vmChildKey struct {
	table string
	key   string
	// vm_nics only. Its id is DeterministicNICID(vm_name, mac) — DERIVED from the
	// name — so a rekey must RE-DERIVE it rather than carry the old id forward.
	// Re-deriving does not make a collision impossible: two VMs can hold the same
	// MAC (CreateVM accepts a supplied one, and two stopped VMs can share an
	// address), and then the re-derived id is exactly the target's.
	mac string
	// vm_pci_realizations only: key is the joined pair, these are the bound halves.
	deviceID, memberID string
}

// targetKey is the remainder this row would hold under vmName.
func (k vmChildKey) targetKey(vmName string) string {
	if k.mac != "" {
		return DeterministicNICID(vmName, k.mac)
	}
	return k.key
}

// vmChildKeySet is table name → the primary-key remainders held in it.
type vmChildKeySet map[string]map[string]bool

func (s vmChildKeySet) add(table, key string) {
	if s[table] == nil {
		s[table] = map[string]bool{}
	}
	s[table][key] = true
}

func (s vmChildKeySet) has(table, key string) bool { return s[table][key] }

func (s vmChildKeySet) merge(other vmChildKeySet) {
	for table, keys := range other {
		for key := range keys {
			s.add(table, key)
		}
	}
}

// pciRealizationKey joins the two non-vm_name PK components of
// vm_pci_realizations into one key, on a separator neither can contain.
func pciRealizationKey(deviceID, memberID string) string {
	return deviceID + "\x00" + memberID
}

// vmChildKeys reads every child row held under vmName, across all five tables
// DeleteVM tombstones.
//
// Nothing here filters deleted_at, in either direction: a tombstone holds its
// primary key just as firmly as a live row — which is why a rekey can collide at
// all — and moving a tombstone out of a replacement's way is exactly what
// ReplaceVMName does.
func vmChildKeys(ctx context.Context, c *Client, vmName string) ([]vmChildKey, error) {
	var out []vmChildKey
	// vm_interfaces and vm_disks key on a COMPOSITE PK (vm_name + X) whose vm_name
	// component is being rekeyed; the rekey is row-scoped to full-PK statements so
	// each is per-row LWW-gated on apply (a bulk WHERE vm_name = ? can't be), which
	// is why the other PK component is enumerated locally here.
	//
	// vm_pci_intent's device_id and vm_pci_realizations' device_id/member_id are
	// name-INDEPENDENT by design (DeterministicPCIIntentID takes no vmName), so they
	// are PRESERVED across a rekey — only vm_name changes. That is what lets the
	// hardware-adoption audit's unconditional re-derive converge onto the same row
	// after a rename instead of forking a duplicate.
	for _, q := range []struct{ table, query string }{
		{"vm_interfaces", `SELECT network_name AS pk FROM vm_interfaces WHERE vm_name = ?`},
		{"vm_disks", `SELECT disk_name AS pk FROM vm_disks WHERE vm_name = ?`},
		{"vm_pci_intent", `SELECT device_id AS pk FROM vm_pci_intent WHERE vm_name = ?`},
	} {
		rows, err := c.Query(ctx, q.query, vmName)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			out = append(out, vmChildKey{table: q.table, key: r.String("pk")})
		}
	}
	nics, err := c.Query(ctx, `SELECT id AS pk, mac FROM vm_nics WHERE vm_name = ?`, vmName)
	if err != nil {
		return nil, err
	}
	for _, r := range nics {
		out = append(out, vmChildKey{table: "vm_nics", key: r.String("pk"), mac: r.String("mac")})
	}
	reals, err := c.Query(ctx, `SELECT device_id, member_id FROM vm_pci_realizations WHERE vm_name = ?`, vmName)
	if err != nil {
		return nil, err
	}
	for _, r := range reals {
		dev, mem := r.String("device_id"), r.String("member_id")
		out = append(out, vmChildKey{
			table: "vm_pci_realizations", key: pciRealizationKey(dev, mem),
			deviceID: dev, memberID: mem,
		})
	}
	return out, nil
}

// vmChildKeysHeld is vmChildKeys as a lookup set.
func vmChildKeysHeld(ctx context.Context, c *Client, vmName string) (vmChildKeySet, error) {
	keys, err := vmChildKeys(ctx, c, vmName)
	if err != nil {
		return nil, err
	}
	held := vmChildKeySet{}
	for _, k := range keys {
		held.add(k.table, k.key)
	}
	return held, nil
}

// vmRekeyPass is one leg of a rekey: move every row of oldName onto newName.
//
// keep, when non-nil, restricts the leg to the child rows it selects by their
// CURRENT key; the rest stay where they are, still holding their keys.
// parentVacated says an earlier leg in the same batch already freed the parent
// key, so the occupancy check must not trip on a row that is on its way out.
type vmRekeyPass struct {
	oldName, newName string
	parentVacated    bool
	keep             func(table, key string) bool
}

// execVMRekey builds every leg's statements into ONE batch and executes it, so a
// two-leg rekey is atomic and lands as a single replicated mutation — there is no
// window, locally or on a receiver, in which a name is held by neither VM.
//
// It refuses (ErrRenameTargetOccupied) before executing anything if a leg would
// write a key that is already held and no earlier leg frees it.
func execVMRekey(ctx context.Context, c *Client, now string, passes ...vmRekeyPass) error {
	var stmts []Statement
	freed := vmChildKeySet{} // child keys an EARLIER leg vacates
	for _, p := range passes {
		if !p.parentVacated {
			held, err := c.Query(ctx, `SELECT name FROM vms WHERE name = ?`, p.newName)
			if err != nil {
				return err
			}
			if len(held) > 0 {
				return fmt.Errorf("%w: vms.name = %q", ErrRenameTargetOccupied, p.newName)
			}
		}
		source, err := vmChildKeys(ctx, c, p.oldName)
		if err != nil {
			return err
		}
		held, err := vmChildKeysHeld(ctx, c, p.newName)
		if err != nil {
			return err
		}
		// The vms rekey patches the name embedded in the stored spec JSON —
		// otherwise spec.name keeps the old name and later XML + firmware-path
		// derivation (which use spec.Name) target the wrong VM (G1). A tombstoned
		// row has no readable spec and moves with the narrower shape; nothing reads
		// a tombstone's spec.
		parent := Statement{SQL: `UPDATE vms SET name = ?, updated_at = ? WHERE name = ?`,
			Params: []interface{}{p.newName, now, p.oldName}}
		if vm, gErr := GetVM(ctx, c, p.oldName); gErr == nil && vm != nil && vm.Spec != "" {
			var spec map[string]interface{}
			if json.Unmarshal([]byte(vm.Spec), &spec) == nil {
				spec["name"] = p.newName
				if b, mErr := json.Marshal(spec); mErr == nil {
					parent = Statement{SQL: `UPDATE vms SET name = ?, spec = ?, updated_at = ? WHERE name = ?`,
						Params: []interface{}{p.newName, string(b), now, p.oldName}}
				}
			}
		}
		stmts = append(stmts, parent)
		vacates := vmChildKeySet{}
		for _, k := range source {
			if p.keep != nil && !p.keep(k.table, k.key) {
				continue
			}
			target := k.targetKey(p.newName)
			if held.has(k.table, target) && !freed.has(k.table, target) {
				return fmt.Errorf("%w: %s (%q, %q)", ErrRenameTargetOccupied, k.table, p.newName, target)
			}
			switch k.table {
			case "vm_interfaces":
				stmts = append(stmts, Statement{
					SQL:    `UPDATE vm_interfaces SET vm_name = ?, updated_at = ? WHERE vm_name = ? AND network_name = ?`,
					Params: []interface{}{p.newName, now, p.oldName, k.key},
				})
			case "vm_disks":
				stmts = append(stmts, Statement{
					SQL:    `UPDATE vm_disks SET vm_name = ?, updated_at = ? WHERE vm_name = ? AND disk_name = ?`,
					Params: []interface{}{p.newName, now, p.oldName, k.key},
				})
			case "vm_nics":
				stmts = append(stmts, Statement{
					SQL:    `UPDATE vm_nics SET vm_name = ?, id = ?, updated_at = ? WHERE vm_name = ? AND id = ?`,
					Params: []interface{}{p.newName, target, now, p.oldName, k.key},
				})
			case "vm_pci_intent":
				stmts = append(stmts, Statement{
					SQL:    `UPDATE vm_pci_intent SET vm_name = ?, updated_at = ? WHERE vm_name = ? AND device_id = ?`,
					Params: []interface{}{p.newName, now, p.oldName, k.key},
				})
			case "vm_pci_realizations":
				stmts = append(stmts, Statement{
					SQL:    `UPDATE vm_pci_realizations SET vm_name = ?, updated_at = ? WHERE vm_name = ? AND device_id = ? AND member_id = ?`,
					Params: []interface{}{p.newName, now, p.oldName, k.deviceID, k.memberID},
				})
			default:
				return fmt.Errorf("corrosion: rekey has no statement for child table %q", k.table)
			}
			vacates.add(k.table, k.key)
		}
		// ip_allocations keys on (network, ip); vm_name is a NON-PK column here, so this stays a
		// bulk update — per-row LWW expansion handles it safely on apply.
		stmts = append(stmts, Statement{
			SQL:    `UPDATE ip_allocations SET vm_name = ?, updated_at = ? WHERE vm_name = ?`,
			Params: []interface{}{p.newName, now, p.oldName},
		})
		freed.merge(vacates)
	}
	return c.ExecuteBatch(ctx, stmts)
}

// RenameVM changes a VM's name across all tables. The new name must be entirely
// FREE — see ErrRenameTargetOccupied.
//
// `lv cutover` does NOT use this: taking a name a tombstone still holds needs a
// single receiver decision over both VMs, which a rekey by UPDATE cannot give
// (ReplaceVM). This is the plain free-target primitive, and it has no caller in
// the tree today — it is kept because the transition it performs is correct and
// its statement shapes are the ones a supported prior release still emits.
func RenameVM(ctx context.Context, c *Client, oldName, newName string) error {
	return execVMRekey(ctx, c, c.NowTS(), vmRekeyPass{oldName: oldName, newName: newName})
}

// UpdateVMInterfaceIP sets the IP of a VM interface.
func UpdateVMInterfaceIP(ctx context.Context, c *Client, vmName, networkName, ip string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vm_interfaces SET ip = ?, updated_at = ? WHERE vm_name = ? AND network_name = ?`,
		ip, now, vmName, networkName,
	)
}

// diskRowSQL writes one whole vm_disks row. It is InsertDisk's statement, and
// the shape InsertVMWithHardware and BackfillDiskBus reuse so that neither
// mints a fingerprint a receiver on the previous release does not know.
const diskRowSQL = `INSERT OR REPLACE INTO vm_disks
		 (vm_name, disk_name, host_name, path, size_bytes, backing_image,
		  storage_type, storage_volume, target_dev, backing_disk,
		  bus, device_kind, delete_with_vm, controller_model, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`

// diskRowParams binds d to diskRowSQL at updated_at = now.
func diskRowParams(d DiskRecord, now string) []interface{} {
	deviceKind := d.DeviceKind
	if deviceKind == "" {
		deviceKind = "disk" // matches the vm_disks.device_kind column default
	}
	return []interface{}{
		d.VMName, d.DiskName, d.HostName, d.Path, d.SizeBytes, d.BackingImage,
		d.StorageType, d.StorageVolume, d.TargetDev, d.BackingDisk,
		nullIfEmpty(d.Bus), deviceKind, boolToInt(d.DeleteWithVM), nullIfEmpty(d.ControllerModel), now,
	}
}

// InsertDisk adds a single disk record (used by hot-plug attach).
func InsertDisk(ctx context.Context, c *Client, d DiskRecord) error {
	return c.Execute(ctx, diskRowSQL, diskRowParams(d, c.NowTS())...)
}

// BackfillDiskBus fills the empty bus of the disk row read as `read`, for the
// startup hardware backfill run by owner. It writes only while, in the same
// transaction, the live row is still exactly `read` — every column — with no
// bus, and still names owner; applied=false means it did not.
//
// The write can therefore never MOVE the row. What it publishes is the row as
// this node holds it, plus the bus, and the guard proves this node still holds
// the row as it read it, as its own. A row that moved since the read, or that
// names another host, is left alone. (On the kvm003 lab the backfill published
// a row naming the host its VM had failed over from — drills 2 and 3 on
// main-e004c250.)
//
// The guard is only as good as the local replica, which is why the caller
// also waits for it to catch up (BackfillHardwareTables): on a replica that has
// not, the row still names the old owner and nothing local can tell.
//
// The statement is InsertDisk's whole-row shape, not an UPDATE of the bus
// column guarded by host_name on the wire. Such an UPDATE is a new
// fingerprint; a receiver on the previous release back-pressures an unknown
// shape, so this node's whole stream to it would stall for the rest of a
// rolling upgrade, and every node emits this for its VMs as it is upgraded.
// Nor would the wire predicate protect anything the local one does not:
// anti-entropy merges whole rows, so a newer local row reaches every peer
// whatever its statement said.
func BackfillDiskBus(ctx context.Context, c *Client, read DiskRecord, bus, owner string) (bool, error) {
	if bus == "" || read.Bus != "" || read.HostName != owner {
		return false, nil
	}
	d := read
	d.Bus = bus
	return c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		return diskRowStill(ctx, tx, read)
	}, []Statement{{SQL: diskRowSQL, Params: diskRowParams(d, c.NowTS())}})
}

// diskRowStill reports, inside tx, whether the live row of disk
// (read.VMName, read.DiskName) is still exactly read — every column a whole-row
// write publishes. A guarded whole-row write made from a read taken outside the
// transaction must not revert a column changed since (a resize's size_bytes, a
// hotplug's bus or target_dev, delete_with_vm): last-writer-wins would carry
// the stale value cluster-wide.
func diskRowStill(ctx context.Context, tx *sql.Tx, read DiskRecord) (bool, error) {
	var (
		host, path, backingImage, storageType, storageVolume, targetDev string
		backingDisk, curBus, deviceKind, controllerModel                string
		sizeBytes, deleteWithVM                                         int64
	)
	readKind := read.DeviceKind
	if readKind == "" {
		readKind = "disk"
	}
	err := tx.QueryRowContext(ctx,
		`SELECT host_name, path, size_bytes, backing_image, storage_type, storage_volume,
		        COALESCE(target_dev, ''), COALESCE(backing_disk, ''), COALESCE(bus, ''),
		        COALESCE(device_kind, 'disk'), COALESCE(delete_with_vm, 1), COALESCE(controller_model, '')
		 FROM vm_disks WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`,
		read.VMName, read.DiskName).Scan(&host, &path, &sizeBytes, &backingImage, &storageType,
		&storageVolume, &targetDev, &backingDisk, &curBus, &deviceKind, &deleteWithVM, &controllerModel)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return host == read.HostName && curBus == read.Bus &&
		path == read.Path && sizeBytes == read.SizeBytes && backingImage == read.BackingImage &&
		storageType == read.StorageType && storageVolume == read.StorageVolume &&
		targetDev == read.TargetDev && backingDisk == read.BackingDisk &&
		deviceKind == readKind && (deleteWithVM == 1) == read.DeleteWithVM &&
		controllerModel == read.ControllerModel, nil
}

// clearDiskBackingAfterRead is a test seam: run between ClearDiskBacking's
// read and its guarded write. Never set in production.
var clearDiskBackingAfterRead func()

// ClearDiskBacking records that disk (vmName, diskName), now at path, has no
// backing: a move that flattens a disk — a full copy or a block mirror — leaves
// a standalone image, and a backing_disk/backing_image left on the row would
// make a later in-place restore rebuild it as an overlay on the old base. It
// writes only while the live row still names path, and uses InsertDisk's
// whole-row shape so it mints no fingerprint a previous-release receiver does
// not know, and only while the live row is still, column for column, the one
// it read (diskRowStill). A row already without a backing is left alone.
func ClearDiskBacking(ctx context.Context, c *Client, vmName, diskName, path string) error {
	var cur DiskRecord
	found := false
	disks, err := GetVMDisks(ctx, c, vmName)
	if err != nil {
		return err
	}
	for _, d := range disks {
		if d.DiskName == diskName {
			cur, found = d, true
		}
	}
	if !found || cur.Path != path || (cur.BackingDisk == "" && cur.BackingImage == "") {
		return nil
	}
	if clearDiskBackingAfterRead != nil {
		clearDiskBackingAfterRead()
	}
	d := cur
	d.BackingDisk, d.BackingImage = "", ""
	// The whole row is re-written, so it is written only while the live row
	// is still exactly the one read: a column changed in between is never
	// reverted.
	_, err = c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		return diskRowStill(ctx, tx, cur)
	}, []Statement{{SQL: diskRowSQL, Params: diskRowParams(d, c.NowTS())}})
	return err
}

// UpdateDiskHostAndPath updates the host and path for a disk after migration.
func UpdateDiskHostAndPath(ctx context.Context, c *Client, vmName, diskName, hostName, path string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vm_disks SET host_name = ?, path = ?, updated_at = ?
		 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`,
		hostName, path, now, vmName, diskName)
}

// UpdateDiskStorage updates storage_type and storage_volume after a
// MoveVolume operation. The path is updated separately via
// UpdateDiskHostAndPath since motion can land within the same host.
func UpdateDiskStorage(ctx context.Context, c *Client, vmName, diskName, storageType, storageVolume string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vm_disks SET storage_type = ?, storage_volume = ?, updated_at = ?
		 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`,
		storageType, storageVolume, now, vmName, diskName)
}

// UpdateDiskPlacement atomically repoints a disk's full placement — host, path,
// storage driver, and pool — in ONE LWW write, so a mid-move failure can't leave
// the row half-moved (path updated but pool stale, or vice versa). It is the
// commit point for both the offline and live MoveVolume paths. Strict: a zero-row
// update (the disk is missing or already soft-deleted) returns ErrNoRowsAffected
// instead of a silent success, so a move never mistakes a vanished disk for a
// completed one. Replaces the prior UpdateDiskHostAndPath + UpdateDiskStorage pair
// at the move sites (those remain for migration / snapshot reconcile).
func UpdateDiskPlacement(ctx context.Context, c *Client, vmName, diskName, hostName, path, storageType, storageVolume string) error {
	now := c.NowTS()
	n, err := c.ExecuteRowsStrict(ctx,
		`UPDATE vm_disks SET host_name = ?, path = ?, storage_type = ?, storage_volume = ?, updated_at = ?
		 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`,
		hostName, path, storageType, storageVolume, now, vmName, diskName)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// CommitMigrationOwnership atomically repoints a VM and every one of its disks
// from sourceHost to targetHost in ONE guarded transaction — the ownership commit
// after a migration cutover. The libvirt cutover is irreversible, so this must be
// all-or-nothing: a per-row loop leaves a crash window where some disk rows point
// at the target while the VM row still points at the source.
//
// expected is a disk snapshot captured BEFORE cutover. The guard, evaluated inside
// the transaction against a consistent view, requires that:
//   - the VM row still sits on sourceHost (or is ALREADY on targetHost — see below),
//   - every expected disk's live row still matches its captured immutable placement
//     (host is source-or-target, path, storage_type, storage_volume all unchanged),
//   - no extra live disk rows have appeared.
//
// This refuses to clobber a concurrent move/retarget that changed a disk's pool or
// type while leaving its path similar.
//
// Idempotent: when the VM and all disks are ALREADY on targetHost (a retry after an
// ambiguous transaction-boundary failure), the writes are no-ops but the guard still
// passes, so it returns committed=true — never a spurious precondition failure.
//
// Returns committed=false (no error) when the preconditions no longer hold; the
// caller MUST treat that as a hard abort, not success.
func CommitMigrationOwnership(ctx context.Context, c *Client, vmName, sourceHost, targetHost, finalState string, expected []DiskRecord) (bool, error) {
	now := c.NowTS()
	stmts := []Statement{{
		SQL:    vmHostStateSQL,
		Params: []interface{}{targetHost, finalState, now, vmName},
	}}
	for _, d := range expected {
		stmts = append(stmts, Statement{
			SQL:    vmDiskHostMoveSQL,
			Params: []interface{}{targetHost, now, vmName, d.DiskName},
		})
	}

	guard := func(tx *sql.Tx) (bool, error) {
		var vmHost string
		// A tombstone is a vanished VM: the parent statement would change nothing
		// there (DispLiveRowUpdate), so committing the disk moves would report an
		// ownership handoff that never happened.
		switch err := tx.QueryRowContext(ctx, `SELECT host_name FROM vms WHERE name = ? AND deleted_at IS NULL`, vmName).Scan(&vmHost); {
		case errors.Is(err, sql.ErrNoRows):
			return false, nil // VM vanished mid-migration → decline
		case err != nil:
			return false, err
		}
		if vmHost != sourceHost && vmHost != targetHost {
			return false, nil // moved to a third host → decline
		}
		for _, d := range expected {
			var host, path, stype, svol string
			switch err := tx.QueryRowContext(ctx,
				`SELECT host_name, path, storage_type, storage_volume FROM vm_disks
				 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`, vmName, d.DiskName).
				Scan(&host, &path, &stype, &svol); {
			case errors.Is(err, sql.ErrNoRows):
				return false, nil // disk vanished → decline
			case err != nil:
				return false, err
			}
			// host is allowed to be source (normal), target (half-committed
			// retry), or the host the row named when the snapshot was taken.
			// The last is a row left behind by a move that re-keyed only the
			// VM: failover before it moved disk rows, or repair-owner. pp3 on
			// the kvm003 lab (main-b3368d7c) still named its failed host, so
			// this guard refused the commit AFTER the irreversible cutover and
			// left the guest on the target with its row `migrating` on the
			// source. A row unchanged since the snapshot is not drift; one
			// that moved anywhere else since is, and is still refused.
			// path/type/volume must be exactly what we captured before cutover.
			if (host != sourceHost && host != targetHost && host != d.HostName) ||
				path != d.Path || stype != d.StorageType || svol != d.StorageVolume {
				return false, nil // drift → decline
			}
		}
		var live int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM vm_disks WHERE vm_name = ? AND deleted_at IS NULL`, vmName).Scan(&live); err != nil {
			return false, err
		}
		if live != len(expected) {
			return false, nil // a disk was added/removed → decline
		}
		return true, nil
	}

	return c.ExecuteBatchGuarded(ctx, guard, stmts)
}

// vmDiskHostMoveSQL repoints one disk row at a host. Every site that moves a
// VM between hosts emits it for each of the VM's disks in the same batch as
// the VM row: a disk row naming a host the VM left breaks the next migration's
// ownership commit and the per-host disk accounting.
const vmDiskHostMoveSQL = `UPDATE vm_disks SET host_name = ?, updated_at = ?
			      WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`

// RepointMigratedVM moves the VM row of a migration that has cut over to
// targetHost when CommitMigrationOwnership declined: the guest runs on the
// target whatever the disk rows say, and a row left `migrating` on the source
// is one nothing heals (owner-assert skips `migrating`). It writes only while
// the row is still on sourceHost in state `migrating`, so it never overrides a
// move made since. The disk rows are left as they are; the caller reports
// them. committed=false when the row is no longer the migration's.
func RepointMigratedVM(ctx context.Context, c *Client, vmName, sourceHost, targetHost, finalState string) (bool, error) {
	now := c.NowTS()
	return c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		var host, state string
		switch err := tx.QueryRowContext(ctx, `SELECT host_name, state FROM vms WHERE name = ? AND deleted_at IS NULL`, vmName).
			Scan(&host, &state); {
		case errors.Is(err, sql.ErrNoRows):
			return false, nil
		case err != nil:
			return false, err
		}
		return host == sourceHost && state == "migrating", nil
	}, []Statement{{
		SQL:    vmHostStateSQL,
		Params: []interface{}{targetHost, finalState, now, vmName},
	}})
}

// RescheduleVMHost re-keys a VM to hostName in state, with its disk rows, in
// one batch. It is the failover coordinator's reschedule write before
// split_brain_gate_v1 is enforced (WriteVMRescheduleProof is the gated one).
//
// A move to any state but "stopped" is refused with ErrWorkloadStopped when the
// row is stopped when the transaction runs: it is failover's pre-activation
// reschedule, and "pending" there is a start on hostName that an operator who
// stopped the VM never asked for. The check is a local precondition, like
// WriteVMRescheduleProof's; it adds no statement and changes no replicated
// shape. A row that is gone is ErrNoRowsAffected.
func RescheduleVMHost(ctx context.Context, c *Client, name, hostName, state string) error {
	disks, err := GetVMDisks(ctx, c, name)
	if err != nil {
		return err
	}
	now := c.NowTS()
	stmts := []Statement{{SQL: vmHostStateSQL, Params: []interface{}{hostName, state, now, name}}}
	for _, d := range disks {
		if d.HostName == hostName {
			continue
		}
		stmts = append(stmts, Statement{
			SQL:    vmDiskHostMoveSQL,
			Params: []interface{}{hostName, now, name, d.DiskName},
		})
	}
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		var startable bool
		if err := tx.QueryRowContext(ctx,
			`SELECT state <> 'stopped' FROM vms WHERE name = ? AND deleted_at IS NULL`, name,
		).Scan(&startable); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return false, err
		}
		if !startable && state != "stopped" {
			return false, ErrWorkloadStopped
		}
		return true, nil
	}, stmts)
	if err != nil {
		return err
	}
	if !applied {
		return ErrNoRowsAffected
	}
	return nil
}

// UpdateDiskSize updates the size_bytes for a disk.
func UpdateDiskSize(ctx context.Context, c *Client, vmName, diskName string, sizeBytes int64) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vm_disks SET size_bytes = ?, updated_at = ?
		 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`,
		sizeBytes, now, vmName, diskName)
}

// UpdateVMDiskPath updates the on-disk path recorded for a disk. Used to
// reconcile the recorded path to the live domain's active disk source after a
// snapshot operation moves the domain onto an overlay (e.g. <disk>.<snapname>).
func UpdateVMDiskPath(ctx context.Context, c *Client, vmName, diskName, path string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vm_disks SET path = ?, updated_at = ?
		 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`,
		path, now, vmName, diskName)
}

// SoftDeleteDisk marks a disk as deleted.
func SoftDeleteDisk(ctx context.Context, c *Client, vmName, diskName string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vm_disks SET deleted_at = ?, updated_at = ? WHERE vm_name = ? AND disk_name = ?`,
		nowRFC3339(), now, vmName, diskName)
}

// ListDisks returns all disks for a VM (alias for GetVMDisks).
func ListDisks(ctx context.Context, c *Client, vmName string) ([]DiskRecord, error) {
	return GetVMDisks(ctx, c, vmName)
}

// InsertInterface adds a single interface record (used by hot-plug attach).
func InsertInterface(ctx context.Context, c *Client, i InterfaceRecord) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO vm_interfaces
		 (vm_name, network_name, ordinal, mac, ip, tap_device, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		i.VMName, i.NetworkName, i.Ordinal, i.MAC, i.IP, i.TapDevice, now)
}

// SoftDeleteInterfaceByMAC marks an interface as deleted by MAC address.
func SoftDeleteInterfaceByMAC(ctx context.Context, c *Client, vmName, mac string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vm_interfaces SET deleted_at = ?, updated_at = ? WHERE vm_name = ? AND mac = ?`,
		nowRFC3339(), now, vmName, mac)
}

// graduateVMOwnerEpochSQL moves a vms row off the pre-epoch default. It is the
// ONE statement for that intent, shared by BackfillOwnerEpochs and
// GraduateVMOwnerEpoch, because two texts for one operation would be two
// replicated fingerprints — and a peer registered for only one of them cannot
// resolve the other, which fails its apply closed and head-of-line blocks its
// whole stream.
//
// Guarded on vm_owner_epoch = 0 so it is idempotent on its own and cannot walk a
// live generation backwards: a retry, or a race with the per-sweep backfill, is
// a no-op rather than a reset.
const graduateVMOwnerEpochSQL = `UPDATE vms SET vm_owner_epoch = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL AND vm_owner_epoch = 0`

// GraduateVMOwnerEpoch assigns the first ownership generation to one named VM.
//
// The create path calls this immediately after inserting the row, because
// INSERT INTO vms does not name vm_owner_epoch (12 columns, and widening it
// would move the insert's fingerprint) so a fresh row takes the column default
// of 0 — and a running VM at epoch 0 has no marker, since
// convergeOwnerEpochMarker returns early for one, which is the window
// colonelpanik/litevirt#157 is about.
//
// Returns ErrNoRowsAffected when the guarded UPDATE matched nothing, via
// ExecuteRows rather than Execute. This is the difference between "the row is
// now at generation 1" and "some other row state exists that this statement
// declined to touch" — a soft-deleted row (a DeleteVM racing the create) or one
// a replicated write already moved off 0. A caller that stamps a runtime marker
// on the strength of this call MUST distinguish them: Execute discards the row
// count, so a no-op would read as success and the marker would name a
// generation the row does not hold, which is the one mismatch nothing
// converges. On a nil return the row is at 1, which is what makes stamping the
// literal 1 sound.
//
// BackfillOwnerEpochs deliberately does NOT use this: it is idempotent by
// predicate across many rows, and a row a concurrent graduation already moved
// is a success for it, not a fault.
func GraduateVMOwnerEpoch(ctx context.Context, c *Client, name string) error {
	n, err := c.ExecuteRowsStrict(ctx, graduateVMOwnerEpochSQL, int64(1), c.NowTS(), name)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// BackfillOwnerEpochs graduates every workload THIS host owns out of the
// pre-epoch 0 (0→1) — the Phase 4 one-time backfill, run by the health sweeps
// while enforcement.owner_epoch is on. Only owned, live rows are touched:
// another host's workloads are its own to graduate (each owner also writes the
// matching runtime marker, which only the owner can), and tombstones stay
// pre-epoch forever. Idempotent by predicate (epoch = 0).
func BackfillOwnerEpochs(ctx context.Context, c *Client, hostName string) error {
	// Per-row full-PK updates, not one bulk UPDATE: a bulk statement replicates
	// through the receiver's per-row LWW expansion, while these carry exact row
	// identity (vms.name / containers.(host_name,name)) and the epoch=0
	// predicate keeps each one idempotent on its own.
	vms, err := c.Query(ctx,
		`SELECT name FROM vms WHERE host_name = ? AND deleted_at IS NULL AND vm_owner_epoch = 0`,
		hostName)
	if err != nil {
		return err
	}
	for _, r := range vms {
		if err := c.Execute(ctx, graduateVMOwnerEpochSQL,
			int64(1), c.NowTS(), r.String("name")); err != nil {
			return err
		}
	}
	cts, err := c.Query(ctx,
		`SELECT name FROM containers WHERE host_name = ? AND deleted_at IS NULL AND owner_epoch = 0`,
		hostName)
	if err != nil {
		return err
	}
	for _, r := range cts {
		if err := c.Execute(ctx,
			`UPDATE containers SET owner_epoch = ?, updated_at = ? WHERE host_name = ? AND name = ? AND deleted_at IS NULL AND owner_epoch = 0`,
			int64(1), c.NowTS(), hostName, r.String("name")); err != nil {
			return err
		}
	}
	return nil
}

// OwnerEpochBackfillComplete reports whether no workload owned by this host
// remains at the pre-epoch 0 — the readiness half of the owner_epoch_v1
// advertisement gate ("never bless an already-diverged cluster": a fleet must
// not latch across a node whose workloads are ungraduated).
func OwnerEpochBackfillComplete(ctx context.Context, c *Client, hostName string) (bool, error) {
	for _, q := range []string{
		`SELECT COUNT(1) AS n FROM vms WHERE host_name = ? AND deleted_at IS NULL AND vm_owner_epoch = 0`,
		`SELECT COUNT(1) AS n FROM containers WHERE host_name = ? AND deleted_at IS NULL AND owner_epoch = 0`,
	} {
		rows, err := c.Query(ctx, q, hostName)
		if err != nil {
			return false, err
		}
		if len(rows) != 1 || rows[0].Int64("n") > 0 {
			return false, nil
		}
	}
	return true, nil
}

// WorkloadRowTrace is what a workload's row says about it, whatever its state —
// including a tombstone. It is the evidence behind an orphan-runtime report
// (internal/health/orphan_runtime.go): which host and generation the row last
// named, and when it was deleted.
type WorkloadRowTrace struct {
	HostName   string
	OwnerEpoch int64
	DeletedAt  string // "" while the row is live
	UpdatedAt  string
}

// LookupVMRowAnyState reads vms row `name`, live or tombstoned. nil when the
// name has no row at all.
func LookupVMRowAnyState(ctx context.Context, c *Client, name string) (*WorkloadRowTrace, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, vm_owner_epoch, COALESCE(deleted_at, '') AS deleted_at, updated_at
		 FROM vms WHERE name = ?`, name)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	r := rows[0]
	return &WorkloadRowTrace{HostName: r.String("host_name"), OwnerEpoch: r.Int64("vm_owner_epoch"),
		DeletedAt: r.String("deleted_at"), UpdatedAt: r.String("updated_at")}, nil
}

// LookupContainerRowsAnyState reads every containers row named `name`, on any
// host, live or tombstoned, newest first.
func LookupContainerRowsAnyState(ctx context.Context, c *Client, name string) ([]WorkloadRowTrace, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, owner_epoch, COALESCE(deleted_at, '') AS deleted_at, updated_at
		 FROM containers WHERE name = ? ORDER BY updated_at DESC`, name)
	if err != nil {
		return nil, err
	}
	out := make([]WorkloadRowTrace, 0, len(rows))
	for _, r := range rows {
		out = append(out, WorkloadRowTrace{HostName: r.String("host_name"), OwnerEpoch: r.Int64("owner_epoch"),
			DeletedAt: r.String("deleted_at"), UpdatedAt: r.String("updated_at")})
	}
	return out, nil
}
