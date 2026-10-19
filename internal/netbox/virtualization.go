package netbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The virtualization and dcim collections this mirror touches.
const (
	vmsPath          = "/api/virtualization/virtual-machines/"
	vmInterfacesPath = "/api/virtualization/interfaces/"
	clusterTypesPath = "/api/virtualization/cluster-types/"
	clustersPath     = "/api/virtualization/clusters/"
	devicesPath      = "/api/dcim/devices/"
	sitesPath        = "/api/dcim/sites/"
	// macAddressesPath exists only on NetBox 4.2+, where a MAC became an object
	// of its own. Reached only when a write shows the server is on that shape —
	// see repairDroppedMAC.
	macAddressesPath = "/api/dcim/mac-addresses/"
)

// VirtualMachine is one virtualization.virtual_machine.
type VirtualMachine struct {
	ID        int
	Name      string
	ClusterID int
	DeviceID  int // 0 when the host is not modelled as a DCIM device
	VCPUs     VCPUs
	MemoryMB  int
	// DiskMB is `virtual_machine.disk`, which NetBox counts in MEGABYTES.
	// Named for its unit because the field it feeds is the whole trap: while
	// this was DiskGB the mirror wrote gibibytes into a megabyte column, so a
	// 20 GiB disk was recorded as 20 MB and read back as 20 GiB. Build it with
	// DiskMBFromBytes rather than converting at a call site.
	DiskMB   int
	Status   string
	Identity string
	// PrimaryIP4ID is virtual_machine.primary_ip4: NetBox's "this machine's
	// main address", which is SEPARATE from assigning an ip_address to a
	// vminterface. Everything downstream reads the primary — NetBox's own UI
	// column, its DNS integrations, nb_inventory's ansible_host — so a VM with
	// an assigned address but no primary reads to all of them as a machine with
	// no address at all. 0 = none.
	PrimaryIP4ID int
	// PrimaryIP6ID is virtual_machine.primary_ip6, the IPv6 counterpart. NetBox
	// keeps the two apart and refuses an address of the wrong family in either.
	// 0 = none.
	PrimaryIP6ID int
}

// bytesPerMB is NetBox's megabyte: DECIMAL, 1 MB = 1,000,000 bytes — not the
// binary mebibyte litevirt uses for memory. `virtual_machine.disk` and
// `virtual_disk.size` are both counted in it.
const bytesPerMB = 1_000_000

// DiskMBFromBytes converts a provisioned byte count to NetBox's disk unit.
//
// THE ONLY conversion into that unit, and it takes BYTES: routing through a
// gibibyte figure first — project quota's DiskQuotaGiB, say, which rounds each
// disk up to whole GiB because quota admission must never under-charge — throws
// away most of the value's precision before the unit is even reached.
//
// Rounds UP, so a recorded size never understates the provisioned disk: an
// inventory record that says a machine has less disk than it has is the reading
// that gets someone paged.
func DiskMBFromBytes(sizeBytes int64) int {
	if sizeBytes <= 0 {
		return 0
	}
	// Divide first, then carry the remainder: adding bytesPerMB-1 up front
	// overflows int64 for a size near the maximum.
	mb := sizeBytes / bytesPerMB
	if sizeBytes%bytesPerMB != 0 {
		mb++
	}
	return int(mb)
}

// VCPUs is NetBox's `vcpus`, which is a DECIMAL on the model and an integer
// count everywhere in litevirt.
//
// It is not an int here because it cannot be: `virtual_machine.vcpus` is a
// DecimalField and NetBox does not coerce decimals to strings, so a real
// response carries `"vcpus": 2.0`. Decoding that into an int fails the WHOLE
// response — the create-response decode and every page of the inventory
// enumeration — so an int made the mirror unable to read a live NetBox at all,
// while the fake, which emitted a bare `2`, could not show it.
//
// FLOAT, not a rounded int, because the value has to survive the round trip for
// the diff to be right: a NetBox that somehow holds 2.5 must compare UNEQUAL to
// a desired 2 and be patched back to it. Truncating on decode would make the
// two compare equal and leave the fractional value in NetBox forever.
//
// Only `vcpus` is decimal. `memory` (mebibytes) and `disk` (DECIMAL megabytes)
// are PositiveIntegerFields on the same model and arrive as JSON integers, so
// they stay ints — and a null in any of the three is simply the zero value,
// which is what an unset field means to the diff.
type VCPUs float64

// UnmarshalJSON accepts what NetBox and its neighbours actually put on the wire:
// a JSON number (`2` or `2.0`), a JSON null, or a QUOTED decimal ("2.00").
//
// The quoted form is not hypothetical: it is what DRF emits for every decimal
// field when COERCE_DECIMAL_TO_STRING is left at its framework default, which
// NetBox overrides but an install fronting it need not. Accepting both costs one
// branch and removes a whole class of "cannot read the server" failure.
func (v *VCPUs) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		*v = 0
		return nil
	}
	s = strings.Trim(s, `"`)
	if s == "" {
		*v = 0
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("netbox: vcpus %s is neither a number nor a decimal string: %w", b, err)
	}
	*v = VCPUs(f)
	return nil
}

// VMInterface is one virtualization.vminterface. It is keyed on MAC, never on
// the litevirt NIC id, which is derived from the VM name and re-derived on
// rename.
type VMInterface struct {
	ID       int
	VMID     int
	Name     string
	MAC      string
	Identity string
}

type vmJSON struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	VCPUs  VCPUs  `json:"vcpus"`
	Memory int    `json:"memory"`
	// Megabytes on the wire, and megabytes in the field it lands in: the two
	// names must not drift apart again.
	DiskMB int `json:"disk"`
	Status *struct {
		Value string `json:"value"`
	} `json:"status"`
	Cluster *struct {
		ID int `json:"id"`
	} `json:"cluster"`
	Device *struct {
		ID int `json:"id"`
	} `json:"device"`
	PrimaryIP4 *struct {
		ID int `json:"id"`
	} `json:"primary_ip4"`
	PrimaryIP6 *struct {
		ID int `json:"id"`
	} `json:"primary_ip6"`
	CustomFields map[string]any `json:"custom_fields"`
}

// toVM maps EVERY field the diff compares.
//
// Omitting one is not a cosmetic bug: if Status is never populated, a desired
// Status of "active" differs from an actual "" on every sweep, so every VM looks
// changed forever and write-on-change never fires. Any field added to the diff
// must be added here too.
func (j vmJSON) toVM() VirtualMachine {
	out := VirtualMachine{
		ID: j.ID, Name: j.Name,
		VCPUs: j.VCPUs, MemoryMB: j.Memory, DiskMB: j.DiskMB,
		Status: j.statusValue(),
	}
	if j.Cluster != nil {
		out.ClusterID = j.Cluster.ID
	}
	if j.Device != nil {
		out.DeviceID = j.Device.ID
	}
	if j.PrimaryIP4 != nil {
		out.PrimaryIP4ID = j.PrimaryIP4.ID
	}
	if j.PrimaryIP6 != nil {
		out.PrimaryIP6ID = j.PrimaryIP6.ID
	}
	if v, ok := j.CustomFields[IdentityField].(string); ok {
		out.Identity = v
	}
	return out
}

// statusValue unwraps NetBox's {"value": "...", "label": "..."} choice object.
func (j vmJSON) statusValue() string {
	if j.Status == nil {
		return ""
	}
	return j.Status.Value
}

type ifaceJSON struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	MAC            string `json:"mac_address"`
	VirtualMachine *struct {
		ID int `json:"id"`
	} `json:"virtual_machine"`
	CustomFields map[string]any `json:"custom_fields"`
}

func (j ifaceJSON) toIface() VMInterface {
	// NetBox echoes a MAC upper-cased. The identity is built from the
	// lower-cased form, so a MAC left as NetBox returned it would never compare
	// equal to the one litevirt holds.
	out := VMInterface{ID: j.ID, Name: j.Name, MAC: strings.ToLower(j.MAC)}
	if j.VirtualMachine != nil {
		out.VMID = j.VirtualMachine.ID
	}
	if v, ok := j.CustomFields[IdentityField].(string); ok {
		out.Identity = v
	}
	return out
}

// ListVMsByCluster enumerates every VM in one cluster, paginated. The diff needs
// the COMPLETE set: a truncated list makes live VMs look vanished, and the sweep
// would delete them.
func (c *Client) ListVMsByCluster(ctx context.Context, clusterID int) ([]VirtualMachine, error) {
	q := url.Values{}
	q.Set("cluster_id", strconv.Itoa(clusterID))
	return paginate(ctx, c, vmsPath, q, vmJSON.toVM)
}

// ListInterfacesByCluster enumerates every interface in one cluster, paginated.
func (c *Client) ListInterfacesByCluster(ctx context.Context, clusterID int) ([]VMInterface, error) {
	q := url.Values{}
	q.Set("cluster_id", strconv.Itoa(clusterID))
	return paginate(ctx, c, vmInterfacesPath, q, ifaceJSON.toIface)
}

// ipBatchSize is how many interface ids go into one address query. A URL
// carrying every interface in a large cluster would exceed what servers and
// proxies accept, so the query is batched rather than sent whole.
const ipBatchSize = 50

// ListOwnedIPsForInterfaces enumerates litevirt-owned addresses assigned to the
// given interfaces, paginated and batched.
//
// The interface set IS the cluster scope. NetBox's IPAddressFilterSet has
// vminterface_id and virtual_machine_id but NO cluster filter, so there is no
// single query for "every address in this cluster"; inventing one would either
// error or, worse, be ignored — silently dropping the scope and returning every
// litevirt address in the install.
//
// The mirror reads ASSIGNMENT from these objects rather than from the interface,
// because assignment lives on the address in NetBox and an interface can carry
// several. Only addresses carrying a non-empty litevirt identity are returned,
// which is what keeps an operator-owned address structurally out of the clear
// path.
func (c *Client) ListOwnedIPsForInterfaces(ctx context.Context, ifaceIDs []int) ([]IPAddress, error) {
	var out []IPAddress
	for i := 0; i < len(ifaceIDs); i += ipBatchSize {
		end := min(i+ipBatchSize, len(ifaceIDs))
		q := url.Values{}
		for _, id := range ifaceIDs[i:end] {
			q.Add("vminterface_id", strconv.Itoa(id))
		}
		q.Set("cf_"+IdentityField+"__n", "") // has a non-empty litevirt identity
		batch, err := paginate(ctx, c, ipAddressesPath, q, ipJSON.toIP)
		if err != nil {
			return nil, err
		}
		out = append(out, batch...)
	}
	return out, nil
}

// vmBody is the write body for a VM, shared by create and update so a PATCH can
// never send a different field set than the CREATE it is reconciling towards.
func vmBody(vm VirtualMachine) map[string]any {
	b := map[string]any{
		"name":          vm.Name,
		"cluster":       vm.ClusterID,
		"vcpus":         vm.VCPUs,
		"memory":        vm.MemoryMB,
		"disk":          vm.DiskMB,
		"status":        vm.Status,
		"custom_fields": map[string]string{IdentityField: vm.Identity},
	}
	// Send device EXPLICITLY, including nil.
	//
	// Omitting the key when the link is absent makes a PATCH leave a stale link
	// in place, so the diff keeps seeing 9 != 0 and emits the same update
	// forever. An explicit null is what actually clears it.
	if vm.DeviceID != 0 {
		b["device"] = vm.DeviceID
	} else {
		b["device"] = nil
	}
	return b
}

// CreateVM creates one virtual machine.
func (c *Client) CreateVM(ctx context.Context, vm VirtualMachine) (VirtualMachine, error) {
	var out vmJSON
	if err := c.do(ctx, http.MethodPost, vmsPath, vmBody(vm), &out); err != nil {
		return VirtualMachine{}, err
	}
	return out.toVM(), nil
}

// UpdateVM patches one virtual machine. Callers must diff first — an
// unconditional PATCH every sweep buries NetBox's changelog in noise.
func (c *Client) UpdateVM(ctx context.Context, id int, vm VirtualMachine) error {
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(vmsPath+"%d/", id), vmBody(vm), nil)
}

// SetPrimaryIP4 sets (or, with ipID 0, clears) a virtual machine's primary_ip4.
//
// A TARGETED patch rather than a field on vmBody, because the two writes have
// different preconditions: NetBox requires the address to already be assigned to
// an interface of this VM, which is only true AFTER the interface phase — while
// vmBody is also what CREATE sends, when the VM has no interfaces at all. Fold
// them together and every create carries a field the server must reject.
func (c *Client) SetPrimaryIP4(ctx context.Context, vmID, ipID int) error {
	return c.setPrimary(ctx, vmID, "primary_ip4", ipID)
}

// SetPrimaryIP6 sets (or, with ipID 0, clears) a virtual machine's primary_ip6.
// Same preconditions as SetPrimaryIP4, and NetBox additionally refuses an
// address that is not IPv6.
func (c *Client) SetPrimaryIP6(ctx context.Context, vmID, ipID int) error {
	return c.setPrimary(ctx, vmID, "primary_ip6", ipID)
}

// setPrimary PATCHes one primary-address field, sending an explicit null to
// clear it: an omitted key is a no-op on a PATCH.
func (c *Client) setPrimary(ctx context.Context, vmID int, field string, ipID int) error {
	body := map[string]any{field: nil}
	if ipID != 0 {
		body[field] = ipID
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(vmsPath+"%d/", vmID), body, nil)
}

// DeleteVM removes one virtual machine, after detaching every address assigned
// to its interfaces.
//
// NetBox deletes a VM's interfaces with it, and deletes each interface's
// addresses with THAT — see DeleteInterface — so a bare DELETE destroys every
// address the VM holds. They are detached first, and survive unassigned.
//
// THE PRIMARIES GO FIRST. NetBox refuses to detach an address that is its VM's
// primary_ip4 or primary_ip6 (IPAddress.clean: "Cannot reassign IP address
// while it is designated as the primary IP for the parent object"), so both are
// cleared before any detach. The VM is about to go, and the cascade lost them
// anyway.
//
// The VM is read first so a VM that is already gone answers 404 exactly as the
// DELETE would, before any address query is made about it. Every later failure
// is reported without its status, so only that read and the DELETE itself can
// tell a caller the VM is absent.
func (c *Client) DeleteVM(ctx context.Context, id int) error {
	var vm vmJSON
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf(vmsPath+"%d/", id), nil, &vm); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("virtual_machine_id", strconv.Itoa(id))
	ips, err := paginate(ctx, c, ipAddressesPath, q, ipJSON.toIP)
	if err != nil {
		return fmt.Errorf("netbox: list the addresses of virtual machine %d before deleting it: %v", id, err)
	}
	var detach []IPAddress
	for _, ip := range ips {
		if ip.AssignedObjectType != vmInterfaceType {
			continue
		}
		if ip.AssignedVMID == 0 {
			// Fail CLOSED. The re-check cannot be made, and skipping the
			// address would leave it to the cascade this exists to prevent.
			return fmt.Errorf("netbox: virtual machine %d not deleted: address %d (%s) is assigned to "+
				"interface %d, but NetBox did not say which VM that interface belongs to",
				id, ip.ID, ip.Address, ip.AssignedObjectID)
		}
		if ip.AssignedVMID == id {
			detach = append(detach, ip)
		}
	}
	if len(detach) > 0 {
		v := vm.toVM()
		clear := map[string]any{}
		if v.PrimaryIP4ID != 0 {
			clear["primary_ip4"] = nil
		}
		if v.PrimaryIP6ID != 0 {
			clear["primary_ip6"] = nil
		}
		if err := c.clearPrimaries(ctx, id, clear); err != nil {
			return fmt.Errorf("netbox: virtual machine %d not deleted: %v", id, err)
		}
	}
	if err := c.detachAll(ctx, detach); err != nil {
		// %w: detachAll's errors carry no NetBox status (see there), only an
		// AddressNotChangeableError a caller may act on.
		return fmt.Errorf("netbox: virtual machine %d not deleted: %w", id, err)
	}
	return c.do(ctx, http.MethodDelete, fmt.Sprintf(vmsPath+"%d/", id), nil, nil)
}

// ClearPrimaryIPs nulls primary_ip4 and/or primary_ip6 of one VM in ONE
// request. One request, because NetBox saves a PATCHed VM as the whole row it
// read at the start of that request: two concurrent PATCHes that each null one
// field can write the other field back.
func (c *Client) ClearPrimaryIPs(ctx context.Context, vmID int, ip4, ip6 bool) error {
	fields := map[string]any{}
	if ip4 {
		fields["primary_ip4"] = nil
	}
	if ip6 {
		fields["primary_ip6"] = nil
	}
	return c.clearPrimaries(ctx, vmID, fields)
}

// clearPrimaries PATCHes the named primary fields of one VM to null. Nothing
// is sent when there is nothing to clear.
func (c *Client) clearPrimaries(ctx context.Context, vmID int, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	if err := c.do(ctx, http.MethodPatch, fmt.Sprintf(vmsPath+"%d/", vmID), fields, nil); err != nil {
		return fmt.Errorf("clear the primary address of virtual machine %d: %v", vmID, err)
	}
	return nil
}

// FindVMByIdentity searches by the identity custom field. Called BEFORE every
// create: NetBox has no idempotency key, so a timeout after creation but before
// the identity-map write would otherwise duplicate the object on retry.
//
// It returns every match rather than the first, because more than one is the
// ambiguity a caller has to refuse instead of guessing at.
func (c *Client) FindVMByIdentity(ctx context.Context, identity string) ([]VirtualMachine, error) {
	q := url.Values{}
	q.Set("cf_"+IdentityField, identity)
	return paginate(ctx, c, vmsPath, q, vmJSON.toVM)
}

// FindInterfaceByIdentity searches interfaces by identity custom field. Like
// FindVMByIdentity it returns every match, so a duplicate is visible to the
// caller rather than silently resolved to whichever object sorted first.
func (c *Client) FindInterfaceByIdentity(ctx context.Context, identity string) ([]VMInterface, error) {
	q := url.Values{}
	q.Set("cf_"+IdentityField, identity)
	return paginate(ctx, c, vmInterfacesPath, q, ifaceJSON.toIface)
}

// CreateInterface creates one VM interface.
func (c *Client) CreateInterface(ctx context.Context, i VMInterface) (VMInterface, error) {
	body := map[string]any{
		"virtual_machine": i.VMID,
		"name":            i.Name,
		"mac_address":     i.MAC,
		"custom_fields":   map[string]string{IdentityField: i.Identity},
	}
	var out ifaceJSON
	if err := c.do(ctx, http.MethodPost, vmInterfacesPath, body, &out); err != nil {
		return VMInterface{}, err
	}
	got := out.toIface()
	if err := c.repairDroppedMAC(ctx, got.ID, i.MAC, got.MAC); err != nil {
		return VMInterface{}, err
	}
	if i.MAC != "" {
		got.MAC = i.MAC
	}
	return got, nil
}

// UpdateInterface patches one VM interface. Diff before calling — an
// unconditional PATCH per sweep buries NetBox's changelog.
//
// The identity is not rewritten: it is derived from the MAC, so an interface
// whose MAC changed is a different identity and therefore a different object,
// not an update.
func (c *Client) UpdateInterface(ctx context.Context, id int, i VMInterface) error {
	body := map[string]any{
		"name":        i.Name,
		"mac_address": i.MAC,
	}
	// The response is decoded rather than discarded so a dropped MAC is visible
	// here: this is the call the mirror makes once a diff has noticed the MAC
	// missing, so it is the call that has to be able to put it back.
	var out ifaceJSON
	if err := c.do(ctx, http.MethodPatch, fmt.Sprintf(vmInterfacesPath+"%d/", id), body, &out); err != nil {
		return err
	}
	return c.repairDroppedMAC(ctx, id, i.MAC, out.toIface().MAC)
}

// repairDroppedMAC records `want` on the interface when the server answered a
// write with `got` — that is, did not honour the `mac_address` field.
//
// NetBox 4.2 moved the MAC off the interface: `vminterface.mac_address` is
// READ-ONLY there, and a MAC is a `dcim.MACAddress` object assigned to the
// interface which the interface points at with `primary_mac_address`. Such a
// server accepts an interface write carrying `mac_address` with a 2xx and
// SILENTLY DROPS the field, so a caller that does not compare what came back
// cannot tell the shapes apart. That silence is the whole hazard: nothing fails,
// and the mirror's NIC diff then sees the MAC missing on every single sweep,
// emits an update, and has that update dropped in turn — one write per NIC per
// sweep against a mirror that can never converge.
//
// Comparing the response, rather than the server's version string, is what keeps
// this correct in both directions: a pre-4.2 server echoes the MAC back and
// never has its (nonexistent) MACAddress collection touched.
//
// An interface's MAC never changes — a NIC's identity is (fingerprint, uuid,
// MAC), so a changed MAC is a different identity and therefore a different
// object — which makes this a create-once repair, not a value to reconcile.
func (c *Client) repairDroppedMAC(ctx context.Context, ifaceID int, want, got string) error {
	if want == "" || ifaceID == 0 || strings.EqualFold(want, got) {
		return nil
	}
	macID, err := c.findAssignedMACAddress(ctx, ifaceID, want)
	if err != nil {
		return err
	}
	if macID == 0 {
		// NetBox permits SEVERAL MACAddress objects carrying the same MAC, so a
		// repair that only ever created would add one more on every retry after
		// a failed PATCH below. Hence the lookup above: adopt, then create.
		var created struct {
			ID int `json:"id"`
		}
		body := map[string]any{
			"mac_address":          want,
			"assigned_object_type": "virtualization.vminterface",
			"assigned_object_id":   ifaceID,
		}
		if err := c.do(ctx, http.MethodPost, macAddressesPath, body, &created); err != nil {
			return fmt.Errorf("netbox: record MAC %s for interface %d: %w", want, ifaceID, err)
		}
		macID = created.ID
	}
	patch := map[string]any{"primary_mac_address": macID}
	if err := c.do(ctx, http.MethodPatch, fmt.Sprintf(vmInterfacesPath+"%d/", ifaceID), patch, nil); err != nil {
		return fmt.Errorf("netbox: set primary MAC of interface %d to %s: %w", ifaceID, want, err)
	}
	return nil
}

// findAssignedMACAddress returns the id of the MACAddress object carrying mac
// and already assigned to this interface, or 0. NetBox matches the address
// case-insensitively, so the lower-cased form litevirt holds is the right query.
func (c *Client) findAssignedMACAddress(ctx context.Context, ifaceID int, mac string) (int, error) {
	q := url.Values{}
	q.Set("mac_address", mac)
	q.Set("assigned_object_type", "virtualization.vminterface")
	q.Set("assigned_object_id", strconv.Itoa(ifaceID))
	var page struct {
		Results []struct {
			ID int `json:"id"`
		} `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, macAddressesPath+"?"+q.Encode(), nil, &page); err != nil {
		return 0, fmt.Errorf("netbox: look up MAC %s of interface %d: %w", mac, ifaceID, err)
	}
	if len(page.Results) == 0 {
		return 0, nil
	}
	return page.Results[0].ID, nil
}

// SetVMIdentity rewrites ONE virtual machine's litevirt identity custom field.
//
// It is the CA re-key's inventory write, and the exact counterpart of
// SetIPIdentity. PATCH, not PUT: NetBox's PUT is a full replace, so an omitted
// `name` or `cluster` would be blanked and the re-key would destroy the objects
// it exists to preserve. The body carries nothing but the custom field for the
// same reason — anything else could rename a VM or move it between clusters
// while re-stamping it.
//
// It deliberately does NOT reuse UpdateVM. That sends the whole mirrored field
// set, so a re-key would have to know a VM's desired name, size and status to
// rewrite its identity — and would silently reconcile them on the way past, in
// an operation whose whole contract is that it changes one field.
func (c *Client) SetVMIdentity(ctx context.Context, id int, identity string) error {
	body := map[string]any{
		"custom_fields": map[string]string{IdentityField: identity},
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(vmsPath+"%d/", id), body, nil)
}

// SetInterfaceIdentity rewrites ONE VM interface's litevirt identity custom
// field. Same shape, same reasons, as SetVMIdentity.
//
// UpdateInterface is not it: that one deliberately never touches the identity,
// because a NIC whose MAC changed is a different object rather than an update.
// The re-key is the one caller that rewrites the identity while the MAC stays
// put, so it needs a write of its own.
func (c *Client) SetInterfaceIdentity(ctx context.Context, id int, identity string) error {
	body := map[string]any{
		"custom_fields": map[string]string{IdentityField: identity},
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(vmInterfacesPath+"%d/", id), body, nil)
}

// DeleteInterface removes one VM interface, after detaching every address
// assigned to it. Without it a hotplug detach never converges in NetBox.
//
// NetBox deletes the addresses assigned to an interface WITH the interface: the
// vminterface's ip_addresses relation is a generic relation, and deleting the
// interface cascades it. A bare DELETE would therefore destroy a leased address
// litevirt still names, and an operator's own address on the same interface.
// Each one is detached first and survives unassigned — litevirt's are released
// or reclaimed through their lease, and an operator's are left for the operator.
//
// Every assignment is detached, not only litevirt-owned ones: detaching is the
// least the delete can do to an address, and the cascade is the most.
//
// The query names the content type and the object id rather than
// vminterface_id, which NetBox validates against existing interfaces: an
// interface already gone would turn into a 400 instead of the 404 the DELETE
// returns.
func (c *Client) DeleteInterface(ctx context.Context, id int) error {
	q := url.Values{}
	q.Set("assigned_object_type", vmInterfaceType)
	q.Set("assigned_object_id", strconv.Itoa(id))
	ips, err := paginate(ctx, c, ipAddressesPath, q, ipJSON.toIP)
	if err != nil {
		return fmt.Errorf("netbox: list the addresses of interface %d before deleting it: %v", id, err)
	}
	var detach []IPAddress
	for _, ip := range ips {
		if ip.AssignedObjectType == vmInterfaceType && ip.AssignedObjectID == id {
			detach = append(detach, ip)
		}
	}
	if len(detach) > 0 {
		if err := c.clearPrimariesNaming(ctx, id, detach); err != nil {
			return err
		}
	}
	if err := c.detachAll(ctx, detach); err != nil {
		// %w: detachAll's errors carry no NetBox status (see there), only an
		// AddressNotChangeableError a caller may act on.
		return fmt.Errorf("netbox: interface %d not deleted: %w", id, err)
	}
	return c.do(ctx, http.MethodDelete, fmt.Sprintf(vmInterfacesPath+"%d/", id), nil, nil)
}

// clearPrimariesNaming clears whichever of the interface's VM's primaries
// names an address about to be detached from it, and only those: NetBox
// refuses the detach of a primary, and the interface's delete would have
// cleared it anyway, while a primary on another interface is not this
// delete's to touch.
//
// The interface read is the one step whose 404 passes through, because an
// interface that is gone is what the DELETE would have reported. Every other
// failure is reported without its status: a VM that cannot be read is not
// proof the interface is absent.
func (c *Client) clearPrimariesNaming(ctx context.Context, ifaceID int, detach []IPAddress) error {
	var iface ifaceJSON
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf(vmInterfacesPath+"%d/", ifaceID), nil, &iface); err != nil {
		return err
	}
	if iface.VirtualMachine == nil || iface.VirtualMachine.ID == 0 {
		return fmt.Errorf("netbox: interface %d not deleted: NetBox did not say which VM it belongs to, "+
			"so a primary address on it cannot be cleared first", ifaceID)
	}
	vmID := iface.VirtualMachine.ID
	var vm vmJSON
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf(vmsPath+"%d/", vmID), nil, &vm); err != nil {
		return fmt.Errorf("netbox: interface %d not deleted: read virtual machine %d: %v", ifaceID, vmID, err)
	}
	v := vm.toVM()
	clear := map[string]any{}
	for _, ip := range detach {
		if v.PrimaryIP4ID != 0 && v.PrimaryIP4ID == ip.ID {
			clear["primary_ip4"] = nil
		}
		if v.PrimaryIP6ID != 0 && v.PrimaryIP6ID == ip.ID {
			clear["primary_ip6"] = nil
		}
	}
	if err := c.clearPrimaries(ctx, vmID, clear); err != nil {
		return fmt.Errorf("netbox: interface %d not deleted: %v", ifaceID, err)
	}
	return nil
}

// vmInterfaceType is the content type of a VM interface in an address's
// generic assignment.
const vmInterfaceType = "virtualization.vminterface"

// detachAll clears the assignment of every address in ips, stopping at the
// first failure. The caller has already re-checked each one's assignment
// against what it asked for: a server that ignored a filter would return
// addresses assigned elsewhere, and clearing those would detach somebody
// else's address.
//
// A 404 on the detach is skipped only once a GET of the address also answers
// 404. NetBox scopes a PATCH to the objects the token may CHANGE and a GET to
// those it may VIEW, so a token that sees an address but may not change it
// gets a 404 on the PATCH while the address is still attached — and the
// DELETE that followed would cascade it away. Anything short of a 404 on the
// GET refuses the delete, and the refusal carries no status, so it is never
// read as the object being gone.
//
// An address carrying no litevirt identity is an operator's. It is detached
// all the same — the assignment cannot outlive the interface, and detaching
// keeps the object where the cascade would destroy it — and it is said out
// loud, because the operator learns of it from nothing else.
func (c *Client) detachAll(ctx context.Context, ips []IPAddress) error {
	for _, ip := range ips {
		err := c.ClearIPAssignment(ctx, ip.ID)
		var ae *APIError
		switch {
		case err == nil:
		case errors.As(err, &ae) && ae.Status == http.StatusNotFound:
			gone, gerr := c.addressGone(ctx, ip.ID)
			switch {
			case gerr != nil:
				// Nothing is known about the address, so the delete is refused —
				// with the GET's own failure, which is not a permission problem.
				return fmt.Errorf("detach address %d (%s): NetBox answered 404, and the GET that "+
					"would confirm it gone failed (%v); refusing to delete what may still hold it",
					ip.ID, ip.Address, gerr)
			case !gone:
				return &AddressNotChangeableError{ID: ip.ID, Address: ip.Address, AssignedTo: ip.AssignedObjectID}
			}
			continue
		default:
			return fmt.Errorf("detach address %d (%s): %v", ip.ID, ip.Address, err)
		}
		if !strings.HasPrefix(ip.Identity, "lv:") {
			slog.Warn("netbox: detached an address litevirt did not create from an interface it is "+
				"deleting; the address is kept, unassigned",
				"netbox_address_id", ip.ID, "address", ip.Address, "interface", ip.AssignedObjectID)
		}
	}
	return nil
}

// AddressNotChangeableError is a delete refused because an address on what is
// being deleted could not be detached, and a GET shows it still exists: the API
// token may view it but not change it. The DELETE would cascade it away, so
// nothing is deleted. A caller can withhold just that delete and report it —
// the fix is change permission on ipam.ipaddress for the token.
type AddressNotChangeableError struct {
	ID         int
	Address    string
	AssignedTo int // the interface it is assigned to
}

func (e *AddressNotChangeableError) Error() string {
	return fmt.Sprintf("NetBox address %d (%s) on interface %d is still attached and this API token "+
		"may view it but not change it, so it cannot be detached; deleting what holds it would "+
		"destroy it", e.ID, e.Address, e.AssignedTo)
}

// addressGone reports whether a GET of the address answers 404.
func (c *Client) addressGone(ctx context.Context, id int) (bool, error) {
	err := c.do(ctx, http.MethodGet, fmt.Sprintf(ipAddressesPath+"%d/", id), nil, nil)
	var ae *APIError
	switch {
	case err == nil:
		return false, nil
	case errors.As(err, &ae) && ae.Status == http.StatusNotFound:
		return true, nil
	default:
		return false, err
	}
}

// AssignIPToInterface attaches an existing address to an interface. NetBox's
// convention is IPs on interfaces, not on the VM.
func (c *Client) AssignIPToInterface(ctx context.Context, ipID, ifaceID int) error {
	body := map[string]any{
		"assigned_object_type": vmInterfaceType,
		"assigned_object_id":   ifaceID,
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(ipAddressesPath+"%d/", ipID), body, nil)
}

// ClearIPAssignment detaches an address from whatever holds it.
//
// It takes the ADDRESS id, not the interface id — assignment lives on the
// address object. Clearing keeps the object. The mirror's clear path still
// detaches only addresses it has proven litevirt owns; DeleteInterface and
// DeleteVM detach every address on what they delete, because the cascade
// would destroy it otherwise.
func (c *Client) ClearIPAssignment(ctx context.Context, ipID int) error {
	// Both halves go explicitly, and as null: an omitted key is a no-op on a
	// PATCH, which would leave the address attached to an interface that is
	// about to disappear.
	body := map[string]any{
		"assigned_object_type": nil,
		"assigned_object_id":   nil,
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf(ipAddressesPath+"%d/", ipID), body, nil)
}

// FindDeviceInCluster resolves a DCIM device id by name SCOPED TO clusterID,
// returning 0 when the device is absent or belongs to some other cluster.
// Neither is an error: the host link is best-effort by design, and an operator
// who does not model hosts in NetBox must still get a working mirror.
//
// THE SCOPE IS LOAD-BEARING, not an optimisation. NetBox validates that a
// virtual_machine's device belongs to that VM's own cluster, so a device outside
// it is not a weaker link — it is a 400 on the write. Resolving by name alone
// therefore turned the optional link into a sweep-ending refusal for the most
// ordinary NetBox there is: one whose hosts were already inventoried by
// something else and belong to no virtualization cluster at all. Nothing was
// mirrored, cluster-wide, for as long as that host stayed in the inventory,
// because the create phase aborts on the first refusal.
//
// Folding the constraint into the QUERY makes "not modelled" and "modelled
// outside this cluster" the same answer — no link — which is what best-effort
// has to mean for a link the server may reject.
//
// clusterID 0 means the caller has not resolved a cluster yet. Nothing can be
// scoped to it, so the answer is 0: no link, never an unscoped lookup that would
// reintroduce the refusal this exists to prevent.
func (c *Client) FindDeviceInCluster(ctx context.Context, name string, clusterID int) (int, error) {
	if clusterID == 0 {
		return 0, nil
	}
	scope := url.Values{}
	scope.Set("cluster_id", strconv.Itoa(clusterID))
	return c.firstIDByNameFiltered(ctx, devicesPath, name, scope)
}

// FindCluster resolves a cluster id by exact name, returning 0 when absent.
//
// The READ half of EnsureCluster, for the callers that must not create. The CA
// re-key enumerates a cluster's inventory to re-stamp it; bringing the cluster
// object into existence as a side effect of that question would have a re-key on
// a cluster that never mirrored anything leave a NetBox object behind. Absence
// is not an error — an absent cluster holds no inventory to re-key.
func (c *Client) FindCluster(ctx context.Context, name string) (int, error) {
	return c.firstIDByName(ctx, clustersPath, name)
}

// EnsureClusterType creates the litevirt cluster type if absent, returning its id.
func (c *Client) EnsureClusterType(ctx context.Context, name string) (int, error) {
	return c.ensureNamed(ctx, clusterTypesPath, name, map[string]any{
		"name": name, "slug": slugify(name),
	})
}

// EnsureCluster creates the cluster if absent and CONVERGES its site, returning
// its id.
//
// THE SITE IS WHY THIS IS NOT JUST ensureNamed. Every VM in a cluster inherits
// that cluster's site, and a mirrored VM with no site is invisible to anything
// that scopes by one — NetBox's own filters, and the DNS and inventory
// integrations built on them. litevirt cannot derive which site the hardware
// sits in, so it is operator-supplied (netbox.site), exactly like the cluster
// name.
//
// CONVERGED, not merely set at create. ensureNamed applies its body only when it
// creates, so an operator adding the site to config later would see it silently
// do nothing on every cluster that had ever mirrored — which is every cluster
// that matters.
//
// siteID 0 means UNMANAGED, and it must never be written through as null. The
// scope was settable by hand long before litevirt could supply it, so clearing
// it on an empty config would strip the site off a working cluster and take
// every VM's inherited site with it — silently undoing the thing this exists to
// provide. Unset leaves whatever is there.
func (c *Client) EnsureCluster(ctx context.Context, name string, typeID, siteID int) (int, error) {
	id, curType, curSite, err := c.findClusterScope(ctx, name)
	if err != nil {
		return 0, err
	}
	if id == 0 {
		body := map[string]any{"name": name, "type": typeID}
		if siteID != 0 {
			body["scope_type"] = siteScopeType
			body["scope_id"] = siteID
		}
		var created struct {
			ID int `json:"id"`
		}
		if err := c.do(ctx, http.MethodPost, clustersPath, body, &created); err != nil {
			return 0, err
		}
		return created.ID, nil
	}
	// Write-on-change. The cluster is resolved on EVERY sweep, so a PATCH per
	// sweep would be a write storm on a 15-minute timer.
	if siteID == 0 || (curType == siteScopeType && curSite == siteID) {
		return id, nil
	}
	return id, c.do(ctx, http.MethodPatch, fmt.Sprintf(clustersPath+"%d/", id), map[string]any{
		"scope_type": siteScopeType,
		"scope_id":   siteID,
	}, nil)
}

// siteScopeType is the content type a cluster's generic scope takes for a site.
// NetBox 4.2 replaced Cluster.site with scope_type/scope_id.
const siteScopeType = "dcim.site"

// findClusterScope resolves a cluster by exact name and returns its id and
// current scope, or id 0 when absent.
//
// The scope comes back from the SAME request as the id: the alternative is a
// detail GET per sweep purely to decide whether a PATCH is needed, which is a
// round trip bought for nothing on every pass of a converged mirror.
func (c *Client) findClusterScope(ctx context.Context, name string) (id int, scopeType string, scopeID int, err error) {
	q := url.Values{}
	q.Set("name", name)
	q.Set("limit", "1")
	var out struct {
		Results []struct {
			ID        int     `json:"id"`
			ScopeType *string `json:"scope_type"`
			ScopeID   *int    `json:"scope_id"`
		} `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, clustersPath+"?"+q.Encode(), nil, &out); err != nil {
		return 0, "", 0, err
	}
	if len(out.Results) == 0 {
		return 0, "", 0, nil
	}
	r := out.Results[0]
	if r.ScopeType != nil {
		scopeType = *r.ScopeType
	}
	if r.ScopeID != nil {
		scopeID = *r.ScopeID
	}
	return r.ID, scopeType, scopeID, nil
}

// FindSiteByName resolves a DCIM site id by name, returning 0 when absent.
// Absence is not an error: the caller reports a configured-but-missing site to
// the operator rather than failing a sweep over it.
func (c *Client) FindSiteByName(ctx context.Context, name string) (int, error) {
	return c.firstIDByName(ctx, sitesPath, name)
}

// ensureNamed resolves an object by exact name, creating it once if absent.
//
// The lookup is not idempotent against a concurrent create on another node: two
// nodes can both miss and both POST. NetBox's unique-name constraint turns the
// loser into a 4xx, which Classify reports as ClassClient — a caller retrying
// the whole ensure then finds the winner's object.
func (c *Client) ensureNamed(ctx context.Context, path, name string, body map[string]any) (int, error) {
	id, _, err := c.ensureNamedReportingCreate(ctx, path, name, body)
	return id, err
}

// ensureNamedReportingCreate is ensureNamed that also reports whether it created
// the object, so a caller with fields to CONVERGE can skip the read-back on the
// one path where the object provably already carries them.
func (c *Client) ensureNamedReportingCreate(ctx context.Context, path, name string, body map[string]any) (int, bool, error) {
	id, err := c.firstIDByName(ctx, path, name)
	if err != nil || id != 0 {
		return id, false, err
	}
	var created struct {
		ID int `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, path, body, &created); err != nil {
		return 0, false, err
	}
	return created.ID, true, nil
}

// firstIDByName reads the first object with an exact name, or 0.
//
// It deliberately does NOT paginate: name is an exact filter and only the first
// match is ever consumed, so limit=1 states that truncation is the intent rather
// than leaving an unbounded request that silently stops at NetBox's default page
// size.
func (c *Client) firstIDByName(ctx context.Context, path, name string) (int, error) {
	return c.firstIDByNameFiltered(ctx, path, name, nil)
}

// firstIDByNameFiltered is firstIDByName with additional filters ANDed in, for
// a lookup whose answer is only usable within some scope. `name` and `limit`
// are set last so a caller cannot accidentally widen either.
func (c *Client) firstIDByNameFiltered(ctx context.Context, path, name string, extra url.Values) (int, error) {
	q := url.Values{}
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	q.Set("name", name)
	q.Set("limit", "1")
	var out struct {
		Results []struct {
			ID int `json:"id"`
		} `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, path+"?"+q.Encode(), nil, &out); err != nil {
		return 0, err
	}
	if len(out.Results) == 0 {
		return 0, nil
	}
	return out.Results[0].ID, nil
}

// slugify renders a name as a NetBox slug. NetBox requires one on create and
// does not derive it for API callers.
func slugify(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
