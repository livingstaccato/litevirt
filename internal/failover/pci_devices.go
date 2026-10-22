package failover

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/placement"
	"github.com/litevirt/litevirt/internal/randid"
)

// A VM with PCI passthrough devices is recovered only onto a host with a free
// device of the kind each needs (placement.FailoverDeviceRequests), and one
// no survivor can take is held on its failed host with a vm_failover_held
// record that says what it waits for and what an operator can do. Its spec's
// litevirt.failover_without_devices label opts out: the VM is recovered as
// any other, and its new host starts it without the devices it has none for.

// addDevicePlacement adds to req what vm's PCI passthrough requires of its
// new host, and returns a description of each device for a hold. hold is
// not empty when the requirement cannot be stated: vm is not recovered this
// pass.
func (c *Coordinator) addDevicePlacement(ctx context.Context, req *placement.Request, vm corrosion.VMRecord) (devices []string, hold string) {
	spec := &pb.VMSpec{}
	if vm.Spec != "" && json.Unmarshal([]byte(vm.Spec), spec) == nil && corrosion.FailoverWithoutDevices(spec) {
		return nil, ""
	}
	reqs, descs, err := placement.FailoverDeviceRequests(ctx, c.db, vm)
	if err != nil {
		slog.Warn("failover: cannot state what a VM's PCI devices require of a host; leaving it this pass (fail closed)",
			"vm", vm.Name, "error", err)
		return nil, "what its PCI passthrough devices require of a host cannot be read: " + err.Error()
	}
	req.Devices = reqs
	// A device the VM itself still holds (on a host it ran on before, back
	// since) is free to it: its new host starts it with that one.
	if len(reqs) > 0 {
		req.ReuseDevicesOf = vm.Name
	}
	return descs, ""
}

// holdForDevices holds vm on host, its failed host: no survivor can take it
// with its PCI passthrough devices. devices describes them; why is the
// placement's verdict. The recovery of host runs again on the next tick.
func (c *Coordinator) holdForDevices(ctx context.Context, host string, vm corrosion.VMRecord, devices []string, why string) {
	c.mVM(ActionReschedule, ResultSkipped, ErrPlacementFailed)
	detail, err := health.RecordHeldForDevices(ctx, c.db, c.hostName, vm.Name, host, devices, why, c.now())
	if err != nil {
		slog.Error("failover: could not record a VM held for its PCI devices", "vm", vm.Name, "host", host, "error", err)
		detail = "held on " + host + ": no surviving host has a free PCI device of the kind its passthrough needs (" +
			strings.Join(devices, "; ") + ")"
	}
	c.noteHold(host, "VM "+vm.Name+": "+detail)
	// Placed again on the next tick, as a refused recovery claim is
	// (retryClaims): a device freed or added on a survivor, or the spec's
	// opt-in, lets it go then, not only at the next fence of host.
	c.retryClaimsFor(host)
	slog.Warn("failover: VM with PCI passthrough left on its failed host — no survivor has its devices",
		"vm", vm.Name, "host", host, "devices", devices, "reason", why)
	if !c.auditSkip(ctx, host, vm.Name, detail, "skipped") {
		return
	}
	if err := corrosion.InsertVMEvent(ctx, c.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: vm.Name, HostName: c.hostName, Type: "vm.failover.held",
		Result: "ok", Severity: "warn", Detail: detail, Username: "failover-coordinator",
	}); err != nil {
		slog.Warn("failover: record the held VM's event", "vm", vm.Name, "error", err)
	}
	c.publish("vm.failover.held", vm.Name, detail)
}

// selectBatch is placement.SelectBatchWithMappings over the PCI inventory of
// hosts and the resource mappings the requests name, read here: SelectBatch
// cannot read them itself. A read that fails leaves every request with
// devices unplaced (its result's Err says why) and places the others.
func (c *Coordinator) selectBatch(ctx context.Context, hosts []corrosion.HostRecord, allVMs []corrosion.VMRecord,
	ctMem map[string]int, obs []corrosion.HostCapacityObservation, now time.Time, reqs []placement.Request) (map[string]placement.BatchResult, error) {
	devices, mappings, err := placement.LoadDevicePools(ctx, c.db, hosts, reqs)
	if err == nil {
		return placement.SelectBatchWithMappings(hosts, allVMs, devices, mappings, ctMem, obs, now, reqs)
	}
	slog.Warn("failover: cannot read the PCI inventory; VMs with PCI devices are left this pass (fail closed)", "error", err)
	unplaced := map[string]placement.BatchResult{}
	rest := make([]placement.Request, 0, len(reqs))
	for _, r := range reqs {
		if len(r.Devices) > 0 {
			unplaced[r.VMName] = placement.BatchResult{Err: fmt.Errorf("its PCI devices cannot be judged: %w", err)}
			continue
		}
		rest = append(rest, r)
	}
	out, serr := placement.SelectBatch(hosts, allVMs, nil, ctMem, obs, now, rest)
	if serr != nil {
		return nil, serr
	}
	for k, v := range unplaced {
		out[k] = v
	}
	return out, nil
}
