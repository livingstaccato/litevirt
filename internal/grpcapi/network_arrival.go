package grpcapi

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
)

// Each attempt owns its exact returned devices until the target observes its
// domain or that attempt explicitly cleans up. No timeout can establish that
// a source libvirt job has stopped. A lost source therefore retains the hold
// until retry/cleanup, including across a daemon restart in the same boot.
type networkArrival struct {
	VM        string            `json:"vm"`
	CreatedAt string            `json:"created_at"`
	Devices   map[string]string `json:"devices"`
}
type networkArrivalKey struct{}

func withNetworkArrival(ctx context.Context) context.Context {
	return context.WithValue(ctx, networkArrivalKey{}, uuid.NewString())
}
func networkArrivalID(ctx context.Context) string {
	id, _ := ctx.Value(networkArrivalKey{}).(string)
	return id
}

// Caller holds the transition read side continuously from MTU judgement to
// recording this map. Legacy callers without an attempt ID can still arrive;
// their tokenless cleanup cannot release a newer or ambiguous hold.
func (s *Server) holdNetworkArrival(ctx context.Context, vm *corrosion.VMRecord, id string) (map[string]string, error) {
	if id == "" {
		id = uuid.NewString()
	}
	devices := s.servedNetworkDevices(ctx, vm.Name)
	d := &s.netDevs
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadLocked()
	if d.loadErr != nil {
		return nil, d.loadErr
	}
	if prior, ok := d.arrivals[id]; ok {
		if prior.VM != vm.Name || prior.CreatedAt != vm.CreatedAt {
			return nil, fmt.Errorf("arrival identity already belongs to another VM incarnation")
		}
		// A retry of the same attempt receives the same device promise.
		devices = prior.Devices
	} else if len(devices) > 0 {
		d.arrivals[id] = networkArrival{VM: vm.Name, CreatedAt: vm.CreatedAt, Devices: devices}
	}
	if err := d.saveLocked(); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for n, dev := range devices {
		out[n] = dev
	}
	return out, nil
}
func (s *Server) releaseNetworkArrival(ctx context.Context, vm, id string) error {
	release, err := s.netDevs.acquireTransition(ctx, true)
	if err != nil {
		return err
	}
	defer release()
	d := &s.netDevs
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadLocked()
	a, ok := d.arrivals[id]
	if !ok || a.VM != vm {
		return nil
	}
	delete(d.arrivals, id)
	if err := d.saveLocked(); err != nil {
		d.arrivals[id] = a
		return err
	}
	return nil
}

// An observed matching domain replaces the future-arrival holder. Merely
// observing a row or a capacity reservation cannot do so. Unreadable runtime
// or row identity conservatively retains the promise.
func (s *Server) networkArrivalUsers(ctx context.Context) map[string]deviceUse {
	d := &s.netDevs
	d.mu.Lock()
	d.loadLocked()
	holds := make(map[string]networkArrival, len(d.arrivals))
	for id, a := range d.arrivals {
		holds[id] = a
	}
	d.mu.Unlock()
	out := map[string]deviceUse{}
	for id, a := range holds {
		arrived := false
		if s.virt != nil {
			rec, e := corrosion.GetVM(ctx, s.db, a.VM)
			if e == nil && rec != nil && rec.CreatedAt == a.CreatedAt && rec.HostName == s.hostName {
				x, e := s.virt.DumpXMLInactive(a.VM)
				active, aerr := s.virt.DomainIsActive(a.VM)
				if e == nil && aerr == nil && active {
					have := map[string]bool{}
					for _, dev := range libvirt.InterfaceBridges(x) {
						have[dev] = true
					}
					arrived = len(a.Devices) > 0
					for _, dev := range a.Devices {
						arrived = arrived && have[dev]
					}
				}
			}
		}
		if arrived {
			d.mu.Lock()
			delete(d.arrivals, id)
			if err := d.saveLocked(); err != nil {
				d.arrivals[id] = a
			}
			d.mu.Unlock()
			// The actual holder is read again by deviceUsersAll before retirement.
			continue
		}
		for _, dev := range a.Devices {
			u := out[dev]
			u.running = append(u.running, "incoming VM "+a.VM+" ("+id+")")
			out[dev] = u
		}
	}
	return out
}
