package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// DuplicateAddressReporter makes an address on a host-isolated network that
// more than one workload's NIC rows hold visible: a WARN, and a
// `network.duplicate_address` event on each VM of the set that runs on this
// host (each host reports its own VMs, so a pair across two hosts gets one
// event per VM). A duplicate is reported once per daemon run until it clears;
// one that comes back is reported again.
type DuplicateAddressReporter struct {
	db   *corrosion.Client
	host string

	mu   sync.Mutex
	seen map[string]bool // reported and not yet cleared
}

// NewDuplicateAddressReporter reports for host.
func NewDuplicateAddressReporter(db *corrosion.Client, host string) *DuplicateAddressReporter {
	return &DuplicateAddressReporter{db: db, host: host, seen: map[string]bool{}}
}

// Report is a LoaderOptions.OnDuplicateAddresses.
func (r *DuplicateAddressReporter) Report(ctx context.Context, dups []corrosion.DuplicateAddress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := map[string]bool{}
	for _, d := range dups {
		var local []corrosion.NICOwner
		names := make([]string, 0, len(d.Owners))
		for _, o := range d.Owners {
			names = append(names, o.Kind+":"+o.Name)
			if o.Host == r.host {
				local = append(local, o)
			}
		}
		if len(local) == 0 {
			continue
		}
		key := d.Network + "|" + d.IP + "|" + strings.Join(names, ",")
		now[key] = true
		if r.seen[key] {
			continue
		}
		r.seen[key] = true
		slog.Warn("host-isolated network: one address is recorded for more than one workload",
			"network", d.Network, "address", d.IP, "holders", strings.Join(names, ", "))
		for _, o := range local {
			if o.Kind != "vm" {
				continue
			}
			if err := corrosion.InsertVMEvent(ctx, r.db, corrosion.VMEventRecord{
				VMName: o.Name, HostName: r.host, Type: "network.duplicate_address",
				Result: "error", Severity: "warn", Username: "firewall",
				Detail: fmt.Sprintf("address %s on network %s is also recorded for %s; the guests conflict on the network",
					d.IP, d.Network, othersThan(names, "vm:"+o.Name)),
			}); err != nil {
				slog.Warn("could not record the duplicate-address event", "vm", o.Name, "error", err)
				delete(r.seen, key) // try again next pass
			}
		}
	}
	for k := range r.seen {
		if !now[k] {
			delete(r.seen, k)
		}
	}
}

func othersThan(names []string, self string) string {
	var out []string
	for _, n := range names {
		if n != self {
			out = append(out, n)
		}
	}
	return strings.Join(out, ", ")
}
