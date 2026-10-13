package grpcapi

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/network"
)

// deferredTeardownError is a provision failure on this host while a DELETED
// network whose teardown here waits on a local user (DeleteNetwork --force,
// or a tombstone the reconciler is holding) still serves an overlapping
// subnet. Its dnsmasq keeps the gateway address, so the new network's dnsmasq
// exits at once, and on its own that exit names nothing an operator can act
// on (lab finding N3).
//
// The network row has already landed when this is returned: the create did
// what it always did, and the reconciler provisions it here once the old
// teardown finishes.
type deferredTeardownError struct {
	name, holder, holderSubnet, inUseBy string
	err                                 error
}

func (e *deferredTeardownError) Error() string {
	return fmt.Sprintf("network %q was created, but this host cannot provision it yet: deleted network %q "+
		"still serves subnet %s here, because its teardown on this host waits until nothing uses it "+
		"(in use by %s). This host provisions %q by itself once that teardown finishes; to finish it now, "+
		"move or remove what still uses %q (%v)",
		e.name, e.holder, e.holderSubnet, e.inUseBy, e.name, e.holder, e.err)
}

func (e *deferredTeardownError) Unwrap() error { return e.err }

// explainProvisionFailure returns provErr, explained by a deferred teardown
// when one is the likely cause (deferredTeardownError). It only adds
// information: any read that fails leaves provErr as it was.
func (s *Server) explainProvisionFailure(ctx context.Context, name string, def compose.NetworkDef, provErr error) error {
	if provErr == nil || def.Subnet == "" {
		return provErr
	}
	mine, err := netip.ParsePrefix(def.Subnet)
	if err != nil {
		return provErr
	}
	rows, err := s.db.Query(ctx,
		`SELECT name, type, config, deleted_at FROM networks WHERE deleted_at IS NOT NULL AND name != ?`, name)
	if err != nil {
		return provErr
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].String("name") < rows[j].String("name") })
	for _, r := range rows {
		old := networkRow{name: r.String("name"), typ: r.String("type"), config: r.String("config"), deletedAt: r.String("deleted_at")}
		if old.config == "" {
			continue
		}
		oldDef, err := networkRowDef(old)
		if err != nil || oldDef.Subnet == "" {
			continue
		}
		p, err := netip.ParsePrefix(oldDef.Subnet)
		if err != nil || !p.Overlaps(mine) {
			continue
		}
		what, err := s.networkUseHere(ctx, old.name, network.BridgeName(old.name, oldDef))
		if err != nil || what == "" {
			continue
		}
		return &deferredTeardownError{
			name: name, holder: old.name, holderSubnet: oldDef.Subnet, inUseBy: what, err: provErr,
		}
	}
	return provErr
}
