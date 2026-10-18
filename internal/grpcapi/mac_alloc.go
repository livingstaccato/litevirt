package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A generated VM MAC has 24 random bits (52:54:00:xx:xx:xx), so with a few
// thousand NICs in a cluster two of them drawing the same one is likely
// unless the draw is checked. A MAC another live NIC records (vm_nics,
// vm_interfaces, container_interfaces, an IPAM lease) is drawn again, up to
// macDrawAttempts times. Two hosts drawing one MAC at the same moment, each
// before seeing the other's row, is caught after the fact by
// ReconcileMACCollisions.

// macDrawAttempts bounds the redraws. At 2^24 MACs a full draw sequence
// failing needs the space nearly full, so exhausting it is an error, not a
// reason to hand out a duplicate.
const macDrawAttempts = 64

var (
	macDrawMu sync.RWMutex
	macDraw   = lv.GenerateMAC
)

// SetMACDrawForTests replaces the random MAC source and returns a func that
// restores it.
func SetMACDrawForTests(draw func() string) (restore func()) {
	macDrawMu.Lock()
	prev := macDraw
	macDraw = draw
	macDrawMu.Unlock()
	return func() {
		macDrawMu.Lock()
		macDraw = prev
		macDrawMu.Unlock()
	}
}

func drawMAC() string {
	macDrawMu.RLock()
	d := macDraw
	macDrawMu.RUnlock()
	return strings.ToLower(d())
}

// macAllocator hands out MACs no live NIC of the cluster records and that
// it has not handed out (or been told of) already. The cluster's MACs are
// read on the first draw, so a request whose NICs all name a MAC reads
// nothing.
type macAllocator struct {
	s      *Server
	taken  map[string]bool
	loaded bool
}

func (s *Server) newMACAllocator() *macAllocator {
	return &macAllocator{s: s, taken: map[string]bool{}}
}

// reserve marks mac as in use: a MAC another NIC of the same request names.
func (a *macAllocator) reserve(mac string) {
	if mac != "" {
		a.taken[strings.ToLower(mac)] = true
	}
}

// next draws a MAC that is not taken. A read failure of the cluster's MACs
// fails the draw: a MAC that cannot be checked is not handed out.
func (a *macAllocator) next(ctx context.Context) (string, error) {
	if !a.loaded {
		if a.s.db != nil {
			ids, err := corrosion.LiveNICIdentities(ctx, a.s.db)
			if err != nil {
				return "", status.Errorf(codes.Internal, "read the cluster's NIC MACs: %v", err)
			}
			for _, id := range ids {
				if id.MAC != "" {
					a.taken[id.MAC] = true
				}
			}
		}
		a.loaded = true
	}
	for i := 0; i < macDrawAttempts; i++ {
		m := drawMAC()
		if !a.taken[m] {
			a.taken[m] = true
			return m, nil
		}
	}
	return "", status.Errorf(codes.ResourceExhausted,
		"no free MAC address after %d draws: every one drawn is already used by a NIC of the cluster", macDrawAttempts)
}

// macHolderOtherThan returns the owner of a live NIC that records one of
// macs, other than owners; "" when none does.
func (s *Server) macHolderOtherThan(ctx context.Context, macs []string, owners ...string) (mac, holder string, err error) {
	want := map[string]bool{}
	for _, m := range macs {
		if m != "" {
			want[strings.ToLower(m)] = true
		}
	}
	if len(want) == 0 || s.db == nil {
		return "", "", nil
	}
	ids, err := corrosion.LiveNICIdentities(ctx, s.db)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "read the cluster's NIC MACs: %v", err)
	}
	mine := map[string]bool{}
	for _, o := range owners {
		mine[o] = true
	}
	for _, id := range ids {
		if want[id.MAC] && !mine[id.Owner] {
			return id.MAC, id.Owner, nil
		}
	}
	return "", "", nil
}

const (
	// NICIdentityEvaluator files the MAC collision condition.
	NICIdentityEvaluator = "nic_identity"
	// CondMACDuplicate is raised on a host while a NIC of a workload on it
	// shares its MAC with a NIC of another workload.
	CondMACDuplicate = "mac_duplicate"
	// MACCollisionReconcileInterval is how often the daemon looks.
	MACCollisionReconcileInterval = time.Minute
)

// ReconcileMACCollisions raises mac_duplicate on this host while a NIC of a
// workload here records a MAC a NIC of another workload records (two hosts
// that drew one MAC at once, or rows an older build wrote), naming both
// NICs, and resolves it once none does. It changes no NIC: a running
// guest's MAC is the operator's to change.
func (s *Server) ReconcileMACCollisions(ctx context.Context) {
	if s.db == nil {
		return
	}
	cols, err := corrosion.ListMACCollisions(ctx, s.db)
	if err != nil {
		slog.Warn("MAC collisions: read the cluster's NICs", "error", err)
		return
	}
	var parts []string
	for _, c := range cols {
		here := false
		var nics []string
		for _, h := range c.Holders {
			here = here || h.Host == s.hostName
			kind := "VM"
			if h.Kind == "ct" {
				kind = "container"
			}
			nics = append(nics, fmt.Sprintf("%s %s (network %s, host %s)", kind, h.Name, h.Network, h.Host))
		}
		if here {
			parts = append(parts, fmt.Sprintf("MAC %s is on %s", c.MAC, strings.Join(nics, " and ")))
		}
	}
	detail := ""
	if len(parts) > 0 {
		detail = strings.Join(parts, "; ") + ". Two NICs on one MAC break each other's traffic and DHCP, and a guard keyed by the MAC admits the other's; " +
			"nothing was changed. Give one of them a new MAC: for a VM, `lv detach-nic <vm> <mac>`, then `lv attach-nic <vm> <network>`; " +
			"a container's NIC gets one only when the container is created again"
	}
	s.setHostCondition(ctx, NICIdentityEvaluator, CondMACDuplicate, len(parts) > 0, corrosion.SeverityCritical, detail)
}
