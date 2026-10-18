package grpcapi

import (
	"context"
	"crypto/rand"
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
	ctMACDraw = randomContainerMAC
)

// SetMACDrawForTests replaces the random VM MAC source and returns a func
// that restores it.
func SetMACDrawForTests(draw func() string) (restore func()) {
	return setDraw(&macDraw, draw)
}

// SetContainerMACDrawForTests replaces the random container MAC source (the
// fallback for a derived MAC another NIC holds) and returns a func that
// restores it.
func SetContainerMACDrawForTests(draw func() string) (restore func()) {
	return setDraw(&ctMACDraw, draw)
}

func setDraw(v *func() string, draw func() string) func() {
	macDrawMu.Lock()
	prev := *v
	*v = draw
	macDrawMu.Unlock()
	return func() {
		macDrawMu.Lock()
		*v = prev
		macDrawMu.Unlock()
	}
}

func drawWith(v *func() string) string {
	macDrawMu.RLock()
	d := *v
	macDrawMu.RUnlock()
	return strings.ToLower(d())
}

// randomContainerMAC is a random MAC in the container scheme of
// corrosion.ContainerMAC: 0x52 (locally administered, unicast), then 40
// random bits.
func randomContainerMAC() string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return fmt.Sprintf("52:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4])
}

// macSet is the cluster's MACs as one request reads them, once: the live
// NICs (corrosion.LiveMACHolders, the one definition the collision scan
// uses too) and the live IPAM leases, a DHCP reservation by MAC.
type macSet struct {
	holders map[string][]corrosion.MACHolder
	leases  map[string][]string
}

func (s *Server) loadMACSet(ctx context.Context) (*macSet, error) {
	if s.db == nil {
		return &macSet{}, nil
	}
	h, err := corrosion.LiveMACHolders(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the cluster's NIC MACs: %v", err)
	}
	l, err := corrosion.LiveLeaseMACs(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the cluster's address leases: %v", err)
	}
	return &macSet{holders: h, leases: l}, nil
}

// heldBy returns a holder of mac other than owners (as LiveNICIdentities
// names them), or "".
func (m *macSet) heldBy(mac string, owners ...string) string {
	mac = strings.ToLower(mac)
	mine := func(o string) bool {
		for _, x := range owners {
			if x == o {
				return true
			}
		}
		return false
	}
	for _, h := range m.holders[mac] {
		if !mine(h.Owner) {
			return h.Owner
		}
	}
	for _, o := range m.leases[mac] {
		if !mine(o) {
			return o
		}
	}
	return ""
}

// firstHeld returns the first of macs another holder has, and the holder.
func (m *macSet) firstHeld(macs []string, owners ...string) (mac, holder string) {
	for _, x := range macs {
		if x == "" {
			continue
		}
		if h := m.heldBy(x, owners...); h != "" {
			return strings.ToLower(x), h
		}
	}
	return "", ""
}

// macAllocator hands out MACs no live NIC or lease of the cluster has and
// that it has not handed out (or been told of) already. The cluster's MACs
// are read on the first draw, so a request whose NICs all name a MAC reads
// nothing.
type macAllocator struct {
	s     *Server
	set   *macSet
	taken map[string]bool
}

func (s *Server) newMACAllocator() *macAllocator {
	return &macAllocator{s: s, taken: map[string]bool{}}
}

// newMACAllocatorFrom draws against a set the request already read.
func (s *Server) newMACAllocatorFrom(set *macSet) *macAllocator {
	return &macAllocator{s: s, set: set, taken: map[string]bool{}}
}

// reserve marks mac as in use: a MAC another NIC of the same request names.
func (a *macAllocator) reserve(mac string) {
	if mac != "" {
		a.taken[strings.ToLower(mac)] = true
	}
}

// free reports whether mac is neither held in the cluster nor taken by this
// request. A read failure of the cluster's MACs is an error: a MAC that
// cannot be checked is not handed out.
func (a *macAllocator) free(ctx context.Context, mac string, owners ...string) (bool, error) {
	if a.set == nil {
		set, err := a.s.loadMACSet(ctx)
		if err != nil {
			return false, err
		}
		a.set = set
	}
	mac = strings.ToLower(mac)
	return !a.taken[mac] && a.set.heldBy(mac, owners...) == "", nil
}

// next draws a VM MAC (52:54:00 and 24 random bits) that is free.
func (a *macAllocator) next(ctx context.Context) (string, error) {
	return a.draw(ctx, &macDraw)
}

// nextContainer draws a container MAC (corrosion.ContainerMAC's scheme, 40
// random bits) that is free.
func (a *macAllocator) nextContainer(ctx context.Context) (string, error) {
	return a.draw(ctx, &ctMACDraw)
}

func (a *macAllocator) draw(ctx context.Context, src *func() string) (string, error) {
	for i := 0; i < macDrawAttempts; i++ {
		m := drawWith(src)
		ok, err := a.free(ctx, m)
		if err != nil {
			return "", err
		}
		if ok {
			a.taken[m] = true
			return m, nil
		}
	}
	return "", status.Errorf(codes.ResourceExhausted,
		"no free MAC address after %d draws: every one drawn is already used by a NIC of the cluster", macDrawAttempts)
}

// macHolderOtherThan returns the first of macs a live NIC or lease of
// another owner than owners holds, and that owner; "" when none does.
func (s *Server) macHolderOtherThan(ctx context.Context, macs []string, owners ...string) (mac, holder string, err error) {
	some := false
	for _, m := range macs {
		some = some || m != ""
	}
	if !some {
		return "", "", nil
	}
	set, err := s.loadMACSet(ctx)
	if err != nil {
		return "", "", err
	}
	mac, holder = set.firstHeld(macs, owners...)
	return mac, holder, nil
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
		detail = strings.Join(parts, "; ") + ". On one network the MAC-keyed forwarding entries (vxlan) and DHCP reservations deliver one's traffic and DHCP replies to the other; " +
			"nothing was changed, and a stopped VM among them is refused `lv start`. Give one of them a new MAC: for a VM, `lv detach-nic <vm> <mac>`, then `lv attach-nic <vm> <network>`; " +
			"for a container, create it again (`lv ct rm`, then `lv ct create`)"
	}
	s.setHostCondition(ctx, NICIdentityEvaluator, CondMACDuplicate, len(parts) > 0, corrosion.SeverityCritical, detail)
}

// refuseStartOnSharedMAC refuses an operator start of the stopped VM name
// while one of its NICs' MACs is held by another workload's NIC or lease
// (mac_duplicate): the start would put two NICs on one MAC. Nothing is
// rewritten; the refusal names the way out.
func (s *Server) refuseStartOnSharedMAC(ctx context.Context, name string) error {
	if s.db == nil {
		return nil
	}
	nics, err := corrosion.MergedVMNICs(ctx, s.db, name)
	if err != nil {
		return status.Errorf(codes.Unavailable, "start %q: read its NICs: %v", name, err)
	}
	if len(nics) == 0 {
		return nil
	}
	macs := make([]string, 0, len(nics))
	for _, n := range nics {
		macs = append(macs, n.MAC)
	}
	mac, holder, err := s.macHolderOtherThan(ctx, macs, name)
	if err != nil {
		return err
	}
	if holder != "" {
		return status.Errorf(codes.FailedPrecondition,
			"start %q: its NIC's MAC %s is also used by %s (mac_duplicate); started, the two would share one MAC. "+
				"Give this NIC a new MAC first: `lv detach-nic %s %s`, then `lv attach-nic %s <network>`",
			name, mac, holder, name, mac, name)
	}
	return nil
}
