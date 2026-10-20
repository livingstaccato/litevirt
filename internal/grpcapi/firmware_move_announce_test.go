package grpcapi

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A live firmware move's guest, and a guest the firmware-move doctor moves,
// learns its gateway is now behind the host it runs on: that host announces
// the gateway of each of its networks out of its own bridge, once the guest
// runs (announceGatewaysOf). A guest held paused reads no gratuitous ARP, and
// a returned guest that is not running gets none.

// fwAnnounced records the announcements of the rig's two hosts, with the
// state of the VM's domain on that host when each was sent.
type fwAnnounced struct {
	mu  sync.Mutex
	got []string
}

func (a *fwAnnounced) all() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.got)
}

// waitFor waits, up to a bound, for want among the announcements: they are
// sent from a goroutine.
func (a *fwAnnounced) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !slices.Contains(a.all(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("no announcement %q; got %v", want, a.all())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// none waits a while for an announcement that must not come.
func (a *fwAnnounced) none(t *testing.T) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	if got := a.all(); len(got) > 0 {
		t.Fatalf("announced %v, want nothing", got)
	}
}

// announceOn gives fwlVM a NIC on a bridge network with a subnet (gateway
// 172.46.0.1 on bridge lan) and records what both hosts announce.
func announceOn(t *testing.T, r *fwlRig) *fwAnnounced {
	t.Helper()
	ctx := context.Background()
	def := compose.NetworkDef{Type: "bridge", Interface: "lan", Subnet: "172.46.0.0/24"}
	cfg, _ := json.Marshal(def)
	if err := corrosion.UpsertNetwork(ctx, r.src.db, corrosion.NetworkRecord{Name: "st_lan", Type: def.Type, Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertInterface(ctx, r.src.db, corrosion.InterfaceRecord{VMName: fwlVM, NetworkName: "st_lan", Ordinal: 0,
		MAC: "52:54:00:00:00:01", IP: "172.46.0.7"}); err != nil {
		t.Fatal(err)
	}
	a := &fwAnnounced{}
	for _, h := range []struct {
		s    *Server
		fake *libvirtfake.Fake
	}{{r.src, r.srcFake}, {r.dst, r.dstFake}} {
		host, fake := h.s.hostName, h.fake
		h.s.SetGatewayAnnouncer(func(bridge string, gw netip.Addr) (bool, error) {
			st, _ := fake.DomainState(fwlVM)
			a.mu.Lock()
			a.got = append(a.got, host+" "+bridge+" "+gw.String()+" "+st)
			a.mu.Unlock()
			return true, nil
		})
	}
	return a
}

func TestFirmwareMove_AnnouncesGatewaysWhereTheGuestRuns(t *testing.T) {
	// A completed live move: the target announces once Release has resumed
	// the guest, never while it is held paused.
	// Mutation: drop the announcement from resumeReleased — red.
	t.Run("live_move/target_announces_after_the_resume", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		a := announceOn(t, r)
		if err := r.migrate(); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		a.waitFor(t, "dst-host lan 172.46.0.1 running")
		for _, g := range a.all() {
			if g != "dst-host lan 172.46.0.1 running" {
				t.Errorf("announcement %q, want only the target's, with its guest running", g)
			}
		}
	})

	// Mutation: drop the announcement from convergeMovedGuest — red (each
	// of the next two).
	t.Run("doctor_adopt/target_announces", func(t *testing.T) {
		r, _ := lostWithOwed(t, true, false, "")
		a := announceOn(t, r)
		if _, err := r.doctor(actAdopt); err != nil {
			t.Fatalf("adopt: %v", err)
		}
		a.waitFor(t, "dst-host lan 172.46.0.1 running")
	})
	t.Run("doctor_return_source_running/source_announces", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.srcFake.SetState(fwlVM, libvirtfake.StateRunning)
		r.park(run, fwmig.PhaseSourceStateSuspect, "the source domain is active again although the move cut over")
		a := announceOn(t, r)
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "running")
		a.waitFor(t, "src-host lan 172.46.0.1 running")
	})
	// Mutation: announce whatever the source's state — red.
	t.Run("doctor_return_source_stopped/nothing_announced", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		r.fenceTarget()
		a := announceOn(t, r)
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
		a.none(t)
	})
}
