package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// The follow-ups to the container replica restore's "no live copy anywhere"
// (t2-dr-rereview-5.md P1-P4). Each peer here is a real Server answering
// GetRuntimeInventory from its own runtime, so the asking side and the
// answering side are tested together.

// serverPeer routes a peer's runtime ask to a real Server, and answers
// ListContainers with the live rows its view holds.
type serverPeer struct {
	pb.LiteVirtClient
	srv  *Server
	ctx  context.Context
	rows []*pb.Container
}

func (p *serverPeer) ListContainers(context.Context, *pb.ListContainersRequest, ...grpc.CallOption) (*pb.ListContainersResponse, error) {
	return &pb.ListContainersResponse{Containers: p.rows}, nil
}

func (p *serverPeer) GetRuntimeInventory(_ context.Context, req *pb.GetRuntimeInventoryRequest, _ ...grpc.CallOption) (*pb.RuntimeInventory, error) {
	return p.srv.GetRuntimeInventory(p.ctx, req)
}

// restoreCT is a container runtime holding the containers names (stopped),
// with an on-disk owner record per name and a directory per name.
type restoreCT struct {
	*fakeCT
	owners   map[string]lxc.ContainerOwner
	ownerErr error
	dirs     map[string]bool
	dirErr   error
}

func (r *restoreCT) ReadOwner(name string) (*lxc.ContainerOwner, error) {
	if r.ownerErr != nil {
		return nil, r.ownerErr
	}
	if o, ok := r.owners[name]; ok {
		return &o, nil
	}
	return nil, nil
}

func (r *restoreCT) StampOwner(string, lxc.ContainerOwner) error { return nil }

func (r *restoreCT) ContainerExists(_ context.Context, name string) (bool, error) {
	if r.dirErr != nil {
		return false, r.dirErr
	}
	return r.dirs[name], nil
}

func newRestoreCT(names ...string) *restoreCT {
	st := map[string]string{}
	dirs := map[string]bool{}
	for _, n := range names {
		st[n] = "stopped"
		dirs[n] = true
	}
	return &restoreCT{fakeCT: &fakeCT{names: names, states: st}, owners: map[string]lxc.ContainerOwner{}, dirs: dirs}
}

// countingVirt is a libvirt that counts how often its domains are listed.
type countingVirt struct {
	*recordingVirt
	lists atomic.Int32
}

func (c *countingVirt) ListDomains() ([]string, error) {
	c.lists.Add(1)
	return c.recordingVirt.ListDomains()
}

// restorePeerHost is a real Server for host name, LXC-capable, with ct as its
// container runtime and virt as its libvirt (nil for none).
func restorePeerHost(t *testing.T, name string, ct ContainerRuntime, virt LibvirtBackend) *Server {
	t.Helper()
	p := testServer(t)
	p.hostName = name
	p.containersRoot = t.TempDir()
	p.SetLXCCapableForTest(true)
	if ct != nil {
		p.SetContainerRuntime(ct)
	}
	if virt != nil {
		p.virt = virt
	}
	return p
}

// followupCluster is the replica host "self" in a cluster of self, src, h2,
// h3; src and h3 answer none, h2 answers as peer does.
func followupCluster(t *testing.T, h2 *Server, h2rows []*pb.Container) *Server {
	t.Helper()
	none := func() *absencePeer { return &absencePeer{} }
	s := absenceServer(t, nil)
	views := map[string]pb.LiteVirtClient{
		"src": none(), "h3": none(),
		"h2": &serverPeer{srv: h2, ctx: peerCtxFor(t, h2, "self"), rows: h2rows},
	}
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if p, ok := views[host]; ok {
			return p, func() {}, nil
		}
		return nil, nil, status.Errorf(codes.Unavailable, "%s is down", host)
	}
	return s
}

func refusedNaming(err error, want string) bool {
	return status.Code(err) == codes.FailedPrecondition && strings.Contains(err.Error(), want)
}

// P1: an inventory made incomplete by something other than containers (a VM
// probe, a marker, the VIP dump) still proves a container absent when the
// container listing itself succeeded and holds no container of the name.
func TestConfirmNoLiveCopy_ContainerListingProvesAbsence(t *testing.T) {
	ctx := context.Background()
	brokenVirt := &recordingVirt{listErr: fmt.Errorf("libvirt down")}

	t.Run("a peer whose libvirt cannot be read", func(t *testing.T) {
		h2 := restorePeerHost(t, "h2", newRestoreCT("other"), brokenVirt)
		s := followupCluster(t, h2, nil)
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); err != nil {
			t.Fatalf("h2 listed its containers and has no web; only its libvirt is unreadable: %v", err)
		}
	})
	t.Run("this host's libvirt cannot be read", func(t *testing.T) {
		h2 := restorePeerHost(t, "h2", newRestoreCT(), nil)
		s := followupCluster(t, h2, nil)
		s.containersRoot = t.TempDir()
		s.SetLXCCapableForTest(true)
		s.SetContainerRuntime(newRestoreCT("other"))
		s.virt = brokenVirt
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); err != nil {
			t.Fatalf("this host listed its containers and has no web; only its libvirt is unreadable: %v", err)
		}
	})
	t.Run("a peer whose container listing fails is still no answer", func(t *testing.T) {
		ct := newRestoreCT()
		ct.listErr = errors.New("lxc-ls: boom")
		h2 := restorePeerHost(t, "h2", ct, nil)
		s := followupCluster(t, h2, nil)
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); !refusedNaming(err, "cannot confirm with h2") {
			t.Fatalf("h2 could not list its containers: %v, want refused naming h2", err)
		}
	})
	t.Run("a peer whose own probe of the container fails is still no answer", func(t *testing.T) {
		h2 := restorePeerHost(t, "h2", newRestoreCT("web"), brokenVirt)
		h2.containerRuntime.(*restoreCT).states["web"] = "FROZEN"
		s := followupCluster(t, h2, nil)
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); !refusedNaming(err, "cannot confirm with h2") {
			t.Fatalf("h2 holds web in a state it could not read: %v, want refused naming h2", err)
		}
	})
	t.Run("an older peer's incomplete inventory is still no answer", func(t *testing.T) {
		// A peer of the previous build sends no container completeness: its
		// whole-host bit is all there is.
		s := absenceServer(t, map[string]*absencePeer{
			"src": {}, "h3": {},
			"h2": {runtime: &pb.RuntimeInventory{Complete: false, Errors: []string{"list domains: boom"}}},
		})
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); !refusedNaming(err, "cannot confirm with h2") {
			t.Fatalf("an older peer's incomplete inventory: %v, want refused naming h2", err)
		}
	})
}

// P2: the runtime ask of a restore probes the containers only; a member's
// libvirt (however many VMs, however slow) is not on its path.
func TestConfirmNoLiveCopy_RuntimeAskDoesNotProbeLibvirt(t *testing.T) {
	ctx := context.Background()
	peerVirt := &countingVirt{recordingVirt: &recordingVirt{domains: map[string]string{"vm1": "running"}}}
	h2 := restorePeerHost(t, "h2", newRestoreCT(), peerVirt)
	s := followupCluster(t, h2, nil)
	selfVirt := &countingVirt{recordingVirt: &recordingVirt{domains: map[string]string{"vm2": "running"}}}
	s.virt = selfVirt
	if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); err != nil {
		t.Fatalf("no copy anywhere: %v", err)
	}
	if n := peerVirt.lists.Load(); n != 0 {
		t.Fatalf("the peer listed its domains %d times to answer for one container", n)
	}
	if n := selfVirt.lists.Load(); n != 0 {
		t.Fatalf("this host listed its domains %d times to answer for one container", n)
	}

	// The unfiltered inventory every other consumer reads is unchanged.
	if _, err := h2.GetRuntimeInventory(peerCtxFor(t, h2, "h9"), &pb.GetRuntimeInventoryRequest{}); err != nil {
		t.Fatal(err)
	}
	if peerVirt.lists.Load() == 0 {
		t.Fatal("the full inventory no longer lists the domains")
	}
}

// P3: another project's live row of the name on a host does not vouch for
// that host's runtime of the name when the runtime's own owner record says it
// is this project's container.
func TestConfirmNoLiveCopy_OtherProjectRowCheckedAgainstOwnerRecord(t *testing.T) {
	ctx := context.Background()
	acmeHere := []*pb.Container{{Name: "web", Project: "acme", HostName: "h2"}}
	for _, tc := range []struct {
		what     string
		owner    *lxc.ContainerOwner
		ownerErr error
		refused  string // "" = allowed
	}{
		{what: "the record says acme", owner: &lxc.ContainerOwner{Project: "acme"}},
		{what: "no record (an earlier build's container)"},
		{what: "the record says _default", owner: &lxc.ContainerOwner{Project: "_default"}, refused: "h2 runs web"},
		{what: "the record cannot be read", ownerErr: errors.New("permission denied"), refused: "cannot confirm with h2"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			ct := newRestoreCT("web")
			if tc.owner != nil {
				ct.owners["web"] = *tc.owner
			}
			ct.ownerErr = tc.ownerErr
			h2 := restorePeerHost(t, "h2", ct, nil)
			s := followupCluster(t, h2, acmeHere)
			err := s.confirmNoLiveCopy(ctx, "_default", "web", "src")
			switch {
			case tc.refused == "" && err != nil:
				t.Fatalf("%s: %v, want allowed", tc.what, err)
			case tc.refused != "" && !refusedNaming(err, tc.refused):
				t.Fatalf("%s: %v, want refused with %q", tc.what, err, tc.refused)
			}
		})
	}

	t.Run("this host", func(t *testing.T) {
		h2 := restorePeerHost(t, "h2", newRestoreCT(), nil)
		s := followupCluster(t, h2, nil)
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{HostName: "self", Name: "web", Project: "acme", State: "stopped"}); err != nil {
			t.Fatal(err)
		}
		ct := newRestoreCT("web")
		ct.owners["web"] = lxc.ContainerOwner{Project: "_default"}
		s.containersRoot = t.TempDir()
		s.SetLXCCapableForTest(true)
		s.SetContainerRuntime(ct)
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); !refusedNaming(err, "self runs web") {
			t.Fatalf("this host's web is stamped _default under acme's row: %v, want refused", err)
		}
		ct.owners["web"] = lxc.ContainerOwner{Project: "acme"}
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); err != nil {
			t.Fatalf("this host's web is acme's: %v", err)
		}
	})
}

// P4: a host whose lxc tooling probe says no still holds a container's
// directory on disk; that copy is named, not reported as absence.
func TestConfirmNoLiveCopy_NoToolingStillChecksTheDirectory(t *testing.T) {
	ctx := context.Background()
	t.Run("a peer", func(t *testing.T) {
		ct := newRestoreCT()
		ct.dirs["web"] = true
		h2 := restorePeerHost(t, "h2", ct, nil)
		h2.SetLXCCapableForTest(false)
		s := followupCluster(t, h2, nil)
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); !refusedNaming(err, "h2 holds web") {
			t.Fatalf("h2 holds web's directory with no tooling: %v, want refused naming h2", err)
		}
		ct.dirs["web"] = false
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); err != nil {
			t.Fatalf("h2 has no tooling and no directory of web: %v", err)
		}
		ct.dirErr = errors.New("stat: input/output error")
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); !refusedNaming(err, "cannot confirm with h2") {
			t.Fatalf("h2 has no tooling and cannot read whether web's directory is there: %v, want refused naming h2", err)
		}
	})
	t.Run("this host", func(t *testing.T) {
		h2 := restorePeerHost(t, "h2", newRestoreCT(), nil)
		s := followupCluster(t, h2, nil)
		ct := newRestoreCT()
		ct.dirs["web"] = true
		s.containersRoot = t.TempDir()
		s.SetLXCCapableForTest(false)
		s.SetContainerRuntime(ct)
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); !refusedNaming(err, "self holds web") {
			t.Fatalf("this host holds web's directory with no tooling: %v, want refused", err)
		}
	})
}
