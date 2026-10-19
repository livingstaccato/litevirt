package grpcapi

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// holdFirstDefine runs during, once, at the first domain define the fake
// sees, before the define lands.
func holdFirstDefine(fake *libvirtfake.Fake, during func()) {
	var first atomic.Bool
	fake.FailDefineDomain = func(string) error {
		if first.CompareAndSwap(false, true) {
			during()
		}
		return nil
	}
}

func wantInProgress(t *testing.T, what string, err error) {
	t.Helper()
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), "in progress") {
		t.Errorf("%s: %v, want Aborted, a create in progress", what, err)
	}
}

// A clone makes a VM of its target name on this host, as a create does: while
// one runs, a create of that name is refused, and while a create runs, a
// clone to its name is (dupcreate review I-3). The one in flight finishes
// whole.
//
// Mutation: drop beginCreate from cloneVMOnSource — both directions go red.
func TestCloneVM_AndACreateOfItsTargetNameDoNotOverlap(t *testing.T) {
	t.Run("clone in flight", func(t *testing.T) {
		s := cloneSourceTemplate(t)
		fake := s.virt.(*libvirtfake.Fake)
		var createErr error
		ran := false
		holdFirstDefine(fake, func() {
			ran = true
			req := disklessCreateRequest("cx")
			req.Spec.Network = nil
			_, createErr = s.createVM(adminCtx(), req, &resolvedCreateVMDecision{resolvedHost: s.hostName, placedHere: true})
		})
		if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "cx", Mode: "full"}); err != nil {
			t.Fatalf("CloneVM: %v", err)
		}
		if !ran {
			t.Fatal("setup: the create never ran inside the clone")
		}
		wantInProgress(t, "a create of the clone's name while the clone runs", createErr)
		disks, _ := corrosion.GetVMDisks(adminCtx(), s.db, "cx")
		if len(disks) == 0 {
			t.Fatal("the clone has no disk rows")
		}
		for _, d := range disks {
			if _, err := os.Stat(d.Path); err != nil {
				t.Errorf("the clone's disk %s is gone: %v", d.Path, err)
			}
		}
		if u, _ := undefinesOf(fake, "cx"); u != 0 {
			t.Errorf("the clone's domain was undefined %d times", u)
		}
	})
	t.Run("create in flight", func(t *testing.T) {
		s := cloneSourceTemplate(t)
		fake := s.virt.(*libvirtfake.Fake)
		var cloneErr error
		ran := false
		holdFirstDefine(fake, func() {
			ran = true
			_, cloneErr = s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "cy", Mode: "full"})
		})
		req := disklessCreateRequest("cy")
		req.Spec.Network = nil
		if _, err := s.createVM(adminCtx(), req, &resolvedCreateVMDecision{resolvedHost: s.hostName, placedHere: true}); err != nil {
			t.Fatalf("createVM: %v", err)
		}
		if !ran {
			t.Fatal("setup: the clone never ran inside the create")
		}
		wantInProgress(t, "a clone to a name a create is making", cloneErr)
		if _, err := os.Stat(s.images.DiskPath("cy", "root")); err == nil {
			t.Error("the refused clone wrote a disk at the name's path")
		}
	})
}

// An import makes a VM of its name too: an import and a create of one name do
// not overlap on a host (dupcreate review I-3).
//
// Mutation: drop beginCreate from ImportVM — both directions go red.
func TestImportVM_AndACreateOfItsNameDoNotOverlap(t *testing.T) {
	t.Run("import in flight", func(t *testing.T) {
		s := concurrentImportServer(t, 10*oneDiskNeed())
		s.images = image.NewStore(s.dataDir)
		s.images.Init()
		stubQemuImg(t)
		fake := s.virt.(*libvirtfake.Fake)
		var createErr error
		ran := false
		holdFirstDefine(fake, func() {
			ran = true
			req := disklessCreateRequest("imp-x")
			req.Spec.Network = nil
			_, createErr = s.createVM(adminCtx(), req, &resolvedCreateVMDecision{resolvedHost: s.hostName, placedHere: true})
		})
		if err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-x", false)}}); err != nil {
			t.Fatalf("ImportVM: %v", err)
		}
		if !ran {
			t.Fatal("setup: the create never ran inside the import")
		}
		wantInProgress(t, "a create of the import's name while the import runs", createErr)
		if u, _ := undefinesOf(fake, "imp-x"); u != 0 {
			t.Errorf("the import's domain was undefined %d times", u)
		}
		if rec, _ := corrosion.GetVM(adminCtx(), s.db, "imp-x"); rec == nil {
			t.Error("the import has no row")
		}
	})
	t.Run("create in flight", func(t *testing.T) {
		s := concurrentImportServer(t, 10*oneDiskNeed())
		s.images = image.NewStore(s.dataDir)
		s.images.Init()
		stubQemuImg(t)
		fake := s.virt.(*libvirtfake.Fake)
		var importErr error
		ran := false
		holdFirstDefine(fake, func() {
			ran = true
			importErr = s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-y", false)}})
		})
		req := disklessCreateRequest("imp-y")
		req.Spec.Network = nil
		if _, err := s.createVM(adminCtx(), req, &resolvedCreateVMDecision{resolvedHost: s.hostName, placedHere: true}); err != nil {
			t.Fatalf("createVM: %v", err)
		}
		if !ran {
			t.Fatal("setup: the import never ran inside the create")
		}
		wantInProgress(t, "an import of a name a create is making", importErr)
		if u, _ := undefinesOf(fake, "imp-y"); u != 0 {
			t.Errorf("the create's domain was undefined %d times", u)
		}
	})
}
