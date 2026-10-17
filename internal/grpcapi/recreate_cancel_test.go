package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// cancelAfterRecreateDelete returns a context the recreate seam cancels once
// the re-create's delete has returned, before its create.
func cancelAfterRecreateDelete(t *testing.T, s *Server) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(adminCtx())
	t.Cleanup(cancel)
	s.recreateDeleted = func(string) { cancel() }
	t.Cleanup(func() { s.recreateDeleted = nil })
	return ctx
}

func recreateSpec(name string) *pb.VMSpec {
	return &pb.VMSpec{Name: name, Image: "img-b", Cpu: 1, MemoryMib: 256, Network: []*pb.NetworkAttachment{{Name: "lan"}}}
}

// A re-create whose client leaves after its delete: when the delete tore the
// VM down, the create runs whatever becomes of the client (no copy would be
// left otherwise); when it removed nothing (a blue-green green, a
// snapshot-and-replace -next, a member already gone), the create is a fresh
// one and stays the client's to cancel.
//
// Mutations: run the create detached whatever the delete did (recreateAs:
// drop the switch back to the caller's context; recreateInline: detach
// createCtx unconditionally) — the "removed nothing" cases go red; never
// detach the create — the "tore down" cases go red.
func TestRecreate_TheCreateIsDetachedOnlyAfterATeardown(t *testing.T) {
	for _, c := range []struct {
		name     string
		target   string // the VM the create makes
		torn     bool
		recreate func(ctx context.Context, s *Server) error
	}{
		{"rolling, removed nothing (-next)", "web-next", false, func(ctx context.Context, s *Server) error {
			return (&serverOps{s: s}).CreateNextVM(ctx, "web", recreateSpec("web"))
		}},
		{"rolling, tore down", "web", true, func(ctx context.Context, s *Server) error {
			return (&serverOps{s: s}).RecreateVM(ctx, "web", recreateSpec("web"))
		}},
		{"inline, removed nothing (member gone)", "fresh", false, func(ctx context.Context, s *Server) error {
			a := planner.VMAction{Kind: planner.OpUpdate, VMName: "fresh", TargetHost: s.hostName, Spec: recreateSpec("fresh")}
			f := &compose.File{Name: "st"}
			return s.recreateInline(ctx, a, f, newDependsOnGate(s, f, []planner.VMAction{a}, nil))
		}},
		{"inline, tore down", "web", true, func(ctx context.Context, s *Server) error {
			a := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: s.hostName, Spec: recreateSpec("web")}
			f := &compose.File{Name: "st"}
			return s.recreateInline(ctx, a, f, newDependsOnGate(s, f, []planner.VMAction{a}, nil))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := inlineStackServer(t, `{"name":"lan"}`)
			createFakeImage(t, s, "img-b")
			ctx := cancelAfterRecreateDelete(t, s)
			err := c.recreate(ctx, s)
			vm, _ := corrosion.GetVM(context.Background(), s.db, c.target)
			if c.torn {
				if vm == nil || !strings.Contains(vm.Spec, `"img-b"`) {
					t.Fatalf("%s is not the re-created VM after a re-create whose client left after the teardown (err %v): %+v",
						c.target, err, vm)
				}
				return
			}
			if vm != nil {
				t.Fatalf("%s was created although its client left before the create and nothing was torn down (err %v)", c.target, err)
			}
			if err == nil {
				t.Fatal("a create its client cancelled answered OK")
			}
		})
	}
}

// A container recorded on a removed host, deleted by a client that leaves
// mid-delete: the delete completes, and so does the clear of its firewall
// tags, which the entry runs after it.
//
// Mutation: clear the tags on the request context — red.
func TestDeleteContainerOnRemovedHost_ClearsItsTagsWhenItsClientLeaves(t *testing.T) {
	s, _ := tagsServer(t)
	markTagsUsed(t, s)
	bg := context.Background()
	if err := corrosion.InsertHost(bg, s.db, corrosion.HostRecord{Name: "gone-host", Address: "10.0.0.9", SSHUser: "root",
		GRPCPort: 7443, State: "active", CertSerial: "aagone"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteHost(bg, s.db, "gone-host"); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(bg, `INSERT INTO containers (host_name, name, state, create_spec, created_at, updated_at)
		VALUES ('gone-host', 'x', 'stopped', ?, 't', 't')`, `{"template":"debian","fw_id":"`+fwA+`"}`); err != nil {
		t.Fatal(err)
	}
	seedTagsFor(t, s, corrosion.TagMemberCT, fwA, map[string]string{"role": "db"}, "x", "gone-host")
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	fired := false
	s.SetDeleteStepHookForTest(func(name, step string) {
		if name == "x" && step == "removed-host" {
			fired = true
			cancel()
		}
	})
	if _, err := s.DeleteContainer(ctx, &pb.DeleteContainerRequest{Name: "x", HostName: "gone-host", Force: true}); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	if !fired {
		t.Fatal("the client never left inside the removed-host delete; the scenario missed the window")
	}
	if ct, _ := corrosion.GetContainer(bg, s.db, "gone-host", "x"); ct != nil {
		t.Fatal("premise: the container's row survived its delete")
	}
	if v, _ := tagsRowValue(t, s, corrosion.TagMemberCT, fwA); v != "" {
		t.Errorf("the deleted container's tags row still holds %q after its client left mid-delete", v)
	}
}
