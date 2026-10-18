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

// failingDeployStream is a deploy stream whose sends fail once the re-create
// of vm is done: that "done" and every send after it. With cancel set the
// client has gone (the stream's context is cancelled); without it the send
// failed while the client is still there.
type failingDeployStream struct {
	mockDeployStream
	vm     string
	cancel context.CancelFunc
	failed bool
}

func (m *failingDeployStream) Send(p *pb.DeployProgress) error {
	if m.failed || (p.Phase == "done" && p.VmName == m.vm) {
		m.failed = true
		if m.cancel != nil {
			m.cancel()
		}
		return context.Canceled
	}
	return m.mockDeployStream.Send(p)
}

// A compose up whose client goes away after a member's re-create (its "done"
// cannot be sent) still records the file it deployed: the stack record
// holds the new compose file, degraded, not the one the re-create replaced.
// A deploy that stops there for another reason, its client still there,
// leaves the record as the last deploy that ran to its end wrote it.
//
// Mutations: drop the record on a failed progress send, or write it on the
// request context — "client gone" keeps the old file; drop the client-gone
// condition — "client still there" records the new file.
func TestDeployStack_AClientGoneAfterTheRecreateStillRecordsTheNewFile(t *testing.T) {
	for _, c := range []struct {
		name       string
		clientGone bool
	}{{"client gone", true}, {"client still there", false}} {
		t.Run(c.name, func(t *testing.T) {
			s := inlineStackServer(t, `{"name":"lan"}`)
			createFakeImage(t, s, "img-b")
			bg := context.Background()
			oldYAML := "name: st\nnetworks:\n  lan:\n    external: true\nvms:\n  web:\n    image: img-a\n    cpu: 1\n" +
				"    memory: 256\n    network:\n      - name: lan\n"
			if err := corrosion.UpsertStack(bg, s.db, corrosion.StackRecord{Name: "st", ComposeHash: "old",
				ComposeYAML: oldYAML, State: stackStateActive}); err != nil {
				t.Fatal(err)
			}
			newYAML := strings.Replace(oldYAML, "img-a", "img-b", 1)
			ctx, cancel := context.WithCancel(adminCtx())
			defer cancel()
			stream := &failingDeployStream{mockDeployStream: mockDeployStream{ctx: ctx}, vm: "web"}
			if c.clientGone {
				stream.cancel = cancel
			}

			err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: newYAML}, stream)
			if !stream.failed {
				t.Fatalf("the re-create never reported done; the scenario missed the window (err %v, sent %+v)", err, stream.sent)
			}
			if err == nil {
				t.Fatal("a deploy whose progress could not be sent answered OK")
			}
			if vm, _ := corrosion.GetVM(bg, s.db, "web"); vm == nil || !strings.Contains(vm.Spec, `"img-b"`) {
				t.Fatalf("premise: web is not the re-created VM: %+v", vm)
			}
			st, gerr := corrosion.GetStack(bg, s.db, "st")
			if gerr != nil || st == nil {
				t.Fatalf("stack record: %+v, %v", st, gerr)
			}
			if !c.clientGone {
				if st.ComposeYAML != oldYAML || st.State != stackStateActive {
					t.Errorf("a deploy that stopped with its client still there rewrote the record: state %q\n%s", st.State, st.ComposeYAML)
				}
				return
			}
			if st.ComposeYAML != newYAML {
				t.Errorf("the stack record holds the file the re-create replaced:\n%s", st.ComposeYAML)
			}
			if st.State != stackStateDegraded {
				t.Errorf("stack state = %q, want %q: the rest of the plan did not run", st.State, stackStateDegraded)
			}
		})
	}
}
