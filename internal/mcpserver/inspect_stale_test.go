package mcpserver

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/apimeta"
)

type staleInspectClient struct {
	pb.LiteVirtClient
	note string
}

func (c *staleInspectClient) InspectVM(_ context.Context, in *pb.InspectVMRequest, opts ...grpc.CallOption) (*pb.VM, error) {
	for _, o := range opts {
		if h, ok := o.(grpc.HeaderCallOption); ok && c.note != "" {
			*h.HeaderAddr = metadata.Pairs(apimeta.InspectStaleHeader, c.note)
		}
	}
	return &pb.VM{Name: in.Name, HostName: "node-1"}, nil
}

// An inspect the daemon answered from its replica says so to an MCP client
// too, as the CLI and REST do: the VM carries the daemon's note.
//
// Mutation: drop the header read — the VM carries no note.
func TestInspectVM_CarriesTheStaleNote(t *testing.T) {
	s := testServer(&staleInspectClient{note: "host node-1 did not answer"}, false)
	env := resultEnvelope(t, s.handleInspectVM(context.Background(), map[string]any{"name": "vm1"}))
	if env.Error != nil {
		t.Fatalf("inspect: %+v", env.Error)
	}
	vm, ok := env.Data.(vmOut)
	if !ok {
		t.Fatalf("data = %T, want vmOut", env.Data)
	}
	if vm.StaleNote != "host node-1 did not answer" {
		t.Errorf("stale_note = %q, want the daemon's note", vm.StaleNote)
	}

	s = testServer(&staleInspectClient{}, false)
	env = resultEnvelope(t, s.handleInspectVM(context.Background(), map[string]any{"name": "vm1"}))
	if vm, _ := env.Data.(vmOut); vm.StaleNote != "" {
		t.Errorf("stale_note = %q on a live answer, want none", vm.StaleNote)
	}
}
