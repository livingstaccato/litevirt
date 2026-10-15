package cli

import (
	"context"
	"io"
	"os"
	"strings"
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
		if h, ok := o.(grpc.HeaderCallOption); ok {
			*h.HeaderAddr = metadata.Pairs(apimeta.InspectStaleHeader, c.note)
		}
	}
	return &pb.VM{Name: in.Name}, nil
}

// Code review [12]. The CLI reads the stale-inspect note under the header
// name the daemon sets (apimeta.InspectStaleHeader), and prints it on stderr.
//
// Mutation: read a different literal header name — no note is printed.
func TestPrintVMInspect_PrintsTheStaleNote(t *testing.T) {
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr
	err := PrintVMInspect(context.Background(), &staleInspectClient{note: "host node-1 did not answer"}, "vm1")
	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	_, _ = io.ReadAll(rOut)
	stderr, _ := io.ReadAll(rErr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stderr), "note: host node-1 did not answer") {
		t.Errorf("stderr = %q, want the daemon's stale note", stderr)
	}
}
