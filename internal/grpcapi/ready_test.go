package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A daemon whose database will not answer is NOT ready, however healthy its
// listener looks. This is the whole defect: the peer probe completed a TLS
// handshake, which lives entirely in the TLS stack, and reported a wedged node
// healthy because nothing ever asked it to read anything.
func TestReady_UnreadyWhenTheLocalReadFails(t *testing.T) {
	s := testServer(t)
	insertReadyHost(t, s, "test-host")
	s.db.Close() // every query from here on returns an error

	resp, err := s.Ready(context.Background(), &pb.ReadyRequest{})
	if err != nil {
		t.Fatalf("Ready returned an error: %v — an unready node must ANSWER, not hang up", err)
	}
	if resp.GetReady() {
		t.Error("ready = true with a database that cannot be read")
	}
}

// The trivial read has to be a real one. A node whose own host row is not in its
// own copy of the cluster state cannot authorize, own or schedule anything, and
// reporting it ready is the same lie in a quieter form.
func TestReady_UnreadyWhenThisNodeIsNotInItsOwnHostsTable(t *testing.T) {
	s := testServer(t)

	resp, err := s.Ready(context.Background(), &pb.ReadyRequest{})
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if resp.GetReady() {
		t.Error("ready = true with no hosts row for this node")
	}
}

// A working node answers ready. Without this, "always report unready" passes
// both tests above.
func TestReady_ReadyWhenTheLocalReadSucceeds(t *testing.T) {
	s := testServer(t)
	insertReadyHost(t, s, "test-host")

	resp, err := s.Ready(context.Background(), &pb.ReadyRequest{})
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if !resp.GetReady() {
		t.Errorf("ready = false on a working node: %q", resp.GetNotReadyReason())
	}
	if got := resp.GetHostName(); got != "test-host" {
		t.Errorf("host_name = %q, want test-host", got)
	}
}

// not_ready_reason carries local error text, so it follows the same rule Ping's
// posture disclosure does: host certificates only. The distributable lv-cli
// certificate gets the verdict without the internals.
func TestReady_ReasonIsWithheldFromANonHostCaller(t *testing.T) {
	s := testServer(t)

	resp, err := s.Ready(context.Background(), &pb.ReadyRequest{})
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if resp.GetReady() {
		t.Fatal("precondition: expected an unready node")
	}
	if got := resp.GetNotReadyReason(); got != "" {
		t.Errorf("not_ready_reason = %q for a caller with no host certificate, want empty", got)
	}
}

func insertReadyHost(t *testing.T, s *Server, name string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: name, Address: "10.0.0.1", SSHUser: "root", State: "active",
	}); err != nil {
		t.Fatalf("insert host: %v", err)
	}
	if h, err := corrosion.GetHost(ctx, s.db, name); err != nil || h == nil {
		t.Fatalf("read back host %q: %v", name, err)
	}
}
