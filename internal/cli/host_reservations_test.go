package cli

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestHostReservationsNote(t *testing.T) {
	if n := hostReservationsNote(&pb.Host{Name: "node-1", ReservedMemMib: 512}); n != "" {
		t.Fatalf("note for a host whose reservations were listed: %q, want none", n)
	}
	n := hostReservationsNote(&pb.Host{Name: "node-1", ReservationsError: "reservation op-bad: invalid character"})
	for _, want := range []string{"warning:", `"node-1"`, "op-bad: invalid character", "unknown, not zero"} {
		if !strings.Contains(n, want) {
			t.Fatalf("note %q lacks %q", n, want)
		}
	}
}
