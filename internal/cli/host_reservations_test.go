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
	n := hostReservationsNote(&pb.Host{Name: "node-1", ReservationsError: "reservation op-bad: invalid character", ReservationsPartial: true})
	for _, want := range []string{"warning:", `"node-1"`, "op-bad: invalid character", "partial", "only the listed reservations"} {
		if !strings.Contains(n, want) {
			t.Fatalf("note %q lacks %q", n, want)
		}
	}
}

// The stale note is keyed on state "stale" (and "release-blocked"): it counts
// those rows and names the manual release; any other state prints nothing.
func TestHostStaleReservationsNote(t *testing.T) {
	quiet := &pb.Host{Name: "node-1", Reservations: []*pb.HostReservation{
		{State: "in-flight"}, {State: "releasable"}, {State: "admitting"}, {State: "auto-expires"}, {State: "journal"},
	}}
	if n := hostStaleReservationsNote(quiet); n != "" {
		t.Fatalf("note for a host with no stale reservation: %q, want none", n)
	}
	n := hostStaleReservationsNote(&pb.Host{Name: "node-1", Reservations: []*pb.HostReservation{
		{State: "stale"}, {State: "in-flight"}, {State: "stale"},
	}})
	want := "note: 2 reservation(s) on node-1 belong to no running operation; release one with lv operation release-reservation <operation-id> --force"
	if n != want {
		t.Fatalf("stale note %q, want %q", n, want)
	}
	n = hostStaleReservationsNote(&pb.Host{Name: "node-1", Reservations: []*pb.HostReservation{{State: "release-blocked"}}})
	if !strings.Contains(n, "1 reservation(s) on node-1 are release-blocked") || !strings.Contains(n, "lv operation release-reservation") {
		t.Fatalf("release-blocked note %q", n)
	}
}
