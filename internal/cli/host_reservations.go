package cli

import (
	"fmt"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// hostReservationsNote is the stderr warning `lv host inspect` prints when some
// reservations counted against the host could not be read. Empty otherwise.
func hostReservationsNote(host *pb.Host) string {
	if host.GetReservationsError() == "" {
		return ""
	}
	return fmt.Sprintf("warning: not every reservation counted against %q could be read: %s; reservedCpu and reservedMemMib are partial: they count only the listed reservations",
		host.GetName(), host.GetReservationsError())
}

// hostStaleReservationsNote is the stderr note `lv host inspect` prints when
// reservations on the host belong to no running operation (state "stale") or
// cannot be released by the sweep (state "release-blocked"): both are released
// only by hand. Empty otherwise.
func hostStaleReservationsNote(host *pb.Host) string {
	stale, blocked := 0, 0
	for _, r := range host.GetReservations() {
		switch r.GetState() {
		case "stale":
			stale++
		case "release-blocked":
			blocked++
		}
	}
	var notes []string
	if stale > 0 {
		notes = append(notes, fmt.Sprintf("note: %d reservation(s) on %s belong to no running operation; release one with lv operation release-reservation <operation-id> --force",
			stale, host.GetName()))
	}
	if blocked > 0 {
		notes = append(notes, fmt.Sprintf("note: %d reservation(s) on %s are release-blocked and the sweep cannot release them; release one with lv operation release-reservation <operation-id> --force",
			blocked, host.GetName()))
	}
	return strings.Join(notes, "\n")
}
