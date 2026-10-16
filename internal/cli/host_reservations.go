package cli

import (
	"fmt"

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
