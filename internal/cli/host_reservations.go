package cli

import (
	"fmt"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// hostReservationsNote is the stderr warning `lv host inspect` prints when the
// reservations counted against the host could not be listed. Empty otherwise.
func hostReservationsNote(host *pb.Host) string {
	if host.GetReservationsError() == "" {
		return ""
	}
	return fmt.Sprintf("warning: the reservations counted against %q could not be listed: %s; its reserved CPU and memory are unknown, not zero",
		host.GetName(), host.GetReservationsError())
}
