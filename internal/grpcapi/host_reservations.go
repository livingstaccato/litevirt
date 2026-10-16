package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// redactedVMName replaces a workload name the caller may not vm.read in a
// reservation's detail sentence.
const redactedVMName = `"<redacted>"`

// hostReservations is InspectHost's reservation listing: every reservation
// counted against host, and their totals — the figures admission subtracts,
// summed from the listed rows themselves, so the two always agree. A row's vm
// and project — and the workload name in its detail — are filled only when
// the caller may vm.read that workload; the amounts, operation id and state
// are always shown, so the rows add up to the totals for any viewer.
//
// A reservation whose data cannot be read is left out and named in errText,
// and the totals then cover only the listed rows; when nothing can be listed,
// errText says so and there are no rows. Either way the caller still returns
// the rest of the host. errText carries an error's own words only for a
// caller who may vm.read cluster-wide, since they can name projects; anyone
// else sees the operation ids and a fixed reason, and the daemon log has the
// detail.
func (s *Server) hostReservations(ctx context.Context, host string) (rows []*pb.HostReservation, cpu, mem int32, errText string) {
	detailed := s.RequirePerm(ctx, "/", "vm.read", "viewer") == nil
	views, unreadable, err := corrosion.HostReservationsPartial(ctx, s.db, host)
	if err != nil {
		slog.Error("list host reservations", "host", host, "err", err)
		if detailed {
			return nil, 0, 0, "reservations could not be listed: " + err.Error()
		}
		return nil, 0, 0, "reservations could not be listed; see the daemon log"
	}
	if len(unreadable) != 0 {
		parts := make([]string, 0, len(unreadable))
		for _, u := range unreadable {
			slog.Warn("host reservation unreadable", "host", host, "op", u.OperationID, "err", u.Err)
			if detailed {
				parts = append(parts, u.Err.Error())
			} else {
				parts = append(parts, "reservation "+u.OperationID+": reservation data unreadable")
			}
		}
		errText = fmt.Sprintf("%d reservation(s) could not be read: %s", len(unreadable), strings.Join(parts, "; "))
	}
	var sumCPU, sumMem int64
	for i := range views {
		sumCPU += int64(views[i].Vector.TargetCPU)
		sumMem += int64(views[i].Vector.TargetMemMiB)
	}
	if sumCPU > math.MaxInt32 || sumMem > math.MaxInt32 {
		errText = fmt.Sprintf("reserved totals overflow (%d vCPU, %d MiB)", sumCPU, sumMem)
		slog.Error("list host reservations", "host", host, "err", errText)
		return nil, 0, 0, errText
	}
	now := time.Now()
	out := make([]*pb.HostReservation, 0, len(views))
	for i := range views {
		v := &views[i]
		r := &pb.HostReservation{
			OperationId:      v.Op.ID,
			Method:           v.Op.Method,
			Kind:             hostReservationKind(v),
			Vcpu:             int32(v.Vector.TargetCPU),
			MemoryMib:        int32(v.Vector.TargetMemMiB),
			CreatedAt:        parseTimestamp(v.Op.CreatedAt),
			State:            hostReservationState(v),
			Detail:           v.Detail,
			HeaderOwnerEpoch: v.HeaderEpoch,
			Admitted:         v.Admitted,
			Provisional:      v.Vector.Provisional,
			ReleaseBlocked:   v.ReleaseBlocked,
		}
		if t, err := time.Parse(time.RFC3339Nano, v.Op.CreatedAt); err == nil && now.After(t) {
			r.AgeSeconds = int64(now.Sub(t) / time.Second)
		}
		if s.canReadVM(ctx, v.VMName) {
			r.Vm = v.VMName
			r.Project = hostReservationProject(v)
		} else if v.VMName != "" {
			r.Detail = strings.ReplaceAll(r.Detail, strconv.Quote(v.VMName), redactedVMName)
		}
		out = append(out, r)
	}
	return out, int32(sumCPU), int32(sumMem), errText
}

// hostReservationState is the state `lv host inspect` shows for a reservation
// class. A blocked release overrides only a class the manual release acts on
// (releasable or stale), where the sweep cannot write it and `lv operation
// release-reservation` writes the failed step instead; any other class keeps
// its own state, since neither releases it (releaseBlocked still says so).
func hostReservationState(v *corrosion.HostReservationView) string {
	if v.ReleaseBlocked && handReleasableClass(v.Class) {
		return "release-blocked"
	}
	switch v.Class {
	case corrosion.ReservationManifest:
		return "journal"
	case corrosion.ReservationCapacityLease:
		return "auto-expires"
	case corrosion.ReservationInFlight:
		return "in-flight"
	case corrosion.ReservationTerminalPastHeader, corrosion.ReservationVMGone:
		return "releasable"
	case corrosion.ReservationAdmitting:
		return "admitting"
	default:
		return "stale"
	}
}

func hostReservationKind(v *corrosion.HostReservationView) string {
	if v.Op.ResourceKind == corrosion.CapacityResourceKind {
		if corrosion.IsTransferLeaseMethod(v.Op.Method) {
			return "transfer-lease"
		}
		return "admission-lease"
	}
	switch corrosion.OperationKind(v.Op.OperationKind) {
	case corrosion.OpResourceUpdateRunning:
		return "resize"
	case corrosion.OpWorkloadCreate:
		return "create"
	}
	return v.Op.OperationKind
}

// hostReservationProject: the operation header's project, else the vector's,
// else the live VM row's.
func hostReservationProject(v *corrosion.HostReservationView) string {
	switch {
	case v.Op.Project != "":
		return v.Op.Project
	case v.Vector.Project != "":
		return v.Vector.Project
	case v.VMLive != nil:
		return v.VMLive.Project
	}
	return ""
}
