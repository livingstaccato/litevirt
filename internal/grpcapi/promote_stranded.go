package grpcapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// noteDisksLeftByPromote records the host-local disks an operator's promotion
// left on the host the VM left (vm.HostName, read before the promotion), as
// the failover coordinator does for its own (failover.noteDisksLeftByPromote).
//
// The promotion re-homes the VM's disk rows onto this host, so once it commits
// nothing names the old host's files: its disk (the real, newer copy of a disk
// the promotion rebuilt from an older replica) and its cloud-init seed stayed
// there unrecorded. They are not removed now, and never by the promotion: the
// old host may be down, and its disk may be the only copy of data written after
// the replica. The record (condition vm_disk_stranded) names them, and the host,
// once it is back, sets each disk aside as <disk path>.superseded-<time>, which
// is kept while the VM exists and swept after superseded_disk_retention_days
// once it is deleted (health/stranded_disk.go; lv host superseded-disks). The
// seed stays with the host until the VM is deleted, as a seed can hold
// user-data.
//
// Best effort: the promotion has succeeded, and a failure here is logged.
func (s *Server) noteDisksLeftByPromote(ctx context.Context, vm *corrosion.VMRecord, disksBefore []corrosion.DiskRecord, readErr error) {
	host := vm.HostName
	if host == "" || host == s.hostName || vm.State == "pending" {
		return // never ran elsewhere: nothing of it is there
	}
	if readErr != nil {
		slog.Error("promote: cannot tell which disks the promotion left on the host the VM left; they are not recorded",
			"vm", vm.Name, "host", host, "error", readErr)
		return
	}
	var left []corrosion.DiskRecord
	for _, d := range disksBefore {
		if d.HostName == host || d.HostName == "" {
			left = append(left, d)
		}
	}
	detail, err := health.RecordStrandedDisks(ctx, s.db, s.hostName, vm.Name, host, s.hostName, left, time.Now())
	if err != nil {
		slog.Error("promote: could not record the host-local disks the promotion left on the host the VM left",
			"vm", vm.Name, "host", host, "error", err)
		return
	}
	if detail == "" {
		return // every disk is on shared storage and moved with it
	}
	detail = "promoted from its replica on " + s.hostName + ": " + detail + "; " + host +
		" keeps them once it is back (lv host superseded-disks " + host + ")"
	slog.Warn("promote: a promoted VM left its host-local disks on the host it left; recorded and kept",
		"vm", vm.Name, "host", host, "target", s.hostName)
	s.audit(ctx, "replica.disk-stranded", vm.Name, detail, "ok")
	s.recordVMEventSeverity(ctx, vm.Name, "vm.promote.disk_stranded", "ok", "warn", detail)
	s.NotifyVMDiskStranded(vm.Name, host, detail)
}
