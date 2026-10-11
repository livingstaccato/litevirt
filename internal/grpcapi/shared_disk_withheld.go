package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/notify"
)

// A VM whose domain was built from its disk rows without a shared disk
// whose row names a host not proven powered off (corrosion.JudgeSharedDiskRows,
// review R4-I2): a durable condition per VM, like a partial promotion's.
// Raised by the start or redefine that withheld the disk, resolved by the
// next one that withholds none. InspectVM shows it as shared_disk_withheld.
const (
	sharedWithheldEvaluator = "shared_disk_start"
	sharedWithheldCode      = "vm.shared_disk_withheld"
	sharedWithheldKind      = "vm"
	vmEventSharedWithheld   = "vm.shared_disk_withheld"
)

type sharedWithheldEvidence struct {
	VM     string `json:"vm"`
	Host   string `json:"host"`
	Detail string `json:"detail"`
}

// ReportSharedDiskWithheld records that vm's domain was built on this host
// without the shared disks detail names (corrosion.WithheldSharedDiskDetail).
// The event and the notification go out when the condition is raised or its
// detail changes; an unchanged one writes nothing.
func (s *Server) ReportSharedDiskWithheld(ctx context.Context, vm, detail string) {
	if detail == "" {
		s.ClearSharedDiskWithheld(ctx, vm)
		return
	}
	if s.db != nil {
		row, found, err := corrosion.GetHealthCondition(ctx, s.db, sharedWithheldEvaluator, sharedWithheldCode, sharedWithheldKind, vm)
		if err != nil {
			slog.Warn("shared disk withheld: read the condition", "vm", vm, "error", err)
		}
		open := err == nil && found && row.Lifecycle != corrosion.ConditionResolved
		var ev sharedWithheldEvidence
		if open {
			_ = json.Unmarshal([]byte(row.Evidence), &ev)
			if ev.Detail == detail && ev.Host == s.hostName {
				return
			}
		}
		ts := time.Now().UTC().Format(time.RFC3339)
		if !open {
			row = corrosion.HealthCondition{Evaluator: sharedWithheldEvaluator, Code: sharedWithheldCode,
				SubjectKind: sharedWithheldKind, SubjectID: vm, Lifecycle: corrosion.ConditionConfirmed,
				FirstSeen: ts, ConfirmedAt: ts}
		}
		b, _ := json.Marshal(sharedWithheldEvidence{VM: vm, Host: s.hostName, Detail: detail})
		row.Evidence, row.Severity, row.Hosts = string(b), corrosion.SeverityWarning, []string{s.hostName}
		row.ObserveCount++
		row.CleanCount = 0
		row.LastSeen, row.ResolvedAt, row.Reporter = ts, "", s.hostName
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("shared disk withheld: persist the condition", "vm", vm, "error", err)
		}
	}
	slog.Error("a VM's domain was built without a shared disk whose owner is not proven off", "vm", vm, "detail", detail)
	s.recordVMEventSeverity(ctx, vm, vmEventSharedWithheld, "warning", "error", detail)
	s.notify(ctx, notify.Notification{Kind: "vm.shared_disk_withheld", Severity: notify.SevError, Subject: vm, Detail: detail})
}

// ClearSharedDiskWithheld resolves vm's condition, if one is open: its domain
// was built since withholding no shared disk.
func (s *Server) ClearSharedDiskWithheld(ctx context.Context, vm string) {
	if s.db == nil {
		return
	}
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, sharedWithheldEvaluator, sharedWithheldCode, sharedWithheldKind, vm)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, s.hostName
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("shared disk withheld: resolve the condition", "vm", vm, "error", err)
	}
}

// sharedDiskWithheldReason is vm's open condition's detail, "" when none is.
func (s *Server) sharedDiskWithheldReason(ctx context.Context, vm string) string {
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, sharedWithheldEvaluator, sharedWithheldCode, sharedWithheldKind, vm)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		return ""
	}
	var ev sharedWithheldEvidence
	if json.Unmarshal([]byte(row.Evidence), &ev) != nil || ev.Detail == "" {
		return "its domain was built without a shared disk whose owner is not proven powered off"
	}
	return ev.Detail
}

// judgeSharedDiskRows is corrosion.JudgeSharedDiskRows on this host, with
// this server's reading of "shared" (diskOnSharedStorage).
func (s *Server) judgeSharedDiskRows(ctx context.Context, disks []corrosion.DiskRecord) ([]corrosion.DiskRecord, []corrosion.WithheldSharedDisk) {
	return corrosion.JudgeSharedDiskRows(ctx, s.db, disks, s.hostName, func(d corrosion.DiskRecord) bool {
		return s.diskOnSharedStorage(ctx, d)
	})
}

// hasSharedRowElsewhere reports whether any of disks is a shared disk whose
// row names another host: the only VMs a start re-judges by redefining.
func (s *Server) hasSharedRowElsewhere(ctx context.Context, disks []corrosion.DiskRecord) bool {
	for _, d := range disks {
		if d.HostName != "" && d.HostName != s.hostName && s.diskOnSharedStorage(ctx, d) {
			return true
		}
	}
	return false
}

// rejudgeSharedDisksForStart redefines vm's domain from its rows before a
// start when one of its shared disks' rows names another host
// (reconcileDomainDefinition judges each such host). Nothing else is
// redefined: every other VM starts on its definition exactly as before.
//
// A running domain is left alone (review m2): a start of a VM that already
// runs only records it running, and redefining its persistent definition
// then would drop a disk the running guest has from its next cold start.
// A withheld boot disk refuses the start (review m1): the domain would boot
// nothing.
func (s *Server) rejudgeSharedDisksForStart(ctx context.Context, vm *corrosion.VMRecord) error {
	if st, err := s.virt.DomainState(vm.Name); err == nil && st == "running" {
		return nil
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil || !s.hasSharedRowElsewhere(ctx, disks) {
		return nil
	}
	if _, withheld := s.judgeSharedDiskRows(ctx, disks); len(withheld) > 0 {
		if boot, ok := corrosion.WithheldBootDisk(withheld); ok {
			detail := corrosion.WithheldSharedDiskDetail(vm.Name, s.hostName, withheld)
			s.ReportSharedDiskWithheld(ctx, vm.Name, detail)
			return status.Errorf(codes.FailedPrecondition, "%s is not started: its boot disk %s is withheld; %s",
				vm.Name, boot.Disk.DiskName, detail)
		}
	}
	if err := s.reconcileDomainDefinition(ctx, vm, nil); err != nil {
		slog.Warn("start: could not redefine the domain to judge its shared disks again; starting it as defined",
			"vm", vm.Name, "error", err)
	}
	return nil
}

// guardSharedDiskStart is health.GuardSharedDiskStart on this host, for the
// definition about to start (its persistent XML when xml is "").
func (s *Server) guardSharedDiskStart(ctx context.Context, vm, xml string) (func(), error) {
	if xml == "" && s.virt != nil {
		if x, err := s.virt.DumpXMLInactive(vm); err == nil {
			xml = x
		}
	}
	return health.GuardSharedDiskStart(ctx, s.db, s.dataDir, s.hostName, vm, xml)
}
