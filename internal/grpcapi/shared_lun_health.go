package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/storage"
)

// The shared_lun evaluator: VMs that already share one iSCSI LUN.
//
// A create refuses a LUN another disk already is (vm_lun_claim.go). A cluster
// that got there before that check — an older build created two VMs, or two
// disks of one VM, on one iscsi pool — keeps what it has: the disks are never
// touched, and starting the VMs is not refused (that would undo nothing; the
// corruption is in what both guests wrote). What the operator is owed is to
// learn of it, so this evaluator raises a health condition naming the VMs
// and the LUN: observed (warning) on the first scan, confirmed (critical) on
// the second, resolved after two clean scans — the dual-run detector's
// lifecycle (dualrun_lifecycle.go). It is replica-only (vm_disks replicates
// everywhere) and runs under a lease of its own (sharedLUNLeaseKey), so one
// node writes it, and a dual-run pass that hangs does not stop it.
//
// Its code is NOT an ownership code (host_safety.go): admission never reads
// it.

const (
	sharedLUNEvaluator = "shared_lun"
	condSharedLUN      = "shared_lun"
	// kindSharedLUN is the notification kind (docs/notifications.md).
	kindSharedLUN = "storage.lun_shared"
	// sharedLUNConfirmScans is how many consecutive positive scans confirm:
	// one replica read can catch a delete's tombstone not yet applied.
	sharedLUNConfirmScans = 2
)

// sharedLUNFinding is one LUN more than one disk is.
type sharedLUNFinding struct {
	device string
	hosts  []string
	detail string
}

// findSharedLUNs groups every use of a LUN in this replica — as a live VM's
// disk, or as a linked clone's base — and returns, keyed by LUN, those that
// more than one guest writes: two or more disks on it, or a disk on it whose
// VM is younger than a clone layered on it. A clone's source is always older
// than the clone; a VM younger than one is not its source, but a newcomer
// that took the LUN after the source was deleted with --keep-disks, writing
// under the clone's overlay.
func (s *Server) findSharedLUNs(ctx context.Context) (map[string]sharedLUNFinding, error) {
	uses, err := corrosion.LiveVMDiskUsesWithPathPrefix(ctx, s.db, iscsiDevicePrefix)
	if err != nil {
		return nil, err
	}
	byLUN := map[string][]corrosion.DiskPathUse{}
	for _, u := range uses {
		if k, ok := storage.FixedDeviceKeyOfPath(u.Path); ok {
			byLUN[k] = append(byLUN[k], u)
		}
	}
	out := map[string]sharedLUNFinding{}
	for k, us := range byLUN {
		var disks, bases []corrosion.DiskPathUse
		for _, u := range us {
			if u.Via == "disk" {
				disks = append(disks, u)
			} else {
				bases = append(bases, u)
			}
		}
		shared := len(disks) >= 2
		for _, d := range disks {
			for _, b := range bases {
				if b.VMCreatedAt < d.VMCreatedAt {
					shared = true
				}
			}
		}
		if !shared {
			continue
		}
		sort.Slice(us, func(i, j int) bool {
			if us[i].VMName != us[j].VMName {
				return us[i].VMName < us[j].VMName
			}
			return us[i].DiskName < us[j].DiskName
		})
		hostSet := map[string]bool{}
		var users []string
		for _, u := range us {
			hostSet[u.HostName] = true
			what := fmt.Sprintf("VM %q disk %q (host %s)", u.VMName, u.DiskName, u.HostName)
			if u.Via != "disk" {
				what = fmt.Sprintf("VM %q disk %q as its linked-clone base (host %s)", u.VMName, u.DiskName, u.HostName)
			}
			users = append(users, what)
		}
		var hosts []string
		for h := range hostSet {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		device := us[0].Path
		if len(disks) > 0 {
			device = disks[0].Path
		}
		out[k] = sharedLUNFinding{
			device: device,
			hosts:  hosts,
			detail: fmt.Sprintf("iSCSI LUN %s is used by %d disks: %s. An iscsi pool is one LUN and holds one disk; "+
				"guests writing one LUN corrupt each other's data, and a VM written under a linked clone's base "+
				"corrupts the clone. Keep one, stop the others, and move their disks to LUNs of their own (a pool "+
				"per LUN, --option lun=N). litevirt does not touch these disks.",
				device, len(us), strings.Join(users, ", ")),
		}
	}
	return out, nil
}

// sharedLUNLeaseKey is the shared_lun scan's lease.
const sharedLUNLeaseKey = corrosion.LeaseKeySharedLUN

// RunSharedLUNDetector runs the shared_lun scan every interval, on whichever
// node holds its lease.
func (s *Server) RunSharedLUNDetector(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	s.sharedLUNPass(ctx, interval)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sharedLUNPass(ctx, interval)
		}
	}
}

// sharedLUNPass takes or renews the lease (TTL two intervals) and, holding
// it, scans once. A node that does not hold it writes nothing.
func (s *Server) sharedLUNPass(ctx context.Context, interval time.Duration) {
	held, _, err := corrosion.AcquireLeaseWithTerm(ctx, s.db, sharedLUNLeaseKey, s.hostName, 2*interval, time.Now())
	if err != nil {
		slog.Warn("shared-LUN scan: lease", "error", err)
		return
	}
	if !held {
		return
	}
	s.detectSharedLUNs(ctx)
}

// detectSharedLUNs runs one shared_lun scan and advances its conditions.
func (s *Server) detectSharedLUNs(ctx context.Context) {
	now := time.Now().UTC().Format(time.RFC3339)
	found, err := s.findSharedLUNs(ctx)
	if err != nil {
		slog.Warn("shared-LUN scan: read disks", "error", err)
		if serr := corrosion.UpsertHealthEvaluatorStatus(ctx, s.db, corrosion.HealthEvaluatorStatus{
			Evaluator: sharedLUNEvaluator, LastScan: now, Coverage: corrosion.CoveragePartial,
			Reporter: s.hostName, Detail: "could not read vm_disks: " + err.Error(),
		}); serr != nil {
			slog.Warn("shared-LUN scan: persist evaluator status", "error", serr)
		}
		return
	}
	active, err := corrosion.ListHealthConditions(ctx, s.db, false)
	if err != nil {
		slog.Warn("shared-LUN scan: list health conditions", "error", err)
		return
	}
	rows := map[string]corrosion.HealthCondition{}
	for _, h := range active {
		if h.Evaluator == sharedLUNEvaluator && h.Code == condSharedLUN {
			rows[h.SubjectID] = h
		}
	}

	for key, f := range found {
		row, exists := rows[key]
		evidence := encodeEvidence(f.detail, f.hosts)
		switch {
		case !exists:
			row = corrosion.HealthCondition{
				Evaluator: sharedLUNEvaluator, Code: condSharedLUN, SubjectKind: "cluster", SubjectID: key,
				Lifecycle: corrosion.ConditionObserved, Severity: corrosion.SeverityWarning,
				ObserveCount: 1, FirstSeen: now,
			}
			s.publish("storage.lun_shared.observed", key, f.detail)
			s.notify(ctx, notify.Notification{Kind: kindSharedLUN, Severity: notify.SevWarn, Subject: f.device,
				Detail: "observed (unconfirmed): " + f.detail})
		case row.Lifecycle == corrosion.ConditionObserved:
			row.ObserveCount++
			if row.ObserveCount >= sharedLUNConfirmScans {
				row.Lifecycle = corrosion.ConditionConfirmed
				row.Severity = corrosion.SeverityCritical
				row.ConfirmedAt = now
				s.publish("storage.lun_shared", key, f.detail)
				s.notify(ctx, notify.Notification{Kind: kindSharedLUN, Severity: notify.SevError, Subject: f.device,
					Detail: f.detail})
				slog.Error("shared-LUN scan: VMs share one iSCSI LUN", "lun", f.device, "detail", f.detail)
			}
		default:
			row.ObserveCount++
		}
		row.CleanCount = 0
		row.LastSeen = now
		row.Hosts, row.Evidence, row.Reporter = f.hosts, evidence, s.hostName
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Error("shared-LUN scan: persist condition", "lun", key, "error", err)
		}
	}

	// Absence proves something only under a valid decision gate: a replica
	// cut off from the cluster cannot vouch that the rows it lacks are gone.
	gateOK := s.resolveGateValid(ctx)
	for key, row := range rows {
		if _, still := found[key]; still || !gateOK {
			continue
		}
		row.CleanCount++
		row.ObserveCount = 0
		row.Reporter = s.hostName
		if row.CleanCount >= conditionCleanScans {
			row.Lifecycle = corrosion.ConditionResolved
			row.ResolvedAt = now
			s.publish("storage.lun_shared.cleared", key, "")
			s.notify(ctx, notify.Notification{Kind: kindSharedLUN, Severity: notify.SevInfo, Subject: key,
				Detail: "resolved: no LUN is the disk of more than one VM any more"})
		}
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Error("shared-LUN scan: persist condition", "lun", key, "error", err)
		}
	}

	if err := corrosion.UpsertHealthEvaluatorStatus(ctx, s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: sharedLUNEvaluator, LastScan: now, Coverage: corrosion.CoverageComplete,
		Reporter: s.hostName, Detail: fmt.Sprintf("%d LUN(s) shared by more than one disk", len(found)),
	}); err != nil {
		slog.Warn("shared-LUN scan: persist evaluator status", "error", err)
	}
}
