package corrosion

import (
	"context"
	"encoding/json"
	"strings"
)

// Shared vocabulary for partition pause (docs/design/partition-pause.md): the
// fence method the majority records when it relies on a minority's pause, the
// condition identities both sides read, and the one definition of "a workload
// the majority would recover elsewhere" — which the minority must pause and
// the majority must recover, so both read it from here.

// FencePauseReliance prefixes the fencing_log DETAIL of a best-effort fence
// that did not reach its host when the coordinator relies on that host's
// partition pause instead (partition_pause_v1 latched). The method stays
// "best-effort-ssh": a coordinator on an older build reads the row exactly as
// it always has (an assumed best-effort fence, gated by safe_fence_default),
// where a new method value would have read to it as a proved power-off. A
// coordinator on this build waits out the pause when it sees the prefix.
// FenceAssuranceDetail classifies such a row FenceSelfPaused.
const FencePauseReliance = "[relies on the host's partition pause] "

// ReliesOnPartitionPause reports whether a fence (method, detail) is one whose
// recovery waits out the host's partition pause.
func ReliesOnPartitionPause(method, detail string) bool {
	return method == "best-effort-ssh" && strings.HasPrefix(detail, FencePauseReliance)
}

// FenceAssuranceDetail is FenceAssurance that also reads the detail: an
// assumed best-effort fence whose recovery relied on the host's partition
// pause is FenceSelfPaused. Operator surfaces use it; the proof-grade and
// safe-fence rules keep reading FenceAssurance, for which it is still
// assumed.
func FenceAssuranceDetail(method, result, detail string) string {
	a := FenceAssurance(method, result)
	if a == FenceAssumed && ReliesOnPartitionPause(method, detail) {
		return FenceSelfPaused
	}
	return a
}

// Health-condition identities for partition pause. One evaluator; every row is
// written by the host it is about (one writer per row).
const (
	PartitionPauseEvaluator = "partition_pause"
	// CondPartitionPaused: this host holds at least one workload it paused
	// itself on losing the voter majority. Subject host/<name>.
	CondPartitionPaused = "partition_paused"
	// CondPartitionPauseFailed: this host lost the majority and could not
	// pause a workload it had to. While it is open the majority does NOT rely
	// on this host's pause (docs/design/partition-pause.md §3.4, §4.3).
	// Subject host/<name>.
	CondPartitionPauseFailed = "partition_pause_failed"
	// CondVMSettled / CondCTSettled: Layer 3 stopped a local copy a verified
	// claim certificate gave to another host. Subject <name>@<host>.
	CondVMSettled = "vm_settled"
	CondCTSettled = "ct_settled"
	// CondVMSettleDeclined: this host runs a copy of a VM whose row names
	// another host, and Layer 3 declined to stop it. The evidence carries the
	// reason and what an operator can do. It resolves once the copy is no
	// longer declined (settled, stopped, gone, or the row names this host).
	// Subject <name>@<host>.
	CondVMSettleDeclined = "vm_settle_declined"
	// CondPartitionOneWay: the failover coordinator sees a quorum of voters
	// failing a host while that host's own rows mark a majority healthy — a
	// one-way partition, in which it may never pause. Visibility only
	// (docs/design/partition-pause.md §7 F4). Subject host/<name>.
	CondPartitionOneWay = "partition_one_way"
)

// HostPartitionPauseFailed reports whether host has an open (not resolved)
// partition_pause_failed condition in c's replica. A read error is returned,
// and the caller must then not rely on the pause.
func HostPartitionPauseFailed(ctx context.Context, c *Client, host string) (bool, error) {
	row, ok, err := GetHealthCondition(ctx, c, PartitionPauseEvaluator, CondPartitionPauseFailed, "host", host)
	if err != nil {
		return false, err
	}
	return ok && row.Lifecycle != ConditionResolved, nil
}

// VMRecoverableOnHostFailure reports whether the failover coordinator would
// move vm off a failed host. autoPromote says the VM is enrolled in
// auto-promote replication.
//
// Auto-promotion is consulted here, not only in the reschedule loop: that loop
// reaches AutoPromoteReplica BEFORE it consults on_host_failure, so a VM
// enrolled in replication with the default policy of "none" is still
// recoverable — by promotion rather than reschedule.
func VMRecoverableOnHostFailure(vm VMRecord, autoPromote bool) bool {
	// A VM stopped by intent is not run anywhere, and nobody asked for it to
	// run: a recovery overwrites the stop with "pending" and starts it
	// elsewhere — on a disk rebuilt blank from its image when the real one is
	// host-local, which then strands the real disk on the failed host. It is
	// never started (docs/migration-failover.md, "Stopped workloads").
	// Auto-promotion defines and starts a VM too, so enrolment does not change
	// this.
	if VMStoppedForFailover(vm) {
		return false
	}
	// Secure Boot / vTPM state (UEFI NVRAM + swtpm) was host-local and died with
	// the host. Neither a reschedule nor a disk-only replica promotion
	// reconstructs it, so this is not work that becomes possible later — recovery
	// is an operator restore from a backup that carried the firmware.
	if VMUsesFirmwareState(vm) {
		return false
	}
	if p := VMFailurePolicy(vm); p != "" && p != "none" {
		return true
	}
	return autoPromote
}

// ContainerRecoverableOnHostFailure is the container half of
// VMRecoverableOnHostFailure.
func ContainerRecoverableOnHostFailure(ct ContainerRecord) bool {
	if ct.OnHostFailure == "" || ct.OnHostFailure == "none" {
		return false
	}
	// Already triaged as unrecoverable on an earlier pass (no re-pullable image
	// and no usable backup) and left in place on purpose so an operator can see
	// it. Re-processing it would loop on a decision already made.
	if ct.StateDetail == ContainerRelocateSkippedDetail {
		return false
	}
	// Stopped, as VMRecoverableOnHostFailure: a relocation recreates and starts
	// it elsewhere, which an operator who stopped it never asked for.
	if ContainerStoppedForFailover(ct) {
		return false
	}
	// A relocate-restore marker means this row has an ACTIVE owner, not that it
	// is stranded: resolvePendingRelocations re-derives every marker cluster-wide
	// on EVERY cycle, independent of the fence path, and retries until the marker
	// ages out. Counting these reports work somebody is doing — and in the worst
	// case inverts the truth, since a restore that LANDED but failed to tombstone
	// its source row leaves the container running on the target with only this
	// row behind.
	if _, _, ok := RelocateRestoreMarker(ct.State, ct.StateDetail); ok {
		return false
	}
	return true
}

// The state_detail values the reconciler records for a VM it found stopped
// that nobody asked to stop (health.classifyStop). Every other detail on a
// stopped row is a stop someone meant: "operator-stop" (StopVM), a drain's
// "drain-cold-move:<op>", a managed save, the failover re-key marker — and a
// stopped row with no detail at all, the safe reading of an unknown stop.
const (
	StopDetailGuestShutdown    = "guest-shutdown"      // clean ACPI poweroff from inside the guest
	StopDetailOutOfBandDestroy = "out-of-band-destroy" // libvirt destroy not initiated by an operator stop
	StopDetailOutOfBand        = "stopped out-of-band" // down, for a reason libvirt did not say
)

// StopIsIntent reports whether a stopped row's state_detail records a stop
// someone meant (see the StopDetail constants).
func StopIsIntent(detail string) bool {
	switch detail {
	case StopDetailGuestShutdown, StopDetailOutOfBandDestroy, StopDetailOutOfBand:
		return false
	}
	return true
}

// VMStoppedForFailover reports whether vm is stopped by intent, so failover
// never starts it: it stays on its host, stopped, with its disks (or, when
// they are all on shared storage, is re-keyed to a live host still stopped,
// RekeyStoppedVM). A VM that stopped without anyone asking — a guest or host
// shutdown — is not: failover recovers it as main did when its disks are all
// shared, and leaves it when one is host-local (VMHasHostLocalDisk), since a
// restart elsewhere would rebuild that disk blank.
func VMStoppedForFailover(vm VMRecord) bool {
	return vm.State == "stopped" && StopIsIntent(vm.StateDetail)
}

// VMHasHostLocalDisk reports whether any of disks is not on cluster-shared
// storage (DiskIsShared), so it does not follow the VM to another host.
func VMHasHostLocalDisk(disks []DiskRecord) bool {
	for _, d := range disks {
		if !DiskIsShared(d) {
			return true
		}
	}
	return false
}

// ContainerStoppedForFailover is VMStoppedForFailover for a container. A row
// the coordinator itself marked relocate-skipped is stopped too, but by
// failover, not by anyone's intent: it was running when its host died, and the
// removed-host pass may still move it (retrySkippedOnRemovedHost).
func ContainerStoppedForFailover(ct ContainerRecord) bool {
	return ct.State == "stopped" && ct.StateDetail != ContainerRelocateSkippedDetail
}

// VMFailurePolicy extracts on_host_failure from a VM's spec JSON.
func VMFailurePolicy(vm VMRecord) string {
	var spec struct {
		OnHostFailure string `json:"on_host_failure"`
	}
	if vm.Spec != "" {
		_ = json.Unmarshal([]byte(vm.Spec), &spec)
	}
	return spec.OnHostFailure
}

// VMUsesFirmwareState reports whether a VM uses Secure Boot or a vTPM — i.e.
// has host-local firmware state (NVRAM + swtpm) that can't survive its host
// dying (G1).
func VMUsesFirmwareState(vm VMRecord) bool {
	var spec struct {
		SecureBoot bool `json:"secure_boot"`
		Tpm        bool `json:"tpm"`
	}
	if vm.Spec != "" {
		_ = json.Unmarshal([]byte(vm.Spec), &spec)
	}
	return spec.SecureBoot || spec.Tpm
}

// AutoPromoteEnrolled returns the VMs enrolled in auto-promote replication —
// the set VMRecoverableOnHostFailure's autoPromote argument is read from.
func AutoPromoteEnrolled(ctx context.Context, c *Client) (map[string]bool, error) {
	rows, err := ListBackupSchedules(ctx, c)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range rows {
		if r.Type == "replication" && r.AutoPromote {
			out[r.VMName] = true
		}
	}
	return out, nil
}

// CertifiedTransferProofs lists the ownership-transfer proofs (reschedule,
// promote, relocate) for (kind, name) that carry a recovery-claim certificate,
// in id order — TOMBSTONED ones included: ReapSpentProofs tombstones a spent
// proof after a day, and its certificate still proves what a majority decided,
// which is all Layer 3 reads it for. It verifies nothing: Layer 3 verifies each
// certificate before it acts on one (docs/design/partition-pause.md §6).
func CertifiedTransferProofs(ctx context.Context, c *Client, kind, name string) ([]ProofRecord, error) {
	rows, err := c.Query(ctx, `SELECT id FROM runtime_action_proofs
		WHERE target_kind = ? AND target_name = ? AND claim_certificate != ''
		ORDER BY id`, kind, name)
	if err != nil {
		return nil, err
	}
	var out []ProofRecord
	for _, r := range rows {
		pr, ok, err := getActionProof(ctx, c, r.String("id"), true)
		if err != nil {
			return nil, err
		}
		if ok && pr.ClaimCertificate != "" && ClaimGatedAction(pr.Action) {
			out = append(out, pr)
		}
	}
	return out, nil
}
