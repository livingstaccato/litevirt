package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A node back from a fence, a crash or a partition holds the cluster as it was
// when it left. Until its first anti-entropy exchange completes, its replica
// can still name it the owner of a workload that was rescheduled while it was
// away — and every mutation below decides WHERE to act from that row: it acts
// locally when the row names this host, and proxies to the named host
// otherwise. Served from a stale row, a mutation runs against the wrong copy
// and writes the stale owner back.
//
// Observed on the kvm003-f3 lab, 2026-09-30: claimvm had been rescheduled from
// node-1 to node-4 (owner epoch 2 on every replica). node-1 booted back and,
// three seconds before its first exchange completed, served `lv compose down`.
// Its row said "mine, epoch 1": it destroyed its own shut-off leftover and
// tombstoned the row with host_name=node-1. The tombstone was the newest full
// row anywhere, so anti-entropy carried it over the owner's row cluster-wide,
// and the VM kept running on node-4 with no row naming it.
//
// So these RPCs are refused, retryably, while the local replica is not caught
// up — the same signal the reconciler's out-of-band stop sync already waits on
// (corrosion.Client.ReplicaCaughtUp). The refusal is the whole guarantee: no
// local check can do better, because on a rejoined node every local witness
// (the row, the owner-epoch marker, the leftover domain) agrees with the stale
// belief. Only the cluster knows the VM moved, and catching up is how the node
// learns it. Once caught up, the row names the real owner, the mutation is
// routed there, and the delete tombstone carries that owner's host and epoch.
//
// The set is the client-facing mutations of an EXISTING workload that act on,
// or route by, the host its local row names — plus the stack verbs that fan
// out to them. Reads, creates, host-level verbs and every peer-internal RPC
// (replication, anti-entropy, recovery claims, voter changes, the Ensure*
// helpers) are deliberately absent: a rejoining node needs those to catch up
// and to rejoin at all.
var staleReplicaGated = map[string]bool{}

func init() {
	for _, m := range []string{
		// VM lifecycle and configuration.
		"StartVM", "StopVM", "RestartVM", "DeleteVM", "RebuildVM", "CutoverVM",
		"UpdateVM", "SetVMMemory", "SetVMLabels", "SetVMIP", "SetBootOrder",
		"AttachDevice", "DetachDevice", "ResizeDisk", "CloneVM", "ConvertToTemplate",
		"AbortVMOperation",
		// VM placement and storage movement.
		"MigrateVM", "MoveVolume", "ReplicateVolume", "MigrateStackVolumes",
		"CrossRegionMigrate", "PromoteReplica",
		// VM backup, restore and snapshots.
		"BackupVM", "RestoreVM", "RestoreLive", "BackupSnapshot", "RestoreFromBackup",
		"CreateSnapshot", "RestoreSnapshot", "DeleteSnapshot",
		// Containers.
		"StartContainer", "StopContainer", "DeleteContainer", "MigrateContainer",
		"SnapshotContainer", "RevertContainerSnapshot", "DeleteContainerSnapshot",
		"BackupContainer", "RestoreContainer", "CloneContainer", "ConvertContainerToTemplate",
		"ConvertContainer",
		// Stacks: compose up updates existing members in place, compose down
		// deletes them — both from the local row's view of where they run.
		"DeployStack", "DeleteStack",
	} {
		staleReplicaGated["/litevirt.v1.LiteVirt/"+m] = true
	}
}

// requireReplicaCaughtUp refuses with codes.Unavailable while this node's
// replica has not caught up with a peer since the process started or since it
// last lost every gossip peer. A cluster of one is trusted without a catch-up
// (see corrosion.ReplicaTrusted). what names the refused action for the
// message and the log.
func (s *Server) requireReplicaCaughtUp(ctx context.Context, what string) error {
	if s.db == nil {
		return nil
	}
	ok, why := corrosion.ReplicaTrusted(ctx, s.db, s.hostName, s.db.ReplicaCaughtUp)
	if ok {
		return nil
	}
	slog.Warn("refusing a workload mutation: this node's replica has not caught up with the cluster, so the host it names as owner may be stale",
		"rpc", what, "detail", why)
	return status.Errorf(codes.Unavailable,
		"%s refused on %s: this node's replica has not caught up with the cluster yet (%s), so it cannot tell which host "+
			"owns the workload now. Retry in a minute, or run the command against another node", what, s.hostName, why)
}

// gateStaleReplica applies requireReplicaCaughtUp to the RPCs in
// staleReplicaGated. The auth interceptors call it after authentication, so an
// unauthenticated caller learns nothing about this node's replica.
func (s *Server) gateStaleReplica(ctx context.Context, fullMethod string) error {
	if !staleReplicaGated[fullMethod] {
		return nil
	}
	return s.requireReplicaCaughtUp(ctx, methodShortName(fullMethod))
}

func methodShortName(fullMethod string) string {
	for i := len(fullMethod) - 1; i >= 0; i-- {
		if fullMethod[i] == '/' {
			return fullMethod[i+1:]
		}
	}
	return fullMethod
}
