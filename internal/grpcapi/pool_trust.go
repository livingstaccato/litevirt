package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
)

// TrustStoragePool confirms, on the pool's host, that a row naming that host
// is its pool (`lv pool trust`).
//
// With preview, the pool's host answers its own row — driver, source,
// target, normalized nfs mount options, and why it does not trust it — and
// records nothing: that is what the operator is shown and confirms.
//
// Without it, the request carries the values the operator confirmed, and
// only those: the host records them in its local ledger when its row is
// exactly them, and refuses otherwise. Confirming a row that names a host
// path is naming that path for root to write in, so it takes what naming it
// in a create takes — storage.hostpath at the cluster root, the protected
// directories refused to everyone — judged on the exact values forwarded and
// on the entry node's own row alike.
//
// Every confirmation is audited as the operator who made it, refusals
// included: on the entry node, and on the pool's host, which takes the
// operator from the forward (repairActor).
func (s *Server) TrustStoragePool(ctx context.Context, req *pb.TrustStoragePoolRequest) (resp *pb.TrustStoragePoolResponse, err error) {
	actor := s.repairActor(ctx)
	host := req.GetHost()
	if host == "" {
		host = s.hostName
	}
	if !req.GetPreview() {
		defer func() {
			where := "on this host"
			if host != s.hostName {
				where = "forwarded to " + host
			}
			result := "ok"
			if err != nil {
				result = fmt.Sprintf("error: %s: %s", status.Code(err), status.Convert(err).Message())
			}
			s.auditAs(ctx, actor, "storage.pool.trust", req.GetName(),
				fmt.Sprintf("host=%s %s driver=%s source=%s target=%s mount_options=%s", host, where,
					req.GetDriver(), req.GetSource(), req.GetTarget(), req.GetMountOptions()), result)
		}()
	}
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := safename.ValidatePoolName(req.GetName()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if !req.GetPreview() && req.GetDriver() == "" {
		return nil, status.Error(codes.InvalidArgument, "driver is required: the row as you confirmed it")
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, req.GetName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "pool %q not on host %q", req.GetName(), host)
	}
	if err := s.RequirePerm(ctx, poolRBACPathFor(rec.Project, rec.Name), "storage.pool.write", "operator"); err != nil {
		return nil, err
	}
	want := pooltrust.BindingOf(req.GetDriver(), req.GetSource(), req.GetTarget(), map[string]string{"options": req.GetMountOptions()})
	if req.GetPreview() {
		// The host's row, paths and all, is shown only to who could confirm it.
		if err := s.RequirePerm(ctx, "/", verbStorageHostPath, "admin"); err != nil {
			return nil, err
		}
	} else {
		// The exact values forwarded, and the row this node holds.
		for _, cfg := range []storage.Config{
			{Driver: want.Driver, Source: want.Source, Target: want.Target, Options: map[string]string{"options": want.MountOptions}},
			{Driver: rec.Driver, Source: rec.Source, Target: rec.Target, Options: rec.Options},
		} {
			if err := s.authorizePoolHostPaths(ctx, fmt.Sprintf("pool %q", rec.Name), cfg); err != nil {
				return nil, err
			}
		}
	}
	if host != s.hostName {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "dial %q: %v", host, err)
		}
		defer conn.Close()
		req.Host = host
		resp, err := client.TrustStoragePool(metadata.AppendToOutgoingContext(ctx, repairActorMDKey, actor), req)
		if status.Code(err) == codes.Unimplemented {
			return nil, status.Errorf(codes.FailedPrecondition,
				"host %q runs a build without pool trust: it acts on every row naming it, so there is nothing to confirm there until it is upgraded", host)
		}
		return resp, err
	}

	pt := s.PoolTrust()
	if pt == nil {
		return nil, status.Error(codes.FailedPrecondition, "this host keeps no pool trust ledger")
	}
	got := pooltrust.BindingOf(rec.Driver, rec.Source, rec.Target, rec.Options)
	v := pt.Judge(rec.Name, got)
	if req.GetPreview() {
		out := &pb.TrustStoragePoolResponse{Pool: storagePoolRecordToPB(rec), MountOptions: got.MountOptions, AlreadyTrusted: v.Trusted}
		if v.Trusted {
			out.TrustedAs = v.Why
		} else {
			out.Why = v.Why
		}
		return out, nil
	}
	if want != got {
		return nil, status.Errorf(codes.FailedPrecondition,
			"this host's row of pool %q is driver %q, source %q, target %q, mount options %q, not the driver %q, source %q, target %q, mount options %q confirmed; check it again (`lv pool trust %s --host %s` shows it)",
			rec.Name, got.Driver, got.Source, got.Target, got.MountOptions, want.Driver, want.Source, want.Target, want.MountOptions, rec.Name, s.hostName)
	}
	resp = &pb.TrustStoragePoolResponse{Pool: storagePoolRecordToPB(rec), MountOptions: got.MountOptions}
	if v.Trusted {
		resp.AlreadyTrusted, resp.TrustedAs = true, v.Why
	} else {
		// The confirmed values, which are the row's: want == got.
		if err := pt.Record(rec.Name, want, pooltrust.HowTrust); err != nil {
			return nil, status.Errorf(codes.Internal, "record the pool in this host's trust ledger: %v", err)
		}
		resp.TrustedAs = pooltrust.TrustLedger
	}
	s.addStoragePoolRef(rec.Name, StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target, Options: rec.Options})
	slog.Info("storage pool row confirmed on this host", "pool", rec.Name, "driver", rec.Driver, "target", rec.Target,
		"already_trusted", resp.AlreadyTrusted, "by", actor)
	s.JudgePoolTrust(ctx)
	return resp, nil
}

// Pool row trust (internal/pooltrust): storage_pools is replicated with no
// check of which host wrote a row, so a row naming this host is acted on —
// as a disk root, a mount, a directory written, swept or listed — only when
// this host stands behind it: config.yaml, its local ledger of the pools it
// created or an operator confirmed, or the daemon's own pool areas. The
// trust is enforced where pool rows become permission:
//
//   - poolRefusal, the one predicate behind checkPoolForWrite,
//     poolUsableForWrite and poolDirForWrite (disk creates, move, replicate,
//     the replication runner, promote, replica increments and areas, import,
//     upload, content list and delete, restore targets, the ISO library,
//     and withinDiskArtifactRoot's roots for every migration receive);
//   - lookupStoragePool and resolvePoolErr, which every name lookup of a
//     pool of this host goes through;
//   - ownPool / ownPools, for the code that reads this host's rows directly
//     (the NFS mount reconcile and a start's mount, the staging sweep, the
//     ISO library sync and fetch);
//   - the daemon's own row consumers (capacity refresh, export refresh, NFS
//     hardening, the in-memory pool map), through the same store.
//
// Readers that only make the daemon MORE careful keep every row: an
// untrusted row there can only add a refusal (the image-archive deny list,
// shared-directory confinement, in-use scans before a prune).

const (
	poolTrustEvaluator   = "pool_trust"
	condPoolRowUntrusted = "pool_row_untrusted"
)

// SetPoolTrust installs this host's pool trust store. NewServer opens one
// from the data directory; the daemon replaces it with the one it adopted
// existing pools into and gave the config pools. nil turns the check off
// (unit tests that build a server by hand).
func (s *Server) SetPoolTrust(t *pooltrust.Store) { s.poolTrust.Store(t) }

// PoolTrust is this host's pool trust store.
func (s *Server) PoolTrust() *pooltrust.Store { return s.poolTrust.Load() }

// poolTrustVerdict judges this host's pool name with ref.
func (s *Server) poolTrustVerdict(name string, ref StoragePoolRef) pooltrust.Verdict {
	return s.PoolTrust().Judge(name, pooltrust.BindingOf(ref.Driver, ref.Source, ref.Target, ref.Options))
}

// poolRowTrusted judges one of this host's rows.
func (s *Server) poolRowTrusted(r corrosion.StoragePoolRecord) bool {
	return s.PoolTrust().Judge(r.Name, pooltrust.BindingOf(r.Driver, r.Source, r.Target, r.Options)).Trusted
}

// errPoolUntrusted is a pool this host does not stand behind.
type errPoolUntrusted struct{ name, why string }

func (e *errPoolUntrusted) Error() string {
	return fmt.Sprintf("this host does not trust pool %q's row: %s", e.name, e.why)
}

func isPoolUntrusted(err error) bool {
	var u *errPoolUntrusted
	return errors.As(err, &u)
}

// checkPoolTrusted refuses one of this host's rows that it does not trust,
// as checkPoolForWrite does, for a writer that does not go through it.
func (s *Server) checkPoolTrusted(r corrosion.StoragePoolRecord) error {
	ref := StoragePoolRef{Driver: r.Driver, Source: r.Source, Target: r.Target, Options: r.Options}
	if v := s.poolTrustVerdict(r.Name, ref); !v.Trusted {
		slog.Error("storage pool refused: this host does not trust its row",
			"pool", r.Name, "host", s.hostName, "driver", r.Driver, "target", r.Target, "reason", v.Why)
		return status.Errorf(codes.FailedPrecondition,
			"pool %q is refused (%v): nothing lists, reads or writes it — if this host's pool is meant to be %s at %q, confirm it with `lv pool trust %s --host %s`",
			r.Name, &errPoolUntrusted{name: r.Name, why: v.Why}, r.Driver, r.Target, r.Name, s.hostName)
	}
	return nil
}

// ownPool is this host's row of pool name, when this host trusts it. An
// untrusted row reads as absent.
func (s *Server) ownPool(ctx context.Context, name string) (corrosion.StoragePoolRecord, bool, error) {
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, name)
	if err != nil || !ok {
		return rec, ok, err
	}
	if !s.poolRowTrusted(rec) {
		return corrosion.StoragePoolRecord{}, false, nil
	}
	return rec, true, nil
}

// ownPools is this host's rows that this host trusts.
func (s *Server) ownPools(ctx context.Context) ([]corrosion.StoragePoolRecord, error) {
	rows, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return nil, err
	}
	out := rows[:0:0]
	for _, r := range rows {
		if s.poolRowTrusted(r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// untrustedPool is one row pool_row_untrusted names.
type untrustedPool struct {
	Pool   string `json:"pool"`
	Driver string `json:"driver"`
	Source string `json:"source,omitempty"`
	Target string `json:"target,omitempty"`
	Why    string `json:"why"`
}

// UntrustedPools lists this host's rows it does not trust, sorted by name.
func (s *Server) UntrustedPools(ctx context.Context) ([]untrustedPool, error) {
	t := s.PoolTrust()
	if t == nil || s.db == nil {
		return nil, nil
	}
	rows, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return nil, err
	}
	var out []untrustedPool
	for _, r := range rows {
		v := t.Judge(r.Name, pooltrust.BindingOf(r.Driver, r.Source, r.Target, r.Options))
		if v.Trusted {
			continue
		}
		out = append(out, untrustedPool{Pool: r.Name, Driver: r.Driver, Source: r.Source, Target: r.Target, Why: v.Why})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pool < out[j].Pool })
	return out, nil
}

// JudgePoolTrust raises pool_row_untrusted for this host while it has rows
// it does not trust, naming each with why and the command that confirms it,
// and resolves it once it has none. The daemon runs it on its pool refresh.
func (s *Server) JudgePoolTrust(ctx context.Context) {
	if s.db == nil || s.PoolTrust() == nil {
		return
	}
	pools, err := s.UntrustedPools(ctx)
	if err != nil {
		slog.Warn("pool trust: list this host's pools", "error", err)
		return
	}
	subject := s.hostName
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, poolTrustEvaluator, condPoolRowUntrusted, "host", subject)
	if err != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	ledgerNote := s.PoolTrust().CorruptNote()
	if len(pools) == 0 && ledgerNote == "" {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("pool trust: resolve condition", "error", err)
		}
		return
	}
	for _, p := range pools {
		slog.Warn("storage pool row not trusted by this host: nothing is written, mounted or listed there until it is confirmed",
			"pool", p.Pool, "driver", p.Driver, "target", p.Target, "why", p.Why,
			"confirm", fmt.Sprintf("lv pool trust %s --host %s", p.Pool, s.hostName))
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: poolTrustEvaluator, Code: condPoolRowUntrusted,
			SubjectKind: "host", SubjectID: subject, Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{s.hostName}
	if ledgerNote != "" {
		slog.Warn("storage pool trust ledger was unreadable: the pools it held are untrusted until confirmed; review the kept copy, then remove it",
			"ledger", ledgerNote)
	}
	ev, _ := json.Marshal(map[string]any{
		"host":              s.hostName,
		"pools":             pools,
		"ledger_unreadable": ledgerNote,
		"detail": fmt.Sprintf("host %s has storage pool rows it did not create and no operator confirmed here; it writes, mounts and lists nothing in them. "+
			"Check each one's driver and target: one you made, confirm with `lv pool trust <pool> --host %s`; one you did not, delete with `lv pool delete <pool> --host %s`",
			s.hostName, s.hostName, s.hostName),
	})
	row.Evidence = string(ev)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("pool trust: raise condition", "error", err)
	}
}
