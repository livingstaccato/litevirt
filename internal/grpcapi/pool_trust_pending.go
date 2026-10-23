package grpcapi

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
	"github.com/litevirt/litevirt/internal/storage"
)

// Test seams: how the pending adoption of an nfs pool mounts its export at
// a staging mount point, and unmounts it again.
var (
	nfsAdoptionMount   = storage.MountNFSPool
	nfsAdoptionUnmount = storage.UnmountNFSDir
)

// pendingAdoptionDir is where the export of a pending nfs pool is mounted to
// be judged: a directory of its own in the daemon's mounts/ area, never the
// target the row names — the row is not trusted, and mounting its export
// there is the write a forged row would want.
func (s *Server) pendingAdoptionDir(name string) string {
	return filepath.Join(s.dataDir, "mounts", ".adopt-"+name)
}

// retryPendingNFSAdoptions judges, once each, the nfs pools the upgrade
// adoption could not judge because their export was not mounted then
// (pooltrust.PendingNFS: an upgrade together with a reboot). The export is
// mounted, hardened, at a staging point in mounts/ (pendingAdoptionDir), the
// adoption's evidence is read there (Store.PendingEvidence: a qcow2 disk of
// this host's VM directly in the pool's directory), and it is unmounted
// again. The pool is then adopted or held for good — exactly one judgement,
// on its first successful mount; a mount that fails is tried again on the
// next pass. A pending row that is gone, changed, or trusted meanwhile (an
// operator confirmed it) is dropped. The mount reconcile runs it every pass.
func (s *Server) retryPendingNFSAdoptions(ctx context.Context) {
	pt := s.PoolTrust()
	if pt == nil || s.db == nil {
		return
	}
	for name, b := range pt.PendingNFS() {
		rec, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, name)
		if err != nil {
			continue
		}
		if !ok || pooltrust.BindingOf(rec.Driver, rec.Source, rec.Target, rec.Options) != b || pt.Judge(name, b).Trusted {
			if err := pt.ResolvePending(name, b, false); err != nil {
				slog.Warn("storage pool trust: a pending adoption not cleared", "pool", name, "error", err)
			}
			continue
		}
		s.judgePendingNFSAdoption(ctx, pt, name, b)
	}
}

func (s *Server) judgePendingNFSAdoption(ctx context.Context, pt *pooltrust.Store, name string, b pooltrust.Binding) {
	if err := s.nfsMu.Lock(ctx); err != nil {
		return
	}
	defer s.nfsMu.Unlock()
	stage := s.pendingAdoptionDir(name)
	cfg := storage.Config{Name: name, Driver: "nfs", Source: b.Source, Target: stage}
	if b.MountOptions != "" {
		cfg.Options = map[string]string{"options": b.MountOptions}
	}
	if err := nfsAdoptionMount(ctx, s.dataDir, cfg); err != nil {
		slog.Info("storage pool trust: a pending nfs pool's export did not mount for its adoption; tried again on the next pass", "pool", name, "error", err)
		return
	}
	ok, why := pt.PendingEvidence(ctx, s.db, s.hostName, name, b, stage)
	if err := nfsAdoptionUnmount(ctx, stage); err != nil {
		slog.Warn("storage pool trust: the staging mount of a pending adoption was not unmounted", "pool", name, "dir", stage, "error", err)
	} else {
		_ = os.Remove(stage)
	}
	if err := pt.ResolvePending(name, b, ok); err != nil {
		slog.Warn("storage pool trust: a pending adoption not recorded; judged again on the next pass", "pool", name, "error", err)
		return
	}
	if ok {
		slog.Info("storage pool trust: an nfs pool held at the upgrade is adopted on its first mount", "pool", name, "evidence", why)
		s.JudgePoolTrust(ctx)
		return
	}
	slog.Warn("storage pool trust: an nfs pool held at the upgrade stays untrusted after its first mount; confirm it with `lv pool trust` if it is this host's",
		"pool", name, "why", why)
}
