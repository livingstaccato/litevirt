package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

// Proving a ceph key at start. A start proves with `rbd info` that this
// host's key opens the VM's disks (ensureCephSecretsForVM). The proof is
// about the KEY: one success proves it for every disk of that pool, so it is
// remembered for cephKeyProofTTL per (litevirt pool, rbd pool, client, key
// fingerprint, conf, monitors). The VMs a failover starts after the first on
// a pool then need no probe, and are not deferred for want of time to prove
// what was just proven. A rotated keyring is a new fingerprint, proven again.
// A remembered proof never makes a start refuse: an image that is gone is
// still reported, by qemu, when the domain starts.

// cephKeyProofTTL is how long a proven key is taken as proven.
const cephKeyProofTTL = 2 * time.Minute

// cephProofNow is the proof cache's clock (tests move it).
var cephProofNow = time.Now

type cephKeyProofs struct {
	mu sync.Mutex
	at map[string]time.Time // cephProofKey → when it was proven
}

func (c *cephKeyProofs) put(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at == nil {
		c.at = map[string]time.Time{}
	}
	now := cephProofNow()
	c.at[key] = now
	for k, t := range c.at {
		if now.Sub(t) >= cephKeyProofTTL {
			delete(c.at, k)
		}
	}
}

func (c *cephKeyProofs) fresh(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.at[key]
	return ok && cephProofNow().Sub(t) < cephKeyProofTTL
}

// cephProofKey names what a successful probe through cfg proves for images
// in rbdPool; "" when the key cannot be read (never remembered).
func cephProofKey(cfg storage.Config, rbdPool string) string {
	fp, ok, err := storage.CephKeyFingerprintOf(cfg.Options)
	if err != nil || !ok {
		return ""
	}
	return strings.Join([]string{cfg.Name, rbdPool, clientOf(cfg), fp, cfg.Options["conf"], cfg.Options["mon_host"]}, "\x00")
}

// startDeferredError is a start that did not fail but has to wait — Ceph did
// not answer, or there was no time left to ask it. To a gRPC caller it is
// the Unavailable it wraps; to the reconciler it is health.ErrStartDeferred,
// which re-drives the start on a later pass rather than parking a proof-less
// one in error (deferPendingStart).
type startDeferredError struct{ err error }

func (e *startDeferredError) Error() string { return e.err.Error() }

func (e *startDeferredError) Unwrap() []error { return []error{e.err, health.ErrStartDeferred} }

func (e *startDeferredError) GRPCStatus() *status.Status { return status.Convert(e.err) }

// deferStart marks a start-path error as a deferral.
func deferStart(err error) error { return &startDeferredError{err: err} }

// CephStartDeferral reports, before the reconciler does any work for a VM
// (its lock, a proof's claim, the define), whether the VM's start would be
// deferred for want of time: it has a ceph disk whose key no remembered proof
// covers, and ctx has less than storage.ProbeBound left. The reconciler then
// leaves the VM for its next pass — walked first — untouched. Any other
// answer, an error included, is the start's own to give.
func (s *Server) CephStartDeferral(ctx context.Context, vm *corrosion.VMRecord) error {
	if s.virt == nil || s.db == nil || vm == nil {
		return nil
	}
	dl, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	left := time.Until(dl)
	if left >= storage.ProbeBound {
		return nil
	}
	probes, err := s.cephStartPlan(ctx, vm, "")
	if err != nil || len(probes) == 0 {
		return nil
	}
	return deferStart(status.Errorf(codes.Unavailable,
		"start %q: proving this host's ceph key for its disks takes up to %v and the walk has %v left",
		vm.Name, storage.ProbeBound, left.Round(time.Millisecond)))
}

// condCephTrashLeftover names images in a ceph pool's trash this host moved
// there (a delete, a rollback) and has not managed to purge: they still use
// the pool's capacity.
const condCephTrashLeftover = "ceph_trash_leftover"

// judgeCephTrash raises ceph_trash_leftover for this host while a purge it
// owes has failed (storage.CephPendingPurges), naming each image, its trash
// id, the error and the command that purges it by hand; and resolves it once
// none has.
func (s *Server) judgeCephTrash(ctx context.Context) {
	var failing []storage.CephPurge
	for _, p := range storage.CephPendingPurges() {
		if p.LastError != "" {
			failing = append(failing, p)
		}
	}
	subject := s.hostName
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, cephPoolEvaluator, condCephTrashLeftover, "host", subject)
	if err != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if len(failing) == 0 {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("ceph: resolve the trash leftover condition", "error", err)
		}
		return
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: cephPoolEvaluator, Code: condCephTrashLeftover,
			SubjectKind: "host", SubjectID: subject, Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{s.hostName}
	type leftover struct {
		Trash     string `json:"trash"`
		Image     string `json:"image"`
		Since     string `json:"since"`
		Attempts  int    `json:"attempts"`
		LastError string `json:"last_error"`
		Purge     string `json:"purge"`
	}
	var list []leftover
	for _, p := range failing {
		list = append(list, leftover{Trash: p.TrashRef(), Image: p.Pool + "/" + p.Image, Since: p.Since.Format(time.RFC3339),
			Attempts: p.Attempts, LastError: p.LastError, Purge: "rbd trash rm " + p.TrashRef()})
	}
	ev, _ := json.Marshal(map[string]any{
		"host": s.hostName, "leftovers": list,
		"detail": fmt.Sprintf("%d deleted ceph image(s) moved to the trash by %s are not purged yet and still use their pool's capacity; %s keeps retrying, or purge them by hand",
			len(list), s.hostName, s.hostName),
	})
	row.Evidence = string(ev)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("ceph: raise the trash leftover condition", "error", err)
	}
}
