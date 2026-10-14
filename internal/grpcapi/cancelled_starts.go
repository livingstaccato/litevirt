package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A start `lv stop --force` cancelled while libvirt had not answered it
// (cancelHeldStart) is undone when libvirt answers: a domain it started is
// destroyed. That duty lived only in the start's goroutine, so a daemon that
// restarted before libvirt answered forgot it, and a domain libvirt started
// afterwards ran under a row that says stopped by its operator — a VM nobody
// asked for, which no other path stops or shows (whole-branch review of
// batch 5, I-2).
//
// The duty is therefore also kept on this host, in
// <data_dir>/cancelled-starts.json, written durably before the cancel writes
// the row. The start's own late answer removes the entry once it has handled
// it. Otherwise sweepCancelledStarts — at daemon start and on each pass of
// the host's background reconcile — carries it out: an entry whose VM's row
// still says stopped by its operator, with its domain running here, has the
// domain destroyed by a forced stop, recorded once; an entry whose domain is
// seen shut off (or gone), or whose row says anything else (the operator
// started the VM again, deleted it, or it moved), is dropped and nothing is
// destroyed. The file is local: no replicated statement, nothing for a peer
// of any version to read.
const cancelledStartsFile = "cancelled-starts.json"

// cancelledStartRecord is one entry of the file.
type cancelledStartRecord struct {
	VM         string `json:"vm"`
	StartAsked string `json:"start_asked"`
	Cancelled  string `json:"cancelled"`
}

type cancelledStarts struct {
	mu      sync.Mutex
	loaded  bool
	loadErr error
	m       map[string]cancelledStartRecord
	busy    map[string]bool
}

func (s *Server) cancelledStartsPath() string {
	return filepath.Join(s.dataDir, cancelledStartsFile)
}

// cancelledStartsLocked returns the entries, reading the file once; mu is
// held. A file that cannot be read is never written over (loadErr).
func (s *Server) cancelledStartsLocked() map[string]cancelledStartRecord {
	c := &s.cancelledStarts
	if c.loaded {
		return c.m
	}
	c.loaded, c.m = true, map[string]cancelledStartRecord{}
	if s.dataDir == "" {
		return c.m
	}
	raw, err := os.ReadFile(s.cancelledStartsPath())
	if errors.Is(err, os.ErrNotExist) {
		return c.m
	}
	var list []cancelledStartRecord
	if err == nil {
		err = json.Unmarshal(raw, &list)
	}
	if err != nil {
		c.loadErr = err
		slog.Error("StopVM: the record of cancelled starts cannot be read; it is not written over, and no start can be cancelled until it reads. Fix or remove it",
			"file", s.cancelledStartsPath(), "error", err)
		return c.m
	}
	for _, r := range list {
		c.m[r.VM] = r
	}
	return c.m
}

// saveCancelledStartsLocked writes the file durably; mu is held.
func (s *Server) saveCancelledStartsLocked() error {
	c := &s.cancelledStarts
	if s.dataDir == "" {
		return nil
	}
	if c.loadErr != nil {
		return fmt.Errorf("the record of cancelled starts (%s) cannot be read: %w", s.cancelledStartsPath(), c.loadErr)
	}
	list := make([]cancelledStartRecord, 0, len(c.m))
	for _, r := range c.m {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].VM < list[j].VM })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return writeSynced(s.cancelledStartsPath(), raw)
}

// recordCancelledStart records, durably, that the start of vm asked for at
// asked was cancelled at cancelled. It fails when the record cannot be
// written, and the cancel is then not made.
func (s *Server) recordCancelledStart(vm string, asked, cancelled time.Time) error {
	s.cancelledStarts.mu.Lock()
	defer s.cancelledStarts.mu.Unlock()
	m := s.cancelledStartsLocked()
	prev, had := m[vm]
	m[vm] = cancelledStartRecord{VM: vm, StartAsked: asked.UTC().Format(time.RFC3339), Cancelled: cancelled.UTC().Format(time.RFC3339)}
	if err := s.saveCancelledStartsLocked(); err != nil {
		if had {
			m[vm] = prev
		} else {
			delete(m, vm)
		}
		return err
	}
	return nil
}

// dropCancelledStart removes vm's entry once its cancelled start is settled.
func (s *Server) dropCancelledStart(vm string) {
	s.cancelledStarts.mu.Lock()
	defer s.cancelledStarts.mu.Unlock()
	m := s.cancelledStartsLocked()
	if _, ok := m[vm]; !ok {
		return
	}
	delete(m, vm)
	if err := s.saveCancelledStartsLocked(); err != nil {
		// Kept on disk: the next sweep finds the domain shut off (or the row
		// changed) and drops it then.
		slog.Warn("StopVM: a settled cancelled start's record was not removed from the file", "vm", vm, "error", err)
	}
}

// sweepCancelledStarts carries out the cancelled starts whose own start is
// no longer running in this daemon (see above). Each entry is judged in its
// own goroutine, one at a time per VM, so a libvirt that does not answer for
// one domain holds neither the pass nor the others; the returned channel is
// closed once every judgement started here has finished (tests wait on it).
func (s *Server) sweepCancelledStarts(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	if s.virt == nil || s.db == nil {
		close(done)
		return done
	}
	s.cancelledStarts.mu.Lock()
	var todo []cancelledStartRecord
	for _, r := range s.cancelledStartsLocked() {
		if s.cancelledStarts.busy[r.VM] {
			continue
		}
		if _, live := s.startFlightOf(r.VM); live {
			continue // the start's own late answer handles it
		}
		if s.cancelledStarts.busy == nil {
			s.cancelledStarts.busy = map[string]bool{}
		}
		s.cancelledStarts.busy[r.VM] = true
		todo = append(todo, r)
	}
	s.cancelledStarts.mu.Unlock()
	var wg sync.WaitGroup
	for _, r := range todo {
		wg.Add(1)
		go func(r cancelledStartRecord) {
			defer wg.Done()
			defer func() {
				s.cancelledStarts.mu.Lock()
				delete(s.cancelledStarts.busy, r.VM)
				s.cancelledStarts.mu.Unlock()
			}()
			s.judgeCancelledStart(context.WithoutCancel(ctx), r)
		}(r)
	}
	go func() { wg.Wait(); close(done) }()
	return done
}

// judgeCancelledStart carries out one cancelled start (sweepCancelledStarts).
func (s *Server) judgeCancelledStart(ctx context.Context, r cancelledStartRecord) {
	unlock, ok := s.tryLockVM(r.VM)
	if !ok {
		return // a lifecycle call holds the VM: the next pass
	}
	defer unlock()
	if _, live := s.startFlightOf(r.VM); live {
		return
	}
	row, err := corrosion.GetVM(ctx, s.db, r.VM)
	if err != nil {
		return // unknown: kept for the next pass
	}
	if row == nil || row.HostName != s.hostName || row.State != "stopped" || row.StateDetail != "operator-stop" {
		slog.Info("StopVM: a cancelled start's VM is no longer stopped by its operator here; nothing to undo", "vm", r.VM)
		s.dropCancelledStart(r.VM)
		return
	}
	active, aerr := s.virt.DomainIsActive(r.VM)
	switch {
	case lv.IsNoDomain(aerr) || (aerr == nil && !active):
		s.dropCancelledStart(r.VM)
		return
	case aerr != nil:
		return // unknown: kept for the next pass
	}
	// The cancelled start's domain runs under a row that says stopped by
	// its operator: libvirt started it after this daemon forgot the start.
	note := fmt.Sprintf("start cancelled: the start asked for at %s was cancelled at %s, and libvirt started its domain after the daemon restarted; the domain was destroyed",
		r.StartAsked, r.Cancelled)
	if _, serr := s.stopVMLockedNote(ctx, row, true, 0, note); serr == nil {
		slog.Warn("StopVM: destroyed the domain of a start cancelled before the daemon restarted", "vm", r.VM)
		s.dropCancelledStart(r.VM)
		return
	} else if st, e := s.virt.DomainState(r.VM); e == nil && st == "running" {
		// It runs and cannot be destroyed: the row says so, never stopped
		// over a running domain, and the failed cancel is recorded once.
		s.noteVMStarted(r.VM)
		if werr := s.persistVMState(ctx, r.VM, "running", "", corrosion.OpVMState); werr != nil {
			slog.Error("StopVM: a cancelled start's domain runs and could not be destroyed; recording it running failed", "vm", r.VM, "error", werr)
			return // kept: tried again next pass
		}
		s.recordVMEvent(ctx, r.VM, "vm.stopped", "error",
			fmt.Sprintf("the start asked for at %s was cancelled at %s, but libvirt started it after the daemon restarted and destroying the domain failed: %v; the VM runs (`lv stop --force %s`)",
				r.StartAsked, r.Cancelled, serr, r.VM))
		s.dropCancelledStart(r.VM)
	}
	// Otherwise the domain is not running and its stop's record failed:
	// kept, and the next pass drops it once it sees the domain shut off.
}
