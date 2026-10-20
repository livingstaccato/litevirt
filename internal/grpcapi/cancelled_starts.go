package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hooks"
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
// the row, for a row put back to stopped by its operator and for one put back
// to error alike. The start's own late answer removes the entry once it has
// handled it. Otherwise sweepCancelledStarts — on each pass of the host's
// background reconcile — carries it out. An entry is kept until one of these
// ends it:
//   - its VM's row says anything but what the cancel wrote (stopped by its
//     operator, or error), or is on another host, or is gone: the operator
//     started it again, deleted it, or it moved; nothing is destroyed;
//   - its domain runs here: libvirt started it late, and it is destroyed by
//     a forced stop, recorded once, the row left as the cancel wrote it;
//   - its domain was seen running and is now not: the start it cancelled
//     has completed, so nothing of it is still pending;
//   - its domain does not run and the host has booted since the entry was
//     made (the kernel's boot ID differs): libvirt's queue of jobs does not
//     survive a boot, so no start can still be pending for it.
//
// A held start has no upper bound on when libvirt answers it (a start queued
// behind another job reads shut off for as long as it waits), so an entry is
// never ended by its age. A restart of libvirtd alone would also end every
// pending start, but nothing here tells reliably that it restarted, so it
// does not end an entry. An entry kept costs a bounded look at its domain on
// each pass.
//
// A later start of the VM on this host removes the entry before it starts the
// domain (endCancelledStartForStart). The file is local: no replicated
// statement, nothing for a peer of any version to read.
const cancelledStartsFile = "cancelled-starts.json"

// cancelledStartRecord is one entry of the file.
type cancelledStartRecord struct {
	VM         string `json:"vm"`
	StartAsked string `json:"start_asked"`
	Cancelled  string `json:"cancelled"`
	// Created is when the record was made (RFC 3339, nanoseconds); it tells
	// one record of a VM from a later one.
	Created string `json:"created"`
	// BootID is the host's boot ID when the record was made ("" when it
	// could not be read): a domain shut off in a later boot has no start
	// pending.
	BootID string `json:"boot_id,omitempty"`
	// Row is the row state the cancel wrote: "stopped" (stopped by its
	// operator; also when empty) or "error".
	Row string `json:"row,omitempty"`
	// Ran says the start this record cancelled has answered: its domain was
	// seen running, or libvirt answered it with an outcome that could not
	// be confirmed. Nothing of it is pending then, so a domain that does
	// not run ends the record.
	Ran bool `json:"ran,omitempty"`
	// Libvirtd identifies the libvirt daemon that held the start when the
	// record was made ("<pid>:<start time>", libvirtdIdentity; "" when it
	// could not be told): a daemon restarted since took its queued jobs
	// with it.
	Libvirtd string `json:"libvirtd,omitempty"`
}

// rowStillCancelled reports whether row still says what the cancel r
// recorded wrote, on this host.
func (s *Server) rowStillCancelled(r cancelledStartRecord, row *corrosion.VMRecord) bool {
	if row == nil || row.HostName != s.hostName {
		return false
	}
	if r.Row == "error" {
		return row.State == "error"
	}
	return row.State == "stopped" && row.StateDetail == "operator-stop"
}

func (s *Server) readBootID() string {
	read := s.bootID
	if read == nil {
		read = func() (string, error) {
			b, err := os.ReadFile(kernelBootIDPath)
			return strings.TrimSpace(string(b)), err
		}
	}
	id, err := read()
	if err != nil || !bootIDPattern.MatchString(id) {
		return ""
	}
	return id
}

// kernelBootIDPath is where Linux publishes the current boot's ID, a random
// UUID (bootIDPattern); anything of another form is not trusted.
const kernelBootIDPath = "/proc/sys/kernel/random/boot_id"

var bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// bootedSince reports whether the host has booted since r was made: both
// boot IDs read, and they differ.
func (s *Server) bootedSince(r cancelledStartRecord) bool {
	cur := s.readBootID()
	return cur != "" && bootIDPattern.MatchString(r.BootID) && r.BootID != cur
}

type cancelledStarts struct {
	mu      sync.Mutex
	loaded  bool
	loadErr error
	// everRead says the file has read at least once in this process: m is
	// then the last good read (with what was recorded since), and stays the
	// answer while the file cannot be read.
	everRead bool
	m        map[string]cancelledStartRecord
	busy     map[string]bool
	// destroying holds the VMs whose domain a judgement asked libvirt to
	// destroy and libvirt has not answered yet.
	destroying map[string]bool
}

func (s *Server) cancelledStartsPath() string {
	return filepath.Join(s.dataDir, cancelledStartsFile)
}

// cancelledStartsLocked returns the entries, reading the file the first
// time; mu is held. It does not read the file again: a file that could not
// be read is read again once per sweep, and by a cancel
// (reloadCancelledStartsLocked), never by every probe.
func (s *Server) cancelledStartsLocked() map[string]cancelledStartRecord {
	c := &s.cancelledStarts
	if !c.loaded {
		s.loadCancelledStartsLocked()
	}
	return c.m
}

// reloadCancelledStartsLocked reads the file again when it could not be
// read; mu is held.
func (s *Server) reloadCancelledStartsLocked() {
	if !s.cancelledStarts.loaded || s.cancelledStarts.loadErr != nil {
		s.loadCancelledStartsLocked()
	}
}

// loadCancelledStartsLocked reads the file; mu is held. A file that cannot be
// read is never written over (loadErr), and the last good read stays the
// answer meanwhile.
func (s *Server) loadCancelledStartsLocked() {
	c := &s.cancelledStarts
	prevErr := c.loadErr
	c.loaded, c.loadErr = true, nil
	if c.m == nil {
		c.m = map[string]cancelledStartRecord{}
	}
	if s.dataDir == "" {
		c.everRead = true
		return
	}
	raw, err := os.ReadFile(s.cancelledStartsPath())
	var list []cancelledStartRecord
	switch {
	case errors.Is(err, os.ErrNotExist):
		err = nil
	case err == nil:
		err = json.Unmarshal(raw, &list)
	}
	if err != nil {
		c.loadErr = err
		if prevErr == nil || prevErr.Error() != err.Error() {
			slog.Error("StopVM: the record of cancelled starts cannot be read; it is not written over, no start can be cancelled until it reads, and the VMs it may name are held from restart. Fix or remove it",
				"file", s.cancelledStartsPath(), "error", err)
		}
		return
	}
	if prevErr != nil {
		slog.Info("StopVM: the record of cancelled starts reads again", "file", s.cancelledStartsPath())
	}
	c.everRead = true
	c.m = map[string]cancelledStartRecord{}
	for _, r := range list {
		c.m[r.VM] = r
	}
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
// asked was cancelled at cancelled, the row put back to rowState ("stopped"
// or "error"). It fails when the record cannot be written, and the cancel is
// then not made.
func (s *Server) recordCancelledStart(vm string, asked, cancelled time.Time, rowState string) error {
	boot, daemon := s.readBootID(), s.readLibvirtdID()
	s.cancelledStarts.mu.Lock()
	defer s.cancelledStarts.mu.Unlock()
	s.reloadCancelledStartsLocked()
	m := s.cancelledStartsLocked()
	prev, had := m[vm]
	row := ""
	if rowState == "error" {
		row = "error"
	}
	m[vm] = cancelledStartRecord{VM: vm, StartAsked: asked.UTC().Format(time.RFC3339), Cancelled: cancelled.UTC().Format(time.RFC3339),
		Created: time.Now().UTC().Format(time.RFC3339Nano), BootID: boot, Row: row, Libvirtd: daemon}
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

// HasCancelledStart reports whether this host holds a cancelled start of the
// VM name, whose row says state and detail: a domain that runs under its row
// is the sweep's to destroy, and the reconciler and the VM checker neither
// record it running nor restart the VM (SetCancelledStartProbe). While the
// file cannot be read, the last good read answers; with none in this
// process, a row that says what a cancel writes (error, or stopped by its
// operator) is taken as possibly named, and no other. It never reads the
// file itself.
func (s *Server) HasCancelledStart(name, state, detail string) bool {
	s.cancelledStarts.mu.Lock()
	defer s.cancelledStarts.mu.Unlock()
	if _, ok := s.cancelledStartsLocked()[name]; ok {
		return true
	}
	c := &s.cancelledStarts
	if c.loadErr != nil && !c.everRead {
		return state == "error" || (state == "stopped" && detail == "operator-stop")
	}
	return false
}

// dropCancelledStart removes vm's entry once its cancelled start is settled.
func (s *Server) dropCancelledStart(vm string) {
	s.dropCancelledStartIf(vm, "")
}

// dropCancelledStartIf is dropCancelledStart, of the entry made at created
// only (any entry when created is ""): a judgement made from one entry never
// ends a later cancel's.
func (s *Server) dropCancelledStartIf(vm, created string) {
	s.cancelledStarts.mu.Lock()
	defer s.cancelledStarts.mu.Unlock()
	m := s.cancelledStartsLocked()
	r, ok := m[vm]
	if !ok || (created != "" && r.Created != created) {
		return
	}
	delete(m, vm)
	if err := s.saveCancelledStartsLocked(); err != nil {
		// Kept on disk: a later sweep ends it again.
		m[vm] = r
		slog.Warn("StopVM: a settled cancelled start's record was not removed from the file", "vm", vm, "error", err)
	}
}

// sweepCancelledStarts carries out the cancelled starts whose own start is
// no longer running in this daemon (see above). Each entry is judged in its
// own goroutine, one at a time per VM; every libvirt call a judgement makes
// is bounded by the live-state wait, so a libvirt that does not answer for
// one domain holds neither the pass, nor the others, nor the VM's lock. The
// returned channel is closed once every judgement started here has finished
// (tests wait on it).
func (s *Server) sweepCancelledStarts(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	if s.virt == nil || s.db == nil {
		close(done)
		return done
	}
	s.cancelledStarts.mu.Lock()
	s.reloadCancelledStartsLocked()
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
	go func() {
		wg.Wait()
		s.judgeCancelledStartConditions(context.WithoutCancel(ctx))
		close(done)
	}()
	return done
}

func cancelledStartActiveKey(vm string) string  { return "cancelled-start-active\x00" + vm }
func cancelledStartDestroyKey(vm string) string { return "cancelled-start-destroy\x00" + vm }

// domainActiveBounded is DomainIsActive within the live-state wait
// (errLiveStateNoAnswer when libvirt has not answered), asked on the
// backend's StateReader when it has one: the daemon's connection can be full
// of calls libvirt does not answer (libvirt/state_reader.go).
func (s *Server) domainActiveBounded(vm string) (bool, error) {
	_, st, err := s.boundedVirtCall(cancelledStartActiveKey(vm), nil, func() (string, error) {
		active, err := s.domainIsActiveRead(vm)
		if active {
			return "active", err
		}
		return "", err
	})
	return st == "active", err
}

// domainIsActiveRead is DomainIsActive on the backend's StateReader, or on
// the daemon's connection when it has none or the reader cannot dial.
func (s *Server) domainIsActiveRead(vm string) (bool, error) {
	if b, ok := s.virt.(interface{ StateReader() *lv.StateReader }); ok {
		if r := b.StateReader(); r != nil {
			active, err := r.DomainIsActive(vm)
			if !errors.Is(err, lv.ErrStateConnUnavailable) {
				return active, err
			}
		}
	}
	return s.virt.DomainIsActive(vm)
}

// markCancelledStartRan records, in the record, that the start r cancelled
// has answered. A record that cannot be rewritten keeps it in memory.
func (s *Server) markCancelledStartRan(r cancelledStartRecord) {
	s.cancelledStarts.mu.Lock()
	defer s.cancelledStarts.mu.Unlock()
	m := s.cancelledStartsLocked()
	cur, ok := m[r.VM]
	if !ok || cur.Created != r.Created || cur.Ran {
		return
	}
	cur.Ran = true
	m[r.VM] = cur
	if err := s.saveCancelledStartsLocked(); err != nil {
		slog.Warn("StopVM: that a cancelled start answered is kept in memory only; the file was not rewritten", "vm", r.VM, "error", err)
	}
}

// markCancelledStartAnswered is markCancelledStartRan for vm's current
// record: its start has answered (finishCancelledStartLocked).
func (s *Server) markCancelledStartAnswered(vm string) {
	s.cancelledStarts.mu.Lock()
	r, ok := s.cancelledStartsLocked()[vm]
	s.cancelledStarts.mu.Unlock()
	if ok {
		s.markCancelledStartRan(r)
	}
}

func (s *Server) cancelledStartRan(r cancelledStartRecord) bool {
	s.cancelledStarts.mu.Lock()
	defer s.cancelledStarts.mu.Unlock()
	cur, ok := s.cancelledStartsLocked()[r.VM]
	return ok && cur.Created == r.Created && cur.Ran
}

// cancelledStartCurrent reports whether r is still vm's record (not ended,
// nor replaced by a later cancel's).
func (s *Server) cancelledStartCurrent(r cancelledStartRecord) bool {
	s.cancelledStarts.mu.Lock()
	defer s.cancelledStarts.mu.Unlock()
	cur, ok := s.cancelledStartsLocked()[r.VM]
	return ok && cur.Created == r.Created
}

func (s *Server) cancelledStartDestroying(vm string) bool {
	s.cancelledStarts.mu.Lock()
	defer s.cancelledStarts.mu.Unlock()
	return s.cancelledStarts.destroying[vm]
}

// judgeCancelledStart carries out one cancelled start (sweepCancelledStarts).
// libvirt is asked about the domain without the VM lock, within the
// live-state wait; the lock is taken only to destroy a domain that runs, and
// that destroy too is waited for within the bound, never past it under the
// lock. A look libvirt does not answer keeps the entry for a later pass.
func (s *Server) judgeCancelledStart(ctx context.Context, r cancelledStartRecord) {
	if _, live := s.startFlightOf(r.VM); live {
		return
	}
	if s.cancelledStartDestroying(r.VM) {
		return // its destroy is outstanding: a later pass sees its outcome
	}
	row, err := corrosion.GetVM(ctx, s.db, r.VM)
	if err != nil {
		return // unknown: kept for the next pass
	}
	if !s.rowStillCancelled(r, row) {
		slog.Info("StopVM: a cancelled start's VM no longer says what the cancel wrote here; nothing to undo", "vm", r.VM)
		s.dropCancelledStartIf(r.VM, r.Created)
		return
	}
	active, aerr := s.domainActiveBounded(r.VM)
	switch {
	case errors.Is(aerr, errLiveStateNoAnswer):
		slog.Info("StopVM: libvirt has not answered for a cancelled start's domain; looked at again next pass", "vm", r.VM)
		return
	case lv.IsNoDomain(aerr) || (aerr == nil && !active):
		// A domain shut off (or not defined) says nothing about a start
		// libvirt may still be making. The record ends only on positive
		// evidence that none is pending (see above).
		switch {
		case s.cancelledStartRan(r):
			// Before hardware_v2, a stop releases the VM's legacy PCI claims
			// (stopVMLockedNote); the start's, held while its outcome was
			// unknown, are let go here, under the VM lock.
			unlock, ok := s.tryLockVMAs(r.VM, "cancelled-start check")
			if !ok {
				return // a lifecycle call holds the VM: the next pass
			}
			defer unlock()
			if !s.cancelledStartCurrent(r) {
				return
			}
			if !s.hardwareV2Latched(ctx) {
				if err := s.releaseDevices(ctx, r.VM); err != nil {
					slog.Warn("StopVM: a cancelled start's record ends; releasing its PCI devices failed", "vm", r.VM, "error", err)
				}
			}
			slog.Info("StopVM: a cancelled start's domain ran and no longer does; its record is ended", "vm", r.VM)
			s.dropCancelledStartIf(r.VM, r.Created)
		case s.bootedSince(r):
			slog.Info("StopVM: a cancelled start's domain does not run, and the host has booted since the cancel; its record is ended", "vm", r.VM)
			s.dropCancelledStartIf(r.VM, r.Created)
		case s.libvirtdRestartedSince(r):
			slog.Info("StopVM: a cancelled start's domain does not run, and the libvirt daemon has restarted since the cancel; its record is ended", "vm", r.VM)
			s.dropCancelledStartIf(r.VM, r.Created)
		}
		return
	case aerr != nil:
		return // unknown: kept for the next pass
	}
	if s.bootedSince(r) {
		// The host has booted since the cancel: the start it cancelled
		// cannot have survived the boot, so the domain that runs is some
		// later start's (an onboot autostart whose running write failed),
		// never the cancelled one's. Nothing is destroyed.
		slog.Info("StopVM: a cancelled start's record predates this boot; the domain that runs is not its start's, and the record is ended", "vm", r.VM)
		s.dropCancelledStartIf(r.VM, r.Created)
		return
	}
	// The domain runs: the start it cancelled has completed.
	s.markCancelledStartRan(r)
	unlock, ok := s.tryLockVMAs(r.VM, "cancelled-start check")
	if !ok {
		return // a lifecycle call holds the VM: the next pass
	}
	defer unlock()
	if _, live := s.startFlightOf(r.VM); live {
		return
	}
	if !s.cancelledStartCurrent(r) {
		// Ended while libvirt was asked (a start of the VM removed it):
		// the domain that runs is that start's.
		return
	}
	row, err = corrosion.GetVM(ctx, s.db, r.VM)
	if err != nil {
		return
	}
	if !s.rowStillCancelled(r, row) {
		s.dropCancelledStartIf(r.VM, r.Created)
		return
	}
	note := fmt.Sprintf("start cancelled: the start asked for at %s was cancelled at %s, and libvirt started its domain after the daemon restarted; the domain was destroyed",
		r.StartAsked, r.Cancelled)
	s.undoCancelledStartLocked(ctx, r, row, note)
}

// undoCancelledStartLocked destroys the domain a cancelled start brought up
// after the daemon restarted, and records it: the row is left as the cancel
// wrote it (stopped by its operator, or error, which holds the VM's set-aside
// disk copies). The destroy is waited for within the live-state wait; one
// libvirt has not answered by then keeps the record, and is recorded when it
// answers. The caller holds the VM lock.
func (s *Server) undoCancelledStartLocked(ctx context.Context, r cancelledStartRecord, row *corrosion.VMRecord, note string) {
	if row.State == "error" {
		note += "; the row is left error, which holds its set-aside disk copies"
	}
	hspec := vmHooks(row)
	pbVM := &pb.VM{Name: row.Name, HostName: row.HostName, State: pb.VMState_VM_STOPPING}
	hooks.Run(ctx, hooks.PreStop, pbVM, hspec)
	destroyed := func() {
		if !s.hardwareV2Latched(ctx) {
			if err := s.releaseDevices(ctx, row.Name); err != nil {
				slog.Warn("StopVM: a cancelled start's domain was destroyed; releasing its PCI devices failed", "vm", row.Name, "error", err)
			}
		}
		s.recordVMEvent(ctx, row.Name, "vm.stopped", "ok", note)
		pbVM.State = pb.VMState_VM_STOPPED
		hooks.Run(ctx, hooks.PostStop, pbVM, hspec)
		slog.Warn("StopVM: destroyed the domain of a start cancelled before the daemon restarted", "vm", row.Name)
	}
	call, _, derr := s.boundedVirtCall(cancelledStartDestroyKey(row.Name), nil, func() (string, error) {
		return "", s.virt.DestroyDomain(row.Name)
	})
	if errors.Is(derr, errLiveStateNoAnswer) {
		if call == nil {
			return
		}
		// Not waited for under the lock. While it is outstanding a start
		// of the VM is refused (endCancelledStartForStart) and no pass asks
		// again. When libvirt answers, the VM lock is taken again and a
		// destroy that succeeded gets the same bookkeeping as one answered
		// in time (hooks, device release, event), and the record ends; a
		// failed one is left to a later pass.
		s.cancelledStarts.mu.Lock()
		if s.cancelledStarts.destroying == nil {
			s.cancelledStarts.destroying = map[string]bool{}
		}
		s.cancelledStarts.destroying[row.Name] = true
		s.cancelledStarts.mu.Unlock()
		slog.Warn("StopVM: libvirt has not answered the destroy of a cancelled start's domain; its record is kept", "vm", row.Name)
		go func() {
			<-call.done
			defer func() {
				s.cancelledStarts.mu.Lock()
				delete(s.cancelledStarts.destroying, row.Name)
				s.cancelledStarts.mu.Unlock()
			}()
			if call.err != nil {
				slog.Warn("StopVM: the destroy of a cancelled start's domain failed late; a later pass looks again", "vm", row.Name, "error", call.err)
				return
			}
			unlock := s.lockVMAs(row.Name, "cancelled-start undo")
			defer unlock()
			destroyed()
			s.dropCancelledStartIf(r.VM, r.Created)
		}()
		return
	}
	if derr == nil {
		destroyed()
		s.dropCancelledStartIf(r.VM, r.Created)
		return
	}
	active, aerr := s.domainActiveBounded(row.Name)
	switch {
	case lv.IsNoDomain(aerr) || (aerr == nil && !active):
		destroyed()
		s.dropCancelledStartIf(r.VM, r.Created)
		return
	case aerr != nil:
		return // unknown: kept, and looked at again next pass
	}
	// It runs and cannot be destroyed: the row says so, never stopped (or
	// error) over a running domain, and the failed cancel is recorded once.
	s.noteVMStarted(row.Name)
	if werr := s.persistVMState(ctx, row.Name, "running", "", corrosion.OpVMState); werr != nil {
		slog.Error("StopVM: a cancelled start's domain runs and could not be destroyed; recording it running failed", "vm", row.Name, "error", werr)
		return // kept: tried again next pass
	}
	s.recordVMEvent(ctx, row.Name, "vm.stopped", "error",
		fmt.Sprintf("the start asked for at %s was cancelled at %s, but libvirt started it after the daemon restarted and destroying the domain failed: %v; the VM runs (`lv stop --force %s`)",
			r.StartAsked, r.Cancelled, derr, row.Name))
	s.dropCancelledStartIf(r.VM, r.Created)
}

// endCancelledStartForStart removes vm's record before a new start of the VM
// starts its domain: the operator's start supersedes the cancel, and the
// sweep must never destroy what it started. It fails, and the start must
// not be made, when the record is there and the file cannot be rewritten
// without it, or while a destroy the sweep asked of the VM's domain has not
// been answered. An unreadable file names nothing the sweep acts on, so it
// does not hold a start.
func (s *Server) endCancelledStartForStart(vm string) error {
	s.cancelledStarts.mu.Lock()
	defer s.cancelledStarts.mu.Unlock()
	if s.cancelledStarts.destroying[vm] {
		return status.Errorf(codes.Unavailable, "start %q: libvirt has not answered the destroy of the domain its earlier cancelled start brought up, and the start was not made; retry once it has (`lv events %s`)", vm, vm)
	}
	m := s.cancelledStartsLocked()
	r, ok := m[vm]
	if !ok || s.cancelledStarts.loadErr != nil {
		return nil
	}
	delete(m, vm)
	if err := s.saveCancelledStartsLocked(); err != nil {
		m[vm] = r
		return fmt.Errorf("the record of its earlier cancelled start could not be removed from %s, and a start with it there could be undone: %w",
			cancelledStartsFile, err)
	}
	slog.Info("StartVM: a start supersedes the VM's cancelled start; its record is removed", "vm", vm)
	return nil
}
