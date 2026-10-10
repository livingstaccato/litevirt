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
	"strings"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// The moved hold: durable, released only on positive evidence.
//
// A rebuild or recreate moves its VM's LUN claim to an allocation that names
// THIS host (the rollout or rebuilding host, H_R) as allocator and the host
// the re-created VM runs on (RunHost) beside it (preflightLUNs). From the
// teardown until H_R's replica holds the re-created VM's rows, H_R itself has
// nothing that shows the LUN in use — the VM's domain and its rows are on
// RunHost — so H_R answers a racing create from a HOLD.
//
// The hold is a record in <data_dir>/iscsi-lun-holds/<token>.json, written
// (fsynced, then renamed into place) before the moved allocation is proposed,
// and read by every answer this host gives (lunHoldersHere). It is node-local
// state, never replicated, and it survives a daemon restart. Nothing releases
// it on a timer, or because the re-create returned — with or without an
// error. It is released only on positive evidence (resolveLUNHold):
//
//   - this host's replica shows the re-created incarnation's own rows (its
//     created_at, learnt from RunHost) on every LUN the hold names — from then
//     on those rows answer for the claim, and only that incarnation's
//     tombstone, a real delete, ends them; or
//   - RunHost, asked by name, answers that nothing there holds the LUN — no
//     in-flight create, no row, no domain — or its removal from the cluster is
//     recorded. RunHost unreachable keeps the hold.
//
// A create of the moved VM that reaches RunHost after the hold was released —
// one still on its way when H_R restarted, or gave up — finds it gone when it
// verifies the hold (claimLUNs) and refuses: RunHost registers the create in
// its own registry first, then asks H_R, and a racer asks H_R before RunHost,
// so a racer that passed both cannot meet a create that later proceeds.
//
// Errors reading the records fail closed: this host answers no LUN question
// until they can be read.

// lunHoldDirName is the records' directory under the data directory.
const lunHoldDirName = "iscsi-lun-holds"

// lunHoldResolveEvery is how often RunLUNHoldResolver re-judges the holds.
const lunHoldResolveEvery = 5 * time.Second

// lunHoldRecord is one moved hold.
type lunHoldRecord struct {
	Token string `json:"token"`
	// VM is the VM re-created, ReplacedCreatedAt the incarnation it replaces.
	VM                string `json:"vm"`
	ReplacedCreatedAt string `json:"replaced_created_at"`
	// LUNs is the LUN keys held, each with its disk.
	LUNs map[string]string `json:"luns"`
	// RunHost is the host the re-created VM is created on.
	RunHost string `json:"run_host"`
	// NewCreatedAt is the re-created incarnation's created_at, once learnt
	// from RunHost: the rows that release the hold are that incarnation's.
	NewCreatedAt string `json:"new_created_at,omitempty"`
	Since        string `json:"since"`
}

// lunHoldStore is this host's moved holds: the records, mirrored in memory,
// and which of them a re-create in this process is still running under.
type lunHoldStore struct {
	mu      sync.Mutex
	loaded  bool
	loadErr error
	recs    map[string]*lunHoldRecord
	active  map[string]bool
	kick    chan struct{}
	resolve sync.Mutex // one resolve pass at a time
}

func (s *Server) lunHoldDir() string { return filepath.Join(s.dataDir, lunHoldDirName) }

// lunHoldsLocked loads the records once. Caller holds s.lunHolds.mu.
func (s *Server) lunHoldsLocked() error {
	h := &s.lunHolds
	if h.loaded {
		return h.loadErr
	}
	h.loaded = true
	h.recs = map[string]*lunHoldRecord{}
	if s.dataDir == "" {
		return nil
	}
	ents, err := os.ReadDir(s.lunHoldDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		h.loadErr = fmt.Errorf("read the iSCSI LUN holds in %s: %w", s.lunHoldDir(), err)
		return h.loadErr
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue // a temporary file a crash left behind: never renamed into place
		}
		b, err := os.ReadFile(filepath.Join(s.lunHoldDir(), name))
		var rec lunHoldRecord
		if err == nil {
			err = json.Unmarshal(b, &rec)
		}
		if err == nil && (rec.Token == "" || rec.Token+".json" != name || len(rec.LUNs) == 0) {
			err = errors.New("not a whole hold record")
		}
		if err != nil {
			h.loadErr = fmt.Errorf("read the iSCSI LUN hold %s: %w", filepath.Join(s.lunHoldDir(), name), err)
			return h.loadErr
		}
		h.recs[rec.Token] = &rec
	}
	return nil
}

// writeLUNHoldFile writes rec durably: a temporary file, fsynced, renamed
// into place, then the directory fsynced.
func (s *Server) writeLUNHoldFile(rec *lunHoldRecord) error {
	if s.dataDir == "" {
		return errors.New("this host has no data directory to record the hold in")
	}
	dir := s.lunHoldDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, rec.Token+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, rec.Token+".json"))
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncLUNHoldDir(dir)
}

func syncLUNHoldDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// putLUNHold records rec, active: a re-create in this process runs under it.
func (s *Server) putLUNHold(rec *lunHoldRecord) error {
	h := &s.lunHolds
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := s.lunHoldsLocked(); err != nil {
		return err
	}
	if h.active == nil {
		h.active = map[string]bool{}
	}
	h.active[rec.Token] = true
	if err := s.writeLUNHoldFile(rec); err != nil {
		delete(h.active, rec.Token)
		return err
	}
	h.recs[rec.Token] = rec
	return nil
}

// dropLUNHoldLocked removes a record. Caller holds s.lunHolds.mu.
func (s *Server) dropLUNHoldLocked(token string) error {
	h := &s.lunHolds
	if err := os.Remove(filepath.Join(s.lunHoldDir(), token+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncLUNHoldDir(s.lunHoldDir()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(h.recs, token)
	delete(h.active, token)
	return nil
}

// abandonLUNHold removes the hold of a re-create refused before anything was
// torn down or proposed beyond what its VM still holds.
func (s *Server) abandonLUNHold(token string) {
	h := &s.lunHolds
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := s.dropLUNHoldLocked(token); err != nil {
		slog.Warn("iSCSI LUN: could not remove the hold of a refused re-create; it is resolved later",
			"token", token, "error", err)
		delete(h.active, token)
	}
}

// finishLUNHold marks the re-create under token returned. The hold stays
// until resolveLUNHold finds evidence; a hold on this host's own create is
// judged at once (nothing to wait for but this host), others are judged by
// the resolver.
func (s *Server) finishLUNHold(token string) {
	h := &s.lunHolds
	h.mu.Lock()
	delete(h.active, token)
	rec := h.recs[token]
	kick := h.kick
	h.mu.Unlock()
	if rec == nil {
		return
	}
	if rec.RunHost == s.hostName {
		if _, err := s.resolveLUNHold(context.Background(), token); err != nil {
			slog.Info("iSCSI LUN: a re-create's hold is kept until its evidence can be read", "vm", rec.VM, "error", err)
		}
		return
	}
	if kick != nil {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
}

// lunHoldPresent reports whether this host still holds token on every key.
func (s *Server) lunHoldPresent(token string, keys []string) (bool, error) {
	h := &s.lunHolds
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := s.lunHoldsLocked(); err != nil {
		return false, err
	}
	rec := h.recs[token]
	if rec == nil {
		return false, nil
	}
	for _, k := range keys {
		if _, ok := rec.LUNs[k]; !ok {
			return false, nil
		}
	}
	return true, nil
}

// lunHoldHolders is the holds on keys, each an in-flight holder answered by
// this host, except the hold exempt.
func (s *Server) lunHoldHolders(keys map[string]bool, exempt string) ([]*pb.LUNHolder, error) {
	h := &s.lunHolds
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := s.lunHoldsLocked(); err != nil {
		return nil, err
	}
	var out []*pb.LUNHolder
	for tok, rec := range h.recs {
		if tok == exempt {
			continue
		}
		for k, disk := range rec.LUNs {
			if keys[k] {
				out = append(out, &pb.LUNHolder{Lun: k, VmName: rec.VM, DiskName: disk, HostName: s.hostName, InFlight: true})
			}
		}
	}
	return out, nil
}

// lunHoldTokens is the holds this host has.
func (s *Server) lunHoldTokens() ([]string, error) {
	h := &s.lunHolds
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := s.lunHoldsLocked(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(h.recs))
	for t := range h.recs {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// lunHoldKeys is rec's LUN keys.
func lunHoldKeys(rec *lunHoldRecord) []string {
	out := make([]string, 0, len(rec.LUNs))
	for k := range rec.LUNs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lunHoldRowsHere reports whether this host's replica has the incarnation of
// rec.VM created at createdAt live on every LUN rec holds.
func (s *Server) lunHoldRowsHere(ctx context.Context, rec *lunHoldRecord, createdAt string) (bool, error) {
	if createdAt == "" {
		return false, nil
	}
	uses, err := corrosion.LiveVMDiskUsesWithPathPrefix(ctx, s.db, iscsiDevicePrefix)
	if err != nil {
		return false, err
	}
	seen := map[string]bool{}
	for _, u := range uses {
		if u.VMName != rec.VM || u.VMCreatedAt != createdAt {
			continue
		}
		if k, ok := storage.FixedDeviceKeyOfPath(u.Path); ok {
			if _, held := rec.LUNs[k]; held {
				seen[k] = true
			}
		}
	}
	return len(seen) == len(rec.LUNs), nil
}

// ResolveLUNHolds judges every moved hold this host has once
// (resolveLUNHold), and returns the first error met.
func (s *Server) ResolveLUNHolds(ctx context.Context) error {
	toks, err := s.lunHoldTokens()
	if err != nil {
		return err
	}
	var first error
	for _, t := range toks {
		if _, err := s.resolveLUNHold(ctx, t); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// RunLUNHoldResolver judges this host's moved holds every interval, and at
// once whenever a re-create under one returns. It runs until ctx is done.
func (s *Server) RunLUNHoldResolver(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = lunHoldResolveEvery
	}
	kick := make(chan struct{}, 1)
	s.lunHolds.mu.Lock()
	s.lunHolds.kick = kick
	s.lunHolds.mu.Unlock()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
		}
		if err := s.ResolveLUNHolds(ctx); err != nil {
			slog.Debug("iSCSI LUN: a moved hold stays until its evidence can be read", "error", err)
		}
	}
}

// resolveLUNHold judges one hold, and releases it on positive evidence only
// (see the file comment). It reports whether it released it.
func (s *Server) resolveLUNHold(ctx context.Context, token string) (bool, error) {
	h := &s.lunHolds
	h.resolve.Lock()
	defer h.resolve.Unlock()
	h.mu.Lock()
	if err := s.lunHoldsLocked(); err != nil {
		h.mu.Unlock()
		return false, err
	}
	cur, active := h.recs[token], h.active[token]
	var rec lunHoldRecord
	if cur != nil {
		rec = *cur
	}
	h.mu.Unlock()
	if cur == nil || active {
		return false, nil
	}
	release := func(why string) (bool, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.active[token] {
			return false, nil
		}
		if err := s.dropLUNHoldLocked(token); err != nil {
			return false, err
		}
		slog.Info("iSCSI LUN: a moved claim's hold is released", "vm", rec.VM, "run_host", rec.RunHost, "evidence", why)
		return true, nil
	}
	if here, err := s.lunHoldRowsHere(ctx, &rec, rec.NewCreatedAt); err != nil {
		return false, err
	} else if here {
		return release("the re-created incarnation's rows are on this host")
	}
	holders, err := s.lunHoldRunHostAnswer(ctx, &rec)
	if err != nil {
		if s.lunHoldRunHostRemoved(ctx, rec.RunHost) {
			return release("the host it was re-created on was removed from the cluster")
		}
		return false, err
	}
	if len(holders) == 0 {
		return release(rec.RunHost + " shows nothing holding the LUN")
	}
	if c := lunHoldNewIncarnation(holders, &rec); c != "" && c != rec.NewCreatedAt {
		h.mu.Lock()
		if p := h.recs[token]; p != nil {
			next := *p
			next.NewCreatedAt = c
			if err := s.writeLUNHoldFile(&next); err == nil {
				h.recs[token] = &next
				rec.NewCreatedAt = c
			}
		}
		h.mu.Unlock()
		if here, err := s.lunHoldRowsHere(ctx, &rec, c); err == nil && here {
			return release("the re-created incarnation's rows are on this host")
		}
	}
	return false, nil
}

// lunHoldNewIncarnation is the created_at of rec.VM's re-created incarnation
// as RunHost's answer shows it: a row holder of that name that is not the
// replaced incarnation.
func lunHoldNewIncarnation(holders []*pb.LUNHolder, rec *lunHoldRecord) string {
	for _, hd := range holders {
		if !hd.InFlight && hd.VmName == rec.VM && hd.VmCreatedAt != "" && hd.VmCreatedAt != rec.ReplacedCreatedAt {
			return hd.VmCreatedAt
		}
	}
	return ""
}

// lunHoldRunHostAnswer is what rec's RunHost holds of rec's LUNs: this
// host's own answer when it is RunHost (rec itself aside), RunHost's,
// asked by name, otherwise.
func (s *Server) lunHoldRunHostAnswer(ctx context.Context, rec *lunHoldRecord) ([]*pb.LUNHolder, error) {
	keys := lunHoldKeys(rec)
	if rec.RunHost == "" || rec.RunHost == s.hostName {
		set := make(map[string]bool, len(keys))
		for _, k := range keys {
			set[k] = true
		}
		return s.lunHoldersHere(ctx, set, replacedVM{}, false, 0, rec.Token, "")
	}
	return s.askLUNHolders(ctx, rec.RunHost, &pb.LUNHoldersRequest{Luns: keys})
}

// lunHoldRunHostRemoved reports whether host's removal from the cluster is
// recorded here: its tombstone, or an adopted voter generation without it.
func (s *Server) lunHoldRunHostRemoved(ctx context.Context, host string) bool {
	if removed, err := corrosion.HostRemoved(ctx, s.db, host); err == nil && removed {
		return true
	}
	el, err := s.lunElectorate(ctx)
	return err == nil && s.votedOut(ctx, el, host)
}
