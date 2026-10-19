package grpcapi

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// migrationStubLedger is a migration target's own record of the disk stubs
// EnsureDisks created here, keyed by path.
//
// A --with-storage migration block-mirrors each source disk into the file at
// the same path on the target, and after a failed attempt the source asks the
// target to remove what it pre-created. Neither may touch a file that was
// already there: the same path on the target can hold that VM's disk from an
// earlier residency — one partition settle kept, in drill D1 — and the mirror
// overwrites it, the cleanup deletes it.
//
// The record is the TARGET's, deliberately. A source cannot know what is on
// the target's disk, and a source of an older build names every disk path in
// its cleanup, so only this side can tell a stub it made from a file it found.
//
// It is in memory. A restart forgets it, which costs only the direction that
// is safe: a stub made before the restart is then treated as a file this host
// did not create — a retry is refused naming it, and a cleanup leaves it.
//
// An entry belongs to the move that made it, and ends with it. It is bound
// to the VM's placement mark when it was made (Server.stubMark: the owner,
// the owner epoch and the placement generation), and once that has changed
// the entry no longer names a stub, and is dropped. Every writer that changes
// a VM's host advances the placement generation in the same batch, so the
// mark changes on every move — live, cold, drain or failover — a move back to
// an earlier host included (a live move commits without bumping the epoch,
// and A→B→A would otherwise make the first move's mark current again). The
// generation is kept only while the cluster-policy gate is open; for the
// moves this host drives, its entries for the VM also end when it starts
// sending the VM elsewhere (endMoveRecords), since a host that owns the VM is
// no move's target. A path that later holds the VM's live disk, or a file at
// it after the VM moved away again, must not read as a stub: a copy would
// replace it (lab2-drain anomaly 6). It also expires after stubLedgerTTL,
// past which no attempt that made it can still be running or cleaning up (an
// adopted migration is aborted at adoptedMigrationCeiling).
type migrationStubLedger struct {
	mu sync.Mutex
	m  map[string]migrationStub
}

type migrationStub struct {
	vm   string
	mark string // the VM's placement mark when the stub was made (Server.stubMark)
	at   time.Time
}

// stubLedgerTTL bounds how long a stub is recognised as this host's own.
func stubLedgerTTL() time.Duration { return adoptedMigrationCeiling + 15*time.Minute }

func (l *migrationStubLedger) add(vm, path, mark string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]migrationStub{}
	}
	l.m[path] = migrationStub{vm: vm, mark: mark, at: time.Now()}
}

// owns reports whether path is a stub this host created for vm in the move
// mark names, and has not outlived its TTL. An entry of another move, or
// expired, is dropped.
func (l *migrationStubLedger) owns(vm, path, mark string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[path]
	if !ok {
		return false
	}
	if time.Since(e.at) > stubLedgerTTL() || e.mark != mark {
		delete(l.m, path)
		return false
	}
	return e.vm == vm
}

// recordedFor returns every unexpired stub recorded for vm in the move mark
// names, with when it was made, so a cleanup can find what this host made
// where the source never learned of it. Entries of another move are dropped.
func (l *migrationStubLedger) recordedFor(vm, mark string) map[string]time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]time.Time{}
	for p, e := range l.m {
		if e.vm != vm {
			continue
		}
		if e.mark != mark || time.Since(e.at) > stubLedgerTTL() {
			delete(l.m, p)
			continue
		}
		out[p] = e.at
	}
	return out
}

func (l *migrationStubLedger) forget(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, path)
}

// forgetVM drops every entry recorded for vm.
func (l *migrationStubLedger) forgetVM(vm string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for p, e := range l.m {
		if e.vm == vm {
			delete(l.m, p)
		}
	}
}

// endMoveRecords ends every record this host made as a target of a move of
// vm. It runs when this host starts sending vm to another host: it owns vm
// then, so each move that made one of those records has ended.
func (s *Server) endMoveRecords(vm string) {
	s.migrationStubs.forgetVM(vm)
	s.migrationISOs.forgetVM(vm)
}

// stubMark is what binds a ledger entry for vm to the move that made it: the
// VM's placement mark now (corrosion.VMPlacementMark). ok=false when the row
// cannot be read; then nothing is recorded, and nothing reads as this host's
// stub (a stub then is a file this host did not create: a retry is refused
// naming it, a cleanup leaves it).
func (s *Server) stubMark(ctx context.Context, vm string) (string, bool) {
	mark, ok, err := corrosion.VMPlacementMark(ctx, s.db, vm)
	if err != nil || !ok {
		return "", false
	}
	return mark, true
}

// moveCatchUp bounds how long recording a stub waits for this host's replica
// to name the calling host as the VM's owner.
var moveCatchUp = 10 * time.Second

// awaitCallerOwns waits, bounded by moveCatchUp, until this host's replica
// names the calling host as vm's owner. It runs before a record is bound to
// the move's mark. The caller is the move's source, which owns vm; a replica
// that does not name it yet lags behind the commit that made it the owner,
// and a mark read from it would change when that commit arrives, mid-move:
// the move would then no longer recognise its own stub (refused by a retry,
// left by its cleanup). A caller that is no cluster host is not waited for.
// Past the bound the record takes the mark the replica holds then.
func (s *Server) awaitCallerOwns(ctx context.Context, vm string) {
	caller := callerMTLSCommonName(ctx)
	if caller == "" || caller == s.hostName || moveCatchUp <= 0 {
		return
	}
	if h, err := corrosion.GetHost(ctx, s.db, caller); err != nil || h == nil {
		return
	}
	deadline := time.Now().Add(moveCatchUp)
	for {
		rec, err := corrosion.GetVM(ctx, s.db, vm)
		if err == nil && rec != nil && rec.HostName == caller {
			return
		}
		if time.Now().After(deadline) {
			owner := ""
			if rec != nil {
				owner = rec.HostName
			}
			slog.Warn("migration stub record: this host's replica does not name the move's source as the VM's owner; recording against the owner it names",
				"vm", vm, "source", caller, "owner_here", owner, "waited", moveCatchUp)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// recordMade records path in l as made here for vm's current move.
func (s *Server) recordMade(ctx context.Context, l *migrationStubLedger, vm, path string) {
	s.awaitCallerOwns(ctx, vm)
	if mark, ok := s.stubMark(ctx, vm); ok {
		l.add(vm, path, mark)
	}
}

// madeHere reports whether l records path as made here for vm's current
// move.
func (s *Server) madeHere(ctx context.Context, l *migrationStubLedger, vm, path string) bool {
	mark, ok := s.stubMark(ctx, vm)
	return ok && l.owns(vm, path, mark)
}

// madeHereFor is every path l records as made here for vm's current move.
func (s *Server) madeHereFor(ctx context.Context, l *migrationStubLedger, vm string) map[string]time.Time {
	mark, ok := s.stubMark(ctx, vm)
	if !ok {
		return nil
	}
	return l.recordedFor(vm, mark)
}
