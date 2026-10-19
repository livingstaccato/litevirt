package grpcapi

import (
	"context"
	"fmt"
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
// An entry belongs to the move that made it, and ends with it: it is bound to
// the VM's owner and owner epoch when it was made (Server.stubMark), and once
// either has changed (the move committed, here or anywhere, or the row was
// re-pointed) the entry no longer names a stub, and is dropped. A path that
// later holds the VM's live disk, or a file at it after the VM moved away
// again, must not read as a stub: a copy would replace it (lab2-drain
// anomaly 6). It also expires after stubLedgerTTL, past which no attempt
// that made it can still be running or cleaning up (an adopted migration is
// aborted at adoptedMigrationCeiling).
type migrationStubLedger struct {
	mu sync.Mutex
	m  map[string]migrationStub
}

type migrationStub struct {
	vm   string
	mark string // the VM's owner and owner epoch when the stub was made
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

// stubMark is what binds a ledger entry for vm to the move that made it: the
// VM's owner and owner epoch now. ok=false when the row cannot be read; then
// nothing is recorded, and nothing reads as this host's stub (a stub then is
// a file this host did not create: a retry is refused naming it, a cleanup
// leaves it).
func (s *Server) stubMark(ctx context.Context, vm string) (string, bool) {
	rec, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil || rec == nil {
		return "", false
	}
	return fmt.Sprintf("%s#%d", rec.HostName, rec.OwnerEpoch), true
}

// recordMade records path in l as made here for vm's current move.
func (s *Server) recordMade(ctx context.Context, l *migrationStubLedger, vm, path string) {
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
