package grpcapi

import (
	"sync"
	"time"
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
// An entry expires after stubLedgerTTL: past that no attempt that made it can
// still be running or cleaning up (an adopted migration is aborted at
// adoptedMigrationCeiling), and a path that later holds the VM's live disk
// must not still read as a stub.
type migrationStubLedger struct {
	mu sync.Mutex
	m  map[string]migrationStub
}

type migrationStub struct {
	vm string
	at time.Time
}

// stubLedgerTTL bounds how long a stub is recognised as this host's own.
func stubLedgerTTL() time.Duration { return adoptedMigrationCeiling + 15*time.Minute }

func (l *migrationStubLedger) add(vm, path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]migrationStub{}
	}
	l.m[path] = migrationStub{vm: vm, at: time.Now()}
}

// owns reports whether path is a stub this host created for vm and has not
// outlived its TTL. An expired entry is dropped.
func (l *migrationStubLedger) owns(vm, path string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[path]
	if !ok {
		return false
	}
	if time.Since(e.at) > stubLedgerTTL() {
		delete(l.m, path)
		return false
	}
	return e.vm == vm
}

// recordedFor returns every unexpired stub recorded for vm, with when it was
// made, so a cleanup can find what this host made where the source never
// learned of it.
func (l *migrationStubLedger) recordedFor(vm string) map[string]time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]time.Time{}
	for p, e := range l.m {
		if e.vm == vm && time.Since(e.at) <= stubLedgerTTL() {
			out[p] = e.at
		}
	}
	return out
}

func (l *migrationStubLedger) forget(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, path)
}
