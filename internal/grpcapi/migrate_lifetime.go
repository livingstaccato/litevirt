package grpcapi

import "sync"

// migrationProducers owns MigrateVM, each admitted drainOneVM, Release, and
// migration adopters. Closing admission and admitting a parent share mu, so
// Wait cannot observe zero and then race a new parent Add. An admitted parent
// retains its adopter before returning; that Add has a live parent count even
// after admission closes. Recovery has its separate producer/child join.
type migrationProducers struct {
	mu      sync.Mutex
	stopped bool
	wg      sync.WaitGroup
}

func (w *migrationProducers) begin() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return false
	}
	w.wg.Add(1)
	return true
}

// retainAdopter is called synchronously by an admitted migration parent,
// before spawning the adopter and before releasing the parent's own count.
// It must not reopen admission: the outcome is already owed by that parent.
func (w *migrationProducers) retainAdopter() { w.wg.Add(1) }
func (w *migrationProducers) done()          { w.wg.Done() }

// StopMigrationAdmission prevents new migration/Release parents from touching
// dependencies during shutdown. It does not cancel admitted work or reject
// its retained adopter. Call before the bounded transport stop.
func (s *Server) StopMigrationAdmission() {
	s.migrationProducers.mu.Lock()
	s.migrationProducers.stopped = true
	s.migrationProducers.mu.Unlock()
}
