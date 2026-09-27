package grpcapi

import "sync"

// TryLockContainer takes the lock LockContainer takes, only if no operation
// holds it: ok is false, and nothing is held, when one does. It is the
// container checker's lock (health.ContainerChecker.SetContainerLock) — its
// sweep is serial, and backup, migrate, snapshot, restore and clone hold the
// lock for their whole run, so waiting for it would stall every other
// container's reconcile behind one long operation.
func (s *Server) TryLockContainer(name string) (unlock func(), ok bool) {
	mu := s.vmMutex("ct/" + name)
	if !mu.TryLock() {
		return nil, false
	}
	return mu.Unlock, true
}

// vmMutex is the mutex lockVM takes for name, created on first use.
func (s *Server) vmMutex(name string) *sync.Mutex {
	s.vmLocksMu.Lock()
	defer s.vmLocksMu.Unlock()
	if s.vmLocks == nil {
		s.vmLocks = map[string]*sync.Mutex{}
	}
	mu, ok := s.vmLocks[name]
	if !ok {
		mu = &sync.Mutex{}
		s.vmLocks[name] = mu
	}
	return mu
}
