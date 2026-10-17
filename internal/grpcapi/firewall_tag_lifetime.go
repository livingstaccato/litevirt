package grpcapi

// beginFirewallTagWork registers an entire synchronous affected body before
// its first DB read. Admission and shutdown share the mutex, so no Add can
// follow a completed drain. It covers SetFirewallTags and delete tag hygiene,
// not arbitrary RPCs or the daemon's other DB users.
func (s *Server) beginFirewallTagWork() (func(), bool) {
	s.fwTagWorkMu.Lock()
	defer s.fwTagWorkMu.Unlock()
	if s.fwTagWorkStopped {
		return nil, false
	}
	if s.fwTagWorkCount == 0 {
		s.fwTagWorkIdle = make(chan struct{})
	}
	s.fwTagWorkCount++
	return func() {
		s.fwTagWorkMu.Lock()
		defer s.fwTagWorkMu.Unlock()
		s.fwTagWorkCount--
		if s.fwTagWorkCount == 0 {
			close(s.fwTagWorkIdle)
		}
	}, true
}

// StopFirewallTagAdmission refuses new affected bodies before irreversible work.
func (s *Server) StopFirewallTagAdmission() {
	s.fwTagWorkMu.Lock()
	s.fwTagWorkStopped = true
	s.fwTagWorkMu.Unlock()
}

// WaitFirewallTagWork follows StopFirewallTagAdmission and keeps dependencies
// open until all admitted bodies, including their detached completion, return.
func (s *Server) WaitFirewallTagWork() {
	s.fwTagWorkMu.Lock()
	idle, n := s.fwTagWorkIdle, s.fwTagWorkCount
	s.fwTagWorkMu.Unlock()
	if n != 0 {
		<-idle
	}
}
