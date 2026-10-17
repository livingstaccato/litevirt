package grpcapi

import (
	"context"
	"sync"
)

// deleteVMWork owns only public DeleteVM bodies and the leftover cleanup they
// launch. A stopped tracker admits no new parent, but an admitted parent can
// still retain its child before it returns. Count cannot reach zero between
// those two ownership periods, so a completed drain cannot be reopened.
type deleteVMWork struct {
	mu      sync.Mutex
	stopped bool
	count   int
	idle    chan struct{}
}
type deleteVMParent struct {
	work   *deleteVMWork
	active bool // guarded by work.mu
}

func (w *deleteVMWork) begin() (*deleteVMParent, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return nil, false
	}
	if w.count == 0 {
		w.idle = make(chan struct{})
	}
	w.count++
	return &deleteVMParent{work: w, active: true}, true
}
func (w *deleteVMWork) finishedLocked() {
	w.count--
	if w.count == 0 {
		close(w.idle)
	}
}
func (p *deleteVMParent) finish() {
	w := p.work
	w.mu.Lock()
	defer w.mu.Unlock()
	p.active = false
	w.finishedLocked()
}
func (p *deleteVMParent) retainChild() (func(), bool) {
	w := p.work
	w.mu.Lock()
	defer w.mu.Unlock()
	if !p.active {
		return nil, false
	}
	w.count++
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.finishedLocked()
	}, true
}

// StopDeleteVMAdmission precedes dependency shutdown; it does not cancel
// already admitted work or change the cleanup's detached caller context.
func (s *Server) StopDeleteVMAdmission() {
	s.deleteWork.mu.Lock()
	s.deleteWork.stopped = true
	s.deleteWork.mu.Unlock()
}

// WaitDeleteVMWork follows StopDeleteVMAdmission. Dependencies must remain
// open until both the public wrappers and their retained children return.
func (s *Server) WaitDeleteVMWork() {
	s.deleteWork.mu.Lock()
	idle, n := s.deleteWork.idle, s.deleteWork.count
	s.deleteWork.mu.Unlock()
	s.dbWorkerEvent(context.Background(), "delete_vm", "drain")
	if n != 0 {
		<-idle
	}
}
