package pki

import (
	"context"
	"errors"
	"sync"
	"time"
)

// HostCertificateLease protects only validated host PKI predicates. Storage
// must independently bind its transaction and check this lease before commit.
type HostCertificateLease struct {
	mu          sync.Mutex
	self        *HostCertificateLease
	lock        *trustLock
	ctx         context.Context
	validations []*HostCertificateValidation
}

func AcquireHostCertificateLease(ctx context.Context, dir string, validations ...*HostCertificateValidation) (*HostCertificateLease, error) {
	if len(validations) == 0 || len(validations) > maxHostValidations {
		return nil, errors.New("invalid host validation set")
	}
	o, err := trustOwnerFor(dir)
	if err != nil {
		return nil, err
	}
	lock, err := o.lock(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*HostCertificateLease, error) { lock.release(); return nil, err }
	for _, cap := range validations {
		if cap == nil || cap.view == nil || cap.view.owner != o || cap.view.nonce != o.nonce || !o.capabilities[cap] {
			return fail(errors.New("foreign or inactive host validation"))
		}
	}
	// Another process cannot change this owner's counter. Always reread and
	// reconcile installed evidence while holding the cross-process lock.
	if _, err := o.captureLocked(validations[0].view.host); err != nil {
		return fail(err)
	}
	lease := &HostCertificateLease{lock: lock, ctx: ctx, validations: append([]*HostCertificateValidation(nil), validations...)}
	lease.self = lease
	if err := lease.Check(); err != nil {
		lease.Release()
		return nil, err
	}
	return lease, nil
}

// Check is the guarded local authorization instant, not a frozen clock. A
// consumer calls it again after waits immediately before its actual COMMIT.
func (l *HostCertificateLease) Check() error {
	if l == nil {
		return errors.New("nil host certificate lease")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.self != l || l.lock == nil {
		return errors.New("inactive host certificate lease")
	}
	if err := l.ctx.Err(); err != nil {
		return err
	}
	o := l.lock.owner
	if o.pendingPolicy.Load() != o.policyCell {
		return errors.New("effective host policy binding changed")
	}
	now := time.Now()
	for _, cap := range l.validations {
		if !o.capabilities[cap] || cap.view.nonce != o.nonce || cap.view.revision != o.revision || cap.view.digest != o.digest || o.dirty != nil {
			return errors.New("host trust changed after validation")
		}
		if now.Before(cap.view.at) || now.Before(cap.notBefore) || !now.Before(cap.notAfter) {
			return errors.New("host certificate not currently valid")
		}
	}
	return nil
}

func (l *HostCertificateLease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.self != l || l.lock == nil {
		return
	}
	for _, cap := range l.validations {
		delete(l.lock.owner.capabilities, cap)
	}
	l.lock.release()
	l.lock = nil
}
