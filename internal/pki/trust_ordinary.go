package pki

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ErrOrdinaryTrustSize identifies an unsupported preparation, never a negative
// certificate verdict. This compatibility view is not strict transfer trust.
var ErrOrdinaryTrustSize = errors.New("ordinary claim trust exceeds supported preparation size")

// ErrOrdinaryTrustBudget means a smaller comparison unit may fit; an
// individual over-bound file is ErrOrdinaryTrustSize instead.
var ErrOrdinaryTrustBudget = errors.New("ordinary claim trust exceeds aggregate preparation budget")

type ordinaryLeafFacts struct {
	revoked   bool
	successor string
}

type OrdinaryClaimTrust struct {
	leaves map[[32]byte]ordinaryLeafFacts
	policy bool
}

func (v *OrdinaryClaimTrust) Contains(c *x509.Certificate) bool {
	if v == nil || c == nil {
		return false
	}
	_, ok := v.leaves[sha256.Sum256(c.Raw)]
	return ok
}
func (v *OrdinaryClaimTrust) Revoked(c *x509.Certificate) bool {
	return v.leaves[sha256.Sum256(c.Raw)].revoked
}
func (v *OrdinaryClaimTrust) Superseded(c *x509.Certificate) error {
	successor := v.leaves[sha256.Sum256(c.Raw)].successor
	if successor == "" {
		return nil
	}
	return &supersededErr{cn: c.Subject.CommonName, serial: c.SerialNumber.Text(16), successor: successor}
}
func (v *OrdinaryClaimTrust) TrustRotatedPeers() bool { return v.policy }

// OrdinaryClaimLease freezes only the legacy CRL/successor/policy predicates
// for exact observed leaves. It cannot mint HostCertificateValidation values.
// Callers acquire it before DB, verify signatures/time in DB, and release after
// commit/rollback. Its view does not learn or touch the filesystem.
type OrdinaryClaimLease struct {
	mu   sync.Mutex
	self *OrdinaryClaimLease
	lock *trustLock
}

func (l *OrdinaryClaimLease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.self != l || l.lock == nil {
		return
	}
	l.lock.release()
	l.lock = nil
}

// AcquireOrdinaryClaimTrust learns the exact eligible candidate leaves before
// capturing their ordinary predicates. Failed persistence retains effective
// memory evidence, as legacy pinning requires; it never certifies durability.
// remainingBytes is the caller's aggregate budget after owned certificates and
// configurations. Size refusal precedes reading/decoding retained large files.
func AcquireOrdinaryClaimTrust(ctx context.Context, dir string, leaves []*x509.Certificate, policy *atomic.Bool, remainingBytes int) (*OrdinaryClaimTrust, *OrdinaryClaimLease, error) {
	o, err := trustOwnerFor(dir)
	if err != nil {
		return nil, nil, err
	}
	if err := bindOrdinaryPolicy(o, policy); err != nil {
		return nil, nil, err
	}
	lock, err := o.lock(ctx)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*OrdinaryClaimTrust, *OrdinaryClaimLease, error) {
		lock.release()
		return nil, nil, err
	}
	if remainingBytes < 0 {
		return fail(ErrOrdinaryTrustBudget)
	}
	// Count exact raw evidence once. Unreadable legacy files retain their old
	// availability policy, but an observable oversize is an operational refusal.
	var crl []byte
	for _, item := range []struct {
		name  string
		limit int
	}{{"ca.crt", maxServingChainBytes}, {"crl.pem", maxTrustCRLBytes}, {supersededFile, maxSupersededBytes}} {
		path := filepath.Join(o.dir, item.name)
		if stat, e := os.Stat(path); e == nil {
			if stat.Size() > int64(item.limit) {
				return fail(ErrOrdinaryTrustSize)
			}
			if stat.Size() > int64(remainingBytes) {
				return fail(ErrOrdinaryTrustBudget)
			}
		}
		raw, e := readBoundedN(path, item.limit)
		if e == nil {
			if len(raw) > remainingBytes {
				return fail(ErrOrdinaryTrustBudget)
			}
			remainingBytes -= len(raw)
		}
		if item.name == "crl.pem" && e == nil {
			crl = raw
		}
	}
	if policy != nil && o.policyCell != nil && o.policyCell != policy {
		return fail(errors.New("ordinary verifier uses a different effective policy source"))
	}
	for _, leaf := range leaves {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if leaf != nil {
			o.noteSuccessorLocked(leaf)
		}
	}
	store := supersessionsFor(o.dir)
	store.mu.Lock()
	store.fileNext = time.Time{}
	loaded := store.loadLocked()
	// Unsaved memory can exceed the retained file; include its unique raw bytes
	// conservatively, even when the same evidence also appears on disk.
	if loaded {
		for _, list := range store.byPrev {
			for _, entry := range list {
				if len(entry.successor.Raw) > remainingBytes {
					store.mu.Unlock()
					return fail(ErrOrdinaryTrustBudget)
				}
				remainingBytes -= len(entry.successor.Raw)
			}
		}
	}
	parseRevoked, verifiedRevoked := map[string]bool{}, map[string]bool{}
	if lists, e := parseCRLs(crl); e == nil {
		verified := loaded
		for _, list := range lists {
			if loaded && list.CheckSignatureFrom(store.ca) != nil {
				verified = false
			}
			for _, entry := range list.RevokedCertificateEntries {
				parseRevoked[entry.SerialNumber.Text(16)] = true
			}
		}
		if verified {
			verifiedRevoked = parseRevoked
		}
	}
	standing := &HostTrust{successors: store.byPrev, revoked: verifiedRevoked}
	view := &OrdinaryClaimTrust{leaves: make(map[[32]byte]ordinaryLeafFacts, len(leaves)), policy: o.policy}
	if policy != nil {
		view.policy = policy.Load()
		if o.policyCell != nil && view.policy != o.policy {
			store.mu.Unlock()
			return fail(errors.New("effective host policy changed outside owner"))
		}
	}
	for _, leaf := range leaves {
		if leaf == nil {
			continue
		}
		facts := ordinaryLeafFacts{revoked: parseRevoked[leaf.SerialNumber.Text(16)]}
		if loaded {
			for _, entry := range store.byPrev[leaf.SerialNumber.Text(16)] {
				serial := entry.successor.SerialNumber.Text(16)
				if entry.cn == leaf.Subject.CommonName && (!verifiedRevoked[serial] || standing.standing(entry.cn, serial, 1)) {
					facts.successor = serial
					break
				}
			}
		}
		view.leaves[sha256.Sum256(leaf.Raw)] = facts
	}
	store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fail(fmt.Errorf("ordinary trust capture: %w", err))
	}
	lease := &OrdinaryClaimLease{lock: lock}
	lease.self = lease
	return view, lease, nil
}
