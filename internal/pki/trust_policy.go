package pki

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
)

type hostPolicyBinding struct{ owner *trustOwner }

var hostPolicies = struct {
	sync.Mutex
	cells   map[*atomic.Bool]*hostPolicyBinding
	pending map[string]*atomic.Bool
	paths   map[string]*trustOwner
}{cells: map[*atomic.Bool]*hostPolicyBinding{}, pending: map[string]*atomic.Bool{}, paths: map[string]*trustOwner{}}

// bindPolicyLocked runs only under the short registry mutex. It never waits on
// an owner. Once bound, a cell cannot fall back to uncoordinated preconfiguration.
func bindPolicyLocked(o *trustOwner, cell *atomic.Bool) error {
	binding := hostPolicies.cells[cell]
	if binding == nil {
		binding = &hostPolicyBinding{}
		hostPolicies.cells[cell] = binding
	}
	if binding.owner != nil && binding.owner != o {
		return errors.New("effective policy cell is bound to another PKI owner")
	}
	if existing := o.pendingPolicy.Load(); existing != nil && existing != cell {
		return errors.New("PKI owner already has an effective policy source")
	}
	binding.owner = o
	o.pendingPolicy.Store(cell)
	return nil
}

func rememberTrustOwnerPath(dir string, o *trustOwner) error {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	hostPolicies.Lock()
	defer hostPolicies.Unlock()
	var pending *atomic.Bool
	for _, path := range []string{absolute, o.dir} {
		if cell := hostPolicies.pending[path]; cell != nil {
			if pending != nil && pending != cell {
				return errors.New("conflicting pending policy cells for PKI aliases")
			}
			pending = cell
		}
	}
	if pending != nil {
		if err := bindPolicyLocked(o, pending); err != nil {
			return err
		}
	}

	hostPolicies.paths[absolute] = o
	hostPolicies.paths[o.dir] = o
	return nil
}

func bindOrdinaryPolicy(o *trustOwner, cell *atomic.Bool) error {
	if cell == nil {
		return nil
	}
	hostPolicies.Lock()
	defer hostPolicies.Unlock()
	return bindPolicyLocked(o, cell)
}

func (o *trustOwner) reconcilePolicyLocked() error {
	cell := o.pendingPolicy.Load()
	if cell == nil {
		return nil
	}
	if o.policyCell == nil {
		o.policyCell = cell
		o.policy = cell.Load()
		o.invalidateLocked()
		return nil
	}
	if o.policyCell != cell || o.policy != cell.Load() {
		return errors.New("effective host policy changed outside owner")
	}
	return nil
}

// PublishHostTrustPolicy publishes the actual application policy cell. An
// unbound cell can be configured before its directory exists. Binding is
// serialized with that Store, and all bound changes require the canonical
// owner/file barrier. Lexical paths are pending lookup keys, never trust roots.
func PublishHostTrustPolicy(dir string, effective *atomic.Bool, value bool) error {
	if effective == nil {
		return errors.New("missing effective host policy")
	}
	absolute := ""
	var err error
	if dir != "" {
		absolute, err = filepath.Abs(dir)
		if err != nil {
			return err
		}
	}
	hostPolicies.Lock()
	binding := hostPolicies.cells[effective]
	if binding == nil {
		binding = &hostPolicyBinding{}
		hostPolicies.cells[effective] = binding
	}
	if bound := binding.owner; bound != nil {
		hostPolicies.Unlock()
		return publishBoundHostPolicy(dir, effective, value, bound)
	}
	if dir == "" {
		effective.Store(value)
		hostPolicies.Unlock()
		return nil
	}
	if prior := hostPolicies.pending[absolute]; prior != nil && prior != effective {
		hostPolicies.Unlock()
		return errors.New("PKI path already has an effective policy source")
	}
	if known := hostPolicies.paths[absolute]; known != nil {
		if err := bindPolicyLocked(known, effective); err != nil {
			hostPolicies.Unlock()
			return err
		}
	}
	hostPolicies.pending[absolute] = effective
	hostPolicies.Unlock()
	o, err := trustOwnerFor(dir)
	if err != nil {
		hostPolicies.Lock()
		defer hostPolicies.Unlock()
		if binding.owner != nil {
			return err
		}
		effective.Store(value)
		return nil
	}
	if err := bindOrdinaryPolicy(o, effective); err != nil {
		return err
	}
	return publishBoundHostPolicy(dir, effective, value, o)
}

func publishBoundHostPolicy(dir string, effective *atomic.Bool, value bool, o *trustOwner) error {
	if dir == "" {
		return errors.New("bound host policy cannot become unconfigured")
	}
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return err
	}
	if canonical != o.dir {
		return errors.New("bound host policy cannot change PKI directory")
	}
	lock, err := o.lock(context.Background())
	if err != nil {
		return err
	}
	defer lock.release()
	if o.policy != value {
		o.invalidateLocked()
	}
	o.policy = value
	effective.Store(value)
	return nil
}
