package libvirtfake

import "fmt"

// ppMark is one domain's partition-pause mark and the run it was set in.
type ppMark struct {
	token string
	run   int
}

// MarkPartitionPaused mirrors libvirt.Client.MarkPartitionPaused: a live-only
// metadata element, so the domain must be active, and it holds only for the
// QEMU run it was set in.
func (f *Fake) MarkPartitionPaused(name, token string) error {
	defer f.daemon()()
	if f.FailMarkPartitionPaused != nil {
		if err := f.FailMarkPartitionPaused(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[name]
	if !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	if st != StateRunning && st != StatePaused {
		return fmt.Errorf("libvirtfake: domain %q is not running (%s)", name, st)
	}
	if f.ppMark == nil {
		f.ppMark = map[string]ppMark{}
	}
	f.ppMark[name] = ppMark{token: token, run: f.starts[name]}
	return nil
}

// PartitionPauseMark mirrors libvirt.Client.PartitionPauseMark.
func (f *Fake) PartitionPauseMark(name string) (string, bool, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[name]
	if !ok {
		return "", false, fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	m, ok := f.ppMark[name]
	if !ok || (st != StateRunning && st != StatePaused) || m.run != f.starts[name] {
		return "", false, nil
	}
	return m.token, true, nil
}

// ClearPartitionPauseMark mirrors libvirt.Client.ClearPartitionPauseMark.
func (f *Fake) ClearPartitionPauseMark(name string) error {
	defer f.daemon()()
	if f.FailClearPartitionPauseMark != nil {
		if err := f.FailClearPartitionPauseMark(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return fmt.Errorf("libvirtfake: domain %q not found", name) // libvirt's lookup error reads so
	}
	delete(f.ppMark, name)
	return nil
}
