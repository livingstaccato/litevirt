package libvirtfake

import (
	"fmt"
	"sync"
)

// ImageLocks models QEMU's image locking on shared storage (an NFS or
// cluster-filesystem pool): a QEMU process holds a write lock on every image
// it has open for as long as it is alive, RUNNING or PAUSED, and a second
// QEMU on any host that opens the same image fails to start with
// `Failed to get "write" lock`. Destroying the domain ends the process and
// releases the lock.
//
// Several fakes (one per fleet node) Join one ImageLocks; Declare names the
// images a domain uses, by domain name, on every member. Whether an image is
// held is read from the members' domain states at the moment of a start, so
// nothing has to release it: a domain that is no longer running or paused
// holds nothing.
type ImageLocks struct {
	mu      sync.Mutex // serialises starts across members, so a check and its start are one step
	images  map[string][]string
	members []*Fake
}

// NewImageLocks returns an empty registry.
func NewImageLocks() *ImageLocks { return &ImageLocks{images: map[string][]string{}} }

// Join makes f a member: its starts are refused while another member's live
// domain holds one of the starting domain's images.
func (l *ImageLocks) Join(f *Fake) {
	l.mu.Lock()
	l.members = append(l.members, f)
	l.mu.Unlock()
	f.mu.Lock()
	f.imageLocks = l
	f.mu.Unlock()
}

// Declare records that domain (on whichever member defines it) uses paths.
func (l *ImageLocks) Declare(domain string, paths ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.images[domain] = append(l.images[domain], paths...)
}

// heldBy reports the first image of domain that another member's live domain
// holds, and which domain holds it. self's own copy of domain is not a holder:
// starting a domain that is already active is libvirt's own refusal. The
// caller holds l.mu and none of the members' f.mu.
func (l *ImageLocks) heldBy(self *Fake, domain string) (image, holder string, ok bool) {
	want := map[string]bool{}
	for _, p := range l.images[domain] {
		want[p] = true
	}
	if len(want) == 0 {
		return "", "", false
	}
	for _, m := range l.members {
		m.mu.Lock()
		for dom, st := range m.domains {
			if (m == self && dom == domain) || (st != StateRunning && st != StatePaused) {
				continue
			}
			for _, p := range l.images[dom] {
				if want[p] {
					m.mu.Unlock()
					return p, dom, true
				}
			}
		}
		m.mu.Unlock()
	}
	return "", "", false
}

// lockedStart runs start under the registry's lock, refusing it while another
// member holds one of domain's images. With no registry it is start.
func (f *Fake) lockedStart(domain string, start func() error) error {
	f.mu.Lock()
	l := f.imageLocks
	f.mu.Unlock()
	if l == nil {
		return start()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if img, _, held := l.heldBy(f, domain); held {
		f.mu.Lock()
		f.record("start-refused", domain, "image-lock="+img)
		f.mu.Unlock()
		return fmt.Errorf("libvirtfake: start domain %q: internal error: process exited while connecting to monitor: "+
			"Failed to get \"write\" lock\nIs another process using the image [%s]?", domain, img)
	}
	return start()
}
