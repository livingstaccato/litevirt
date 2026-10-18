package grpcapi

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// createFlight is one create of a VM running on this host as the VM's owner,
// from its start to its return. uuid is the domain uuid the create minted,
// once it has.
type createFlight struct {
	name  string
	uuid  string
	since time.Time
}

// beginCreate registers the owner leg of a create of name on this host. While
// it is registered, a second create of the name is refused here with Aborted,
// before it reserves, sweeps or makes anything: the two would otherwise share
// the name's domain, disk and seed paths, and the second's orphan sweep, debris
// sweep and failed-create cleanup would act on the first's files (lab 2
// delcancel r5, item 4: a `compose up` killed mid re-create and run again).
//
// It is not lockVM: a rebuild calls the create while holding that lock, and a
// create waiting behind a long one would answer a client that gave up long ago.
// The returned func ends the flight; setUUID records the uuid the create mints.
func (s *Server) beginCreate(name string) (end func(), setUUID func(string), err error) {
	s.createFlightsMu.Lock()
	defer s.createFlightsMu.Unlock()
	for f := range s.createFlights {
		if f.name == name {
			return nil, nil, status.Errorf(codes.Aborted,
				"a create of VM %q is in progress on %s (since %s, %s ago); this create did nothing. "+
					"Retry once that one has finished: `lv inspect %s` shows the VM it made",
				name, s.hostName, f.since.UTC().Format(time.RFC3339), time.Since(f.since).Round(time.Second), name)
		}
	}
	if s.createFlights == nil {
		s.createFlights = map[*createFlight]struct{}{}
	}
	// Each flight is its own entry, not the name's: the orphan sweep's
	// guard (liveCreateDefined) finds every create in flight by its uuid.
	f := &createFlight{name: name, since: time.Now()}
	s.createFlights[f] = struct{}{}
	end = func() {
		s.createFlightsMu.Lock()
		defer s.createFlightsMu.Unlock()
		delete(s.createFlights, f)
	}
	setUUID = func(u string) {
		s.createFlightsMu.Lock()
		defer s.createFlightsMu.Unlock()
		f.uuid = u
	}
	return end, setUUID, nil
}

// liveCreateDefined reports whether a create in flight on this host minted
// domain uuid u, other than the caller's own (self): a domain of that uuid is
// that create's, never a leftover to sweep.
func (s *Server) liveCreateDefined(u, self string) bool {
	if u == "" || u == self {
		return false
	}
	s.createFlightsMu.Lock()
	defer s.createFlightsMu.Unlock()
	for f := range s.createFlights {
		if f.uuid == u {
			return true
		}
	}
	return false
}

// refuseExistingVM refuses a create of name while a VM of the name exists. A
// rebuild or recreate whose replica here has not yet applied the tombstone of
// the VM it replaces sees that VM's row: exactly that incarnation is settled
// (settleReplacedVM), anything else still refuses.
func (s *Server) refuseExistingVM(ctx context.Context, name string) error {
	existing, _ := corrosion.GetVM(ctx, s.db, name)
	if existing == nil {
		return nil
	}
	replaced, err := s.settleReplacedVM(ctx, existing)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"VM %q: this host still holds the VM it re-creates and could not retire it: %v", name, err)
	}
	if !replaced {
		return status.Errorf(codes.AlreadyExists, "VM %q already exists", name)
	}
	return nil
}

// refuseLiveDomainOfName is the create's orphan sweep's guard. A domain of
// the name with no VM record is removed only when it is a leftover: one that
// runs is a guest, whatever left it there (a create that could not stop its
// own domain, or a row lost), and one a create in flight here defined is that
// create's. The create is refused for either and nothing is touched; it used
// to destroy and undefine the domain, which made a live guest's domain
// transient and let the debris sweep unlink the disk its qemu had open.
// A state that cannot be read refuses too.
func (s *Server) refuseLiveDomainOfName(name, self string) error {
	x, xerr := s.virt.DumpXMLInactive(name)
	if xerr != nil {
		x, _ = s.virt.DumpXML(name)
	}
	if s.liveCreateDefined(domainUUIDFromXML(x), self) {
		return status.Errorf(codes.Aborted,
			"a create of VM %q is in progress on %s; this create did nothing. Retry once that one has finished", name, s.hostName)
	}
	active, err := s.virt.DomainIsActive(name)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"create %s refused on %s: a domain of the name is defined with no VM record, and whether it runs cannot be read (%v); "+
				"nothing was created and the domain is left as it is", name, s.hostName, err)
	}
	if active {
		return status.Errorf(codes.FailedPrecondition,
			"create %s refused on %s: a domain of the name is running there with no VM record; nothing was created and the "+
				"domain is left as it is, with its disks. Find out what it is before it is stopped: once it is, the next create "+
				"of %s removes it and the disks at its name's paths",
			name, s.hostName, name)
	}
	return nil
}

// foreignDomainDiskPaths is the disk sources of the domain of name when it is
// not the one a create of uuid self defined (libvirt reads a stopped
// domain's from its definition): a failed create removes none of them. A domain whose uuid
// cannot be read is foreign. Empty when no domain of the name exists.
func (s *Server) foreignDomainDiskPaths(name, self string) map[string]bool {
	if s.virt == nil || !s.virt.DomainExists(name) {
		return nil
	}
	x, err := s.virt.DumpXMLInactive(name)
	if err != nil {
		x, _ = s.virt.DumpXML(name)
	}
	if u := domainUUIDFromXML(x); u != "" && u == self {
		return nil
	}
	out := map[string]bool{}
	if src, err := s.virt.DomainDiskSources(name); err == nil {
		for _, p := range src {
			out[p] = true
		}
	}
	return out
}
