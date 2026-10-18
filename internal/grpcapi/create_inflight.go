package grpcapi

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
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
		// Say which domain, and whether litevirt ever stamped it as a VM's
		// runtime, so the operator can tell a lost row from a hand-made guest.
		u := domainUUIDFromXML(x)
		if u == "" {
			u = "unreadable"
		}
		stamp := "it carries no litevirt owner-epoch stamp"
		if e, ok, gerr := s.virt.GetDomainOwnerEpoch(name); gerr != nil {
			stamp = fmt.Sprintf("its litevirt owner-epoch stamp cannot be read (%v)", gerr)
		} else if ok {
			stamp = fmt.Sprintf("it carries litevirt's owner-epoch stamp %d, so it was a litevirt VM's runtime", e)
		}
		return status.Errorf(codes.FailedPrecondition,
			"create %s refused on %s: a domain of the name (uuid %s) is running there with no VM record; %s. Nothing was "+
				"created and the domain is left as it is, with its disks. Find out what it is before it is stopped: once it is, "+
				"the next create of %s removes it and the disks at its name's paths",
			name, s.hostName, u, stamp, name)
	}
	return nil
}

// foreignDomainDiskPaths reports, for a path, whether the domain of name names
// it when that domain is not the one a create of uuid self defined (libvirt
// reads a stopped domain's sources from its definition): a failed create
// removes none of those. A source is matched by its spelling and by the file
// it is (a symlinked pool directory names one file two ways). A domain whose
// uuid cannot be read is foreign. Nothing matches when no domain of the name
// exists.
func (s *Server) foreignDomainDiskPaths(name, self string) func(string) bool {
	none := func(string) bool { return false }
	if s.virt == nil || !s.virt.DomainExists(name) {
		return none
	}
	x, err := s.virt.DumpXMLInactive(name)
	if err != nil {
		x, _ = s.virt.DumpXML(name)
	}
	if u := domainUUIDFromXML(x); u != "" && u == self {
		return none
	}
	byName := map[string]bool{}
	var files []os.FileInfo
	if src, err := s.virt.DomainDiskSources(name); err == nil {
		for _, p := range src {
			byName[p] = true
			if fi, serr := os.Stat(p); serr == nil {
				files = append(files, fi)
			}
		}
	}
	return func(p string) bool {
		if byName[p] {
			return true
		}
		fi, err := os.Stat(p)
		if err != nil {
			return false
		}
		for _, f := range files {
			if os.SameFile(fi, f) {
				return true
			}
		}
		return false
	}
}

// domainIsVMsOwn reports whether the domain of name on this host is the
// runtime of the VM whose spec uuid is specUUID. Its uuid is the VM's (every
// definer carries it), or, when diskOwner names the VM, the domain runs on a
// disk the VM's row records on this host (a domain an older promotion or
// restore defined under a uuid libvirt chose). The owner-epoch stamp is no
// identity: healers write it by name onto whatever domain of the name runs on
// the owner, and epochs repeat across VMs and incarnations. du is the
// domain's uuid; err is set when what the domain is cannot be read, and then
// nothing about it is known.
func (s *Server) domainIsVMsOwn(ctx context.Context, name, specUUID, diskOwner string) (own bool, du string, err error) {
	x, xerr := s.virt.DumpXMLInactive(name)
	if xerr != nil {
		var lerr error
		if x, lerr = s.virt.DumpXML(name); lerr != nil {
			return false, "", fmt.Errorf("%v; live: %v", xerr, lerr)
		}
	}
	du = domainUUIDFromXML(x)
	if du == "" {
		return false, "", fmt.Errorf("its definition names no uuid")
	}
	if specUUID != "" && du == specUUID {
		return true, du, nil
	}
	if diskOwner == "" {
		return false, du, nil
	}
	recorded, rerr := corrosion.GetVMDisks(ctx, s.db, diskOwner)
	if rerr != nil {
		return false, du, fmt.Errorf("the VM's disks cannot be read: %v", rerr)
	}
	var mine []string
	for _, d := range recorded {
		if d.HostName == s.hostName && d.Path != "" && (d.DeviceKind == "" || d.DeviceKind == "disk") {
			mine = append(mine, d.Path)
		}
	}
	return domainRunsOnAny(x, mine), du, nil
}

// domainRunsOnAny reports whether a domain's own disks (not its CD-ROMs, not
// their backing chains) name one of paths, by spelling or by the file it is.
func domainRunsOnAny(domXML string, paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	var dom struct {
		Devices struct {
			Disks []struct {
				Device string `xml:"device,attr"`
				Source struct {
					File string `xml:"file,attr"`
					Dev  string `xml:"dev,attr"`
				} `xml:"source"`
			} `xml:"disk"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		return false
	}
	for _, d := range dom.Devices.Disks {
		if d.Device != "" && d.Device != "disk" {
			continue
		}
		for _, src := range []string{d.Source.File, d.Source.Dev} {
			if src == "" {
				continue
			}
			sfi, serr := os.Stat(src)
			for _, p := range paths {
				if p == src {
					return true
				}
				if serr != nil {
					continue
				}
				if pfi, perr := os.Stat(p); perr == nil && os.SameFile(sfi, pfi) {
					return true
				}
			}
		}
	}
	return false
}
