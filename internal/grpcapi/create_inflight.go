package grpcapi

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/storage"
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
// removes none of those. Every source form a create makes is read — a file,
// a block device, an rbd image (by pool/image, on any cluster) — from the
// domain's persistent and live definitions and from DomainDiskSources, and a
// file is matched by its spelling and by the file it is (a symlinked pool
// directory names one file two ways), looked at within
// sharedDiskStatTimeout. A domain whose uuid cannot be read is foreign.
// Nothing matches only when libvirt says no domain of the name exists (its
// typed VIR_ERR_NO_DOMAIN, never an error's text); when
// what the domain names cannot be known (its definition or its sources
// unreadable, a source of another form, a file that cannot be looked at),
// every path matches and the failed create leaves its disks.
func (s *Server) foreignDomainDiskPaths(name, self string) func(string) bool {
	none := func(string) bool { return false }
	all := func(string) bool { return true }
	if s.virt == nil {
		return none
	}
	inactive, ierr := s.virt.DumpXMLInactive(name)
	live, lerr := s.virt.DumpXML(name)
	switch {
	case ierr != nil && lerr != nil:
		if lv.IsNoDomain(ierr) && lv.IsNoDomain(lerr) {
			return none
		}
		return all
	case lerr != nil:
		// A running domain's live definition can name a disk its
		// persistent one does not (a hot-plugged one).
		return all
	case ierr != nil:
		inactive = live
	}
	if u := domainUUIDFromXML(inactive); u != "" && u == self {
		return none
	}
	byName := map[string]bool{}
	rbd := map[string]bool{}
	for _, x := range []string{inactive, live} {
		if x == "" {
			continue
		}
		files, specs, ok := domainDiskSourcesFromXML(x)
		if !ok {
			return all
		}
		for _, f := range files {
			byName[f] = true
		}
		for _, sp := range specs {
			rbd[sp] = true
		}
	}
	src, err := s.virt.DomainDiskSources(name)
	if err != nil {
		return all
	}
	for _, p := range src {
		byName[p] = true
	}
	var files []os.FileInfo
	for p := range byName {
		fi, serr := statInfoWithin(p, sharedDiskStatTimeout)
		switch {
		case serr == nil:
			files = append(files, fi)
		case errors.Is(serr, fs.ErrNotExist), errors.Is(serr, syscall.ENOTDIR), errors.Is(serr, syscall.ELOOP):
		default:
			return all
		}
	}
	return func(p string) bool {
		if byName[p] {
			return true
		}
		if l, ok := storage.ParseCephLocator(p); ok {
			return rbd[l.Spec]
		}
		fi, err := statInfoWithin(p, sharedDiskStatTimeout)
		if err != nil {
			// Nothing there is no file of the domain's; a path that cannot
			// be looked at may be.
			return !(errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP))
		}
		for _, f := range files {
			if os.SameFile(fi, f) {
				return true
			}
		}
		return false
	}
}

// domainDiskSourcesFromXML reads every <disk> source of a domain definition:
// files and block devices by path, rbd images by pool/image. ok is false
// when the definition cannot be parsed, or a disk has a source of another
// form (a libvirt volume, another network protocol), which could name
// anything.
func domainDiskSourcesFromXML(domXML string) (paths, rbdSpecs []string, ok bool) {
	var dom struct {
		Devices struct {
			Disks []struct {
				Type   string `xml:"type,attr"`
				Source *struct {
					File     string `xml:"file,attr"`
					Dev      string `xml:"dev,attr"`
					Protocol string `xml:"protocol,attr"`
					Name     string `xml:"name,attr"`
				} `xml:"source"`
			} `xml:"disk"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		return nil, nil, false
	}
	for _, d := range dom.Devices.Disks {
		src := d.Source
		if src == nil {
			continue // an empty drive
		}
		switch {
		case src.Protocol == "rbd" && src.Name != "":
			rbdSpecs = append(rbdSpecs, src.Name)
		case src.File != "":
			paths = append(paths, src.File)
		case src.Dev != "":
			paths = append(paths, src.Dev)
		case src.Protocol == "" && (d.Type == "file" || d.Type == "block" || d.Type == ""):
			// A file or block drive with no medium.
		default:
			return nil, nil, false
		}
	}
	return paths, rbdSpecs, true
}

// domainIsVMsOwn reports whether the domain of name on this host is the
// runtime of the VM whose spec uuid is specUUID. Its uuid is the VM's (every
// definer carries it), or, when diskOwner names the VM, the domain runs on a
// disk the VM's row records on this host (a domain an older promotion or
// restore defined under a uuid libvirt chose). The owner-epoch stamp is no
// identity: healers write it by name onto whatever domain of the name runs on
// the owner, and epochs repeat across VMs and incarnations. du is the
// domain's uuid; why says, when the disk rule matched nothing, what it
// compared; err is set when what the domain is cannot be read, and then
// nothing about it is known.
func (s *Server) domainIsVMsOwn(ctx context.Context, name, specUUID, diskOwner string) (own bool, du, why string, err error) {
	x, xerr := s.virt.DumpXMLInactive(name)
	if xerr != nil {
		var lerr error
		if x, lerr = s.virt.DumpXML(name); lerr != nil {
			return false, "", "", fmt.Errorf("%v; live: %v", xerr, lerr)
		}
	}
	du = domainUUIDFromXML(x)
	if du == "" {
		return false, "", "", fmt.Errorf("its definition names no uuid")
	}
	if specUUID != "" && du == specUUID {
		return true, du, "", nil
	}
	if diskOwner == "" {
		return false, du, "", nil
	}
	recorded, rerr := corrosion.GetVMDisks(ctx, s.db, diskOwner)
	if rerr != nil {
		return false, du, "", fmt.Errorf("the VM's disks cannot be read: %v", rerr)
	}
	var mine []string
	for _, d := range recorded {
		if d.HostName == s.hostName && d.Path != "" && (d.DeviceKind == "" || d.DeviceKind == "disk") {
			mine = append(mine, d.Path)
		}
	}
	if len(mine) == 0 {
		return false, du, fmt.Sprintf("the VM's row records no disk on %s", s.hostName), nil
	}
	on, rbdWhy, derr := domainDiskMatch(x, mine)
	if derr != nil {
		return false, du, "", derr
	}
	if !on {
		why = fmt.Sprintf("none of its disks is one of the %d the VM's row records on %s", len(mine), s.hostName)
		if rbdWhy != "" {
			why = rbdWhy
		}
	}
	return on, du, why, nil
}

// domainRunsOnAny reports whether a domain's own disks (not its CD-ROMs, not
// their backing chains) name one of paths: a file or block device by
// spelling, then by the file it is; a Ceph RBD network disk by its
// pool/image against an "rbd:" path on the same Ceph cluster
// (rbdSameCluster) — the same pool/image on another cluster is another
// image. A file is looked at within
// sharedDiskStatTimeout; a path at which no file can be (missing, a
// component that is a file, a symlink loop) matches nothing, and one that
// cannot be looked at (a hard mount whose server is gone) is an error:
// whether the domain runs on it is not known.
func domainRunsOnAny(domXML string, paths []string) (bool, error) {
	on, _, err := domainDiskMatch(domXML, paths)
	return on, err
}

// domainDiskMatch is domainRunsOnAny, and, when it matched nothing, why an
// rbd disk of the domain that is the pool/image of one of paths is not that
// disk ("" when none is): its Ceph cluster is another, or cannot be told.
func domainDiskMatch(domXML string, paths []string) (bool, string, error) {
	if len(paths) == 0 {
		return false, "", nil
	}
	var dom struct {
		Devices struct {
			Disks []struct {
				Device string `xml:"device,attr"`
				Source struct {
					File     string `xml:"file,attr"`
					Dev      string `xml:"dev,attr"`
					Protocol string `xml:"protocol,attr"`
					Name     string `xml:"name,attr"`
					Hosts    []struct {
						Name string `xml:"name,attr"`
						Port string `xml:"port,attr"`
					} `xml:"host"`
					Config struct {
						File string `xml:"file,attr"`
					} `xml:"config"`
				} `xml:"source"`
			} `xml:"disk"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		return false, "", nil
	}
	var srcs []string
	rbdWhy := ""
	for _, d := range dom.Devices.Disks {
		if d.Device != "" && d.Device != "disk" {
			continue
		}
		if d.Source.Protocol == "rbd" {
			if d.Source.Name == "" {
				continue
			}
			var mons []cephMon
			for _, h := range d.Source.Hosts {
				mons = append(mons, cephMon{host: strings.Trim(h.Name, "[]"), port: h.Port})
			}
			for _, p := range paths {
				l, ok := storage.ParseCephLocator(p)
				if !ok || l.Spec != d.Source.Name {
					continue
				}
				if rbdSameCluster(mons, d.Source.Config.File, l) {
					return true, "", nil
				}
				if rbdWhy == "" {
					rbdWhy = rbdClusterMismatch(d.Source.Name, mons, d.Source.Config.File)
				}
			}
			continue
		}
		for _, src := range []string{d.Source.File, d.Source.Dev} {
			if src == "" {
				continue
			}
			for _, p := range paths {
				if p == src {
					return true, "", nil
				}
			}
			srcs = append(srcs, src)
		}
	}
	// No spelling matched: compare the files themselves.
	var local []string
	for _, p := range paths {
		if !strings.HasPrefix(p, "rbd:") {
			local = append(local, p)
		}
	}
	if len(srcs) == 0 || len(local) == 0 {
		return false, rbdWhy, nil
	}
	look := func(p string) (os.FileInfo, bool, error) {
		fi, err := statInfoWithin(p, sharedDiskStatTimeout)
		switch {
		case err == nil:
			return fi, true, nil
		case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.ELOOP):
			// Nothing is at the path that could be a file: no match.
			return nil, false, nil
		default:
			return nil, false, fmt.Errorf("disk %s cannot be looked at: %v", p, err)
		}
	}
	var pfis []os.FileInfo
	for _, p := range local {
		fi, ok, err := look(p)
		if err != nil {
			return false, "", err
		}
		if ok {
			pfis = append(pfis, fi)
		}
	}
	if len(pfis) == 0 {
		return false, rbdWhy, nil
	}
	for _, src := range srcs {
		sfi, ok, err := look(src)
		if err != nil {
			return false, "", err
		}
		if !ok {
			continue
		}
		for _, pfi := range pfis {
			if os.SameFile(sfi, pfi) {
				return true, "", nil
			}
		}
	}
	return false, rbdWhy, nil
}

// cephMon is one Ceph monitor address: host, and port when one is named.
type cephMon struct{ host, port string }

// parseCephMon reads one storage.ParseMonHost entry: "host", "host:port" or
// "[v6]:port".
func parseCephMon(m string) cephMon {
	if strings.HasPrefix(m, "[") {
		if end := strings.IndexByte(m, ']'); end > 0 {
			return cephMon{host: m[1:end], port: strings.TrimPrefix(m[end+1:], ":")}
		}
	}
	if h, p, found := strings.Cut(m, ":"); found && !strings.Contains(p, ":") {
		return cephMon{host: h, port: p}
	}
	return cephMon{host: m}
}

// sameMon reports whether a and b are one monitor: one host, on one port or
// on its two default protocol ports (v2 3300, v1 6789); a monitor named with
// no port is on a default one, never on any other.
func sameMon(a, b cephMon) bool {
	if a.host == "" || a.host != b.host {
		return false
	}
	if a.port == b.port {
		return true
	}
	isDefault := func(p string) bool { return p == "" || p == "3300" || p == "6789" }
	return isDefault(a.port) && isDefault(b.port)
}

// rbdClusterMismatch says why an rbd disk of a domain that is a recorded
// pool/image is not the recorded disk (rbdSameCluster), for an operator.
func rbdClusterMismatch(spec string, dom []cephMon, domConf string) string {
	on := "the default ceph.conf's monitors"
	if len(dom) > 0 {
		names := make([]string, len(dom))
		for i, m := range dom {
			names[i] = m.host
			if m.port != "" {
				names[i] += ":" + m.port
			}
		}
		on = "monitors " + strings.Join(names, ", ")
	} else if domConf != "" {
		on = "the cluster of its own " + domConf
	}
	return fmt.Sprintf("its rbd disk %s is the VM's pool/image, but on %s, which share no monitor with the VM's Ceph cluster "+
		"(another cluster, or one that cannot be told); if the cluster's monitors were all replaced, the domain still names the "+
		"retired ones: undefine it, or give it the current ones, and rebuild again", spec, on)
}

// rbdSameCluster reports whether a domain's rbd source, on monitors dom,
// and the "rbd:" locator l name the same Ceph cluster, positively: they
// share a monitor. l's monitors are its litevirt pool's on this host, its
// mon_host, and its conf's; a side that names none uses the default
// ceph.conf, whose monitors stand in for it, and two sides that both name
// none read the same file. A cluster that cannot be known (a conf or the
// default ceph.conf unreadable, or naming no monitor, or a domain that names
// a <config file> of its own and no monitor) is not the same.
func rbdSameCluster(dom []cephMon, domConf string, l storage.CephLocator) bool {
	if len(dom) == 0 && domConf != "" {
		// The domain reads its cluster from a conf of its own, which says
		// nothing this host can compare.
		return false
	}
	var want []cephMon
	add := func(ms []string) {
		for _, m := range ms {
			want = append(want, parseCephMon(m))
		}
	}
	explicit := false
	if ms, ok := lv.CephPoolMonitors(l.Opts["lvpool"]); ok {
		explicit = true
		add(ms)
	}
	if v, ok := l.Opts["mon_host"]; ok {
		explicit = true
		add(storage.ParseMonHost(v))
	}
	if conf := l.Opts["conf"]; conf != "" && !storage.IsDefaultCephConf(conf) {
		explicit = true
		if ms, err := storage.CephMonHosts(conf); err == nil {
			add(ms)
		}
	}
	if !explicit && len(dom) == 0 {
		return true
	}
	if !explicit || len(dom) == 0 {
		def, err := storage.CephMonHosts(storage.DefaultCephConf())
		if err != nil {
			return false
		}
		var ms []cephMon
		for _, m := range def {
			ms = append(ms, parseCephMon(m))
		}
		if !explicit {
			want = ms
		} else {
			dom = ms
		}
	}
	for _, a := range dom {
		for _, b := range want {
			if sameMon(a, b) {
				return true
			}
		}
	}
	return false
}

// domainNIC is one <interface> of a domain definition: its MAC (lower
// case, "" when it names none) and the bridge it is on ("" when it is on
// none).
type domainNIC struct {
	MAC, Bridge string
}

// domainNICsFromXML is each <interface> of a domain definition, in order.
func domainNICsFromXML(domXML string) ([]domainNIC, error) {
	var dom struct {
		Devices struct {
			Interfaces []struct {
				Type string `xml:"type,attr"`
				MAC  struct {
					Address string `xml:"address,attr"`
				} `xml:"mac"`
				Source struct {
					Bridge string `xml:"bridge,attr"`
				} `xml:"source"`
			} `xml:"interface"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		return nil, err
	}
	nics := make([]domainNIC, 0, len(dom.Devices.Interfaces))
	for _, n := range dom.Devices.Interfaces {
		nic := domainNIC{MAC: strings.ToLower(n.MAC.Address)}
		if n.Type == "bridge" {
			nic.Bridge = n.Source.Bridge
		}
		nics = append(nics, nic)
	}
	return nics, nil
}
