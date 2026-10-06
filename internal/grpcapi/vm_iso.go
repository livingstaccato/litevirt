package grpcapi

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/storage"
)

// An installer ISO (VMSpec.iso) is a file on the target host that qemu opens
// and the guest reads as a CD-ROM. Naming one is therefore reading that file:
// an ISO of <pki_dir>/host.key gives the guest the host's peer identity, which
// is admin on every node, and <data_dir>/state.db or /etc/shadow are as bad.
//
// There are two ways to name one:
//
//   - A library reference "<pool>/<file>.iso" (iso_library.go): the global
//     library "isos", open to every project, or a pool the VM's project may
//     use and the caller may read. The host resolves it to a plain file
//     directly in the pool's directory, at create and at every start.
//   - An absolute host path, which needs storage.hostpath at the cluster root
//     (only Admin holds it). An absolute path that names a .iso directly in
//     a pool's directory — what earlier specs stored — is taken as that
//     pool's reference, for a non-admin too.
//
// Either way the file must be a plain file (no symlink anywhere along the
// path the host hands qemu, a single hard link), and storage.CheckReadFile
// refuses the PKI directory, the daemon's internal state and the secret system
// directories, to everyone.

// verbISOHostPath is the RBAC verb an arbitrary host path takes. It is the
// same verb the storage-pool host-path gate uses ("storage.hostpath"); kept as
// its own name here so this file does not depend on that change's file.
const verbISOHostPath = "storage.hostpath"

// isoPoolFor returns the file-based pools on host whose directory is iso's
// directory. Several pool rows can share one directory (target-less local
// pools all live in <data_dir>/disks). On this host the directory is the one
// the file is opened through — symlinks resolved — and compared by path and by
// identity (poolsMappingDir), so neither a link nor a bind mount aliases
// another pool's directory past it.
func (s *Server) isoPoolFor(ctx context.Context, host, iso string) ([]corrosion.StoragePoolRecord, error) {
	dir := filepath.Dir(iso)
	if host == s.hostName {
		got, err := probeDir(dir)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "which pools share %s cannot be told: %v; refusing until it answers", dir, err)
		}
		if got.path != "" {
			dir = got.path
		}
	}
	return s.poolsMappingDir(ctx, host, dir)
}

// authorizeVMISO is the create-time gate for spec.Iso. It runs on the entry
// node, where the caller is the user, and again on the owner, where a
// forwarded call is a peer; both judge the replicated pool rows of host. It
// records in spec.IsoScope which kind of pool (or an Admin's host path) the
// ISO is, which every later resolution holds the VM to. On the owner, a
// peer-forwarded spec arrives with the entry's classification, which the owner
// keeps rather than re-deriving it from the peer's own (admin) authority.
//
// A non-admin's absolute path into a pool directory is judged as that pool's
// reference and stored as written, so a compose file that names it does not
// differ from what was stored.
func (s *Server) authorizeVMISO(ctx context.Context, project, host string, spec *pb.VMSpec) error {
	iso := spec.GetIso()
	trusted := spec.GetIsoScope()
	spec.IsoScope = ""
	if iso == "" {
		return nil
	}
	poolScope := func(pool, file string) error {
		kind, err := s.authorizeISORef(ctx, project, host, pool, file)
		if err != nil {
			return err
		}
		if trusted != "" && trusted != kind {
			return status.Errorf(codes.FailedPrecondition,
				"iso %s/%s is a %s pool on %s, but the entry node saw a %s one; retry once the pool rows agree", pool, file, kind, host, trusted)
		}
		spec.IsoScope = kind
		return nil
	}
	if pool, file, ok := parseISORef(iso); ok {
		return poolScope(pool, file)
	}
	if !filepath.IsAbs(iso) {
		return status.Errorf(codes.InvalidArgument,
			"iso %q must be a library reference <pool>/<file>.iso (`lv iso ls` lists them) or, for an Admin, an absolute host path", iso)
	}
	if filepath.Clean(iso) != iso {
		return status.Errorf(codes.InvalidArgument,
			"iso %q must be an absolute, clean path on the target host", iso)
	}
	if err := storage.CheckReadPathLexical(iso, s.dataDir, s.pkiDir); err != nil {
		return status.Errorf(codes.InvalidArgument, "iso: %v", err)
	}
	perr := s.RequirePerm(ctx, "/", verbISOHostPath, "admin")
	if perr == nil && (trusted == "" || trusted == isoScopeHostPath) {
		spec.IsoScope = isoScopeHostPath
		return nil
	}
	if perr != nil && status.Code(perr) != codes.PermissionDenied {
		return perr
	}
	ref, ok, rerr := s.isoRefForPath(ctx, host, iso)
	if rerr != nil {
		return rerr
	}
	if ok {
		pool, file, _ := parseISORef(ref)
		return poolScope(pool, file)
	}
	return status.Errorf(codes.PermissionDenied,
		"iso %q is a host path on %s; attaching an arbitrary host file lets the guest read it, "+
			"so it needs %s at the cluster root (the Admin role on /). Name an ISO from a library instead, "+
			"as <pool>/<file>.iso (`lv iso ls` lists them)",
		iso, host, verbISOHostPath)
}

// resolveSpecISO is this host's resolution of a VM's ISO through its pool: a
// library reference, or an absolute path recorded at create as a pool's file
// (held to the library record too, like a reference). viaPool is false for an
// Admin's host path and for a VM created before iso_scope was recorded whose
// ISO is an absolute path; the caller resolves that with resolveHostISO.
func (s *Server) resolveSpecISO(ctx context.Context, vmName, project string, spec *pb.VMSpec) (path string, viaPool bool, err error) {
	iso, scope := spec.GetIso(), spec.GetIsoScope()
	if iso == "" {
		return "", false, nil
	}
	key := isoIdentityKey(vmName, spec)
	if pool, file, ok := parseISORef(iso); ok {
		path, err := s.resolveISOForVM(ctx, project, scope, pool, file, true, key)
		return path, true, err
	}
	switch scope {
	case isoScopeGlobal, isoScopePool, isoScopeProject:
		ref, ok, rerr := s.isoRefForPath(ctx, s.hostName, iso)
		if rerr != nil {
			return "", true, rerr
		}
		if !ok {
			return "", true, isoAbsent(status.Errorf(codes.FailedPrecondition,
				"iso %q names a file in a %s pool, and no pool on this host (%s) has that directory", iso, scope, s.hostName))
		}
		pool, file, _ := parseISORef(ref)
		path, err := s.resolveISOForVM(ctx, project, scope, pool, file, true, key)
		return path, true, err
	}
	return "", false, nil
}

// resolveVMISO is the owning host's resolution of spec.Iso to the file qemu
// is handed, against its own filesystem: through its pool (resolveSpecISO),
// or an Admin's absolute path resolved once (resolveHostISO).
func (s *Server) resolveVMISO(ctx context.Context, project string, spec *pb.VMSpec) (string, error) {
	path, viaPool, err := s.resolveSpecISO(ctx, spec.GetName(), project, spec)
	if err != nil || viaPool || spec.GetIso() == "" {
		return path, err
	}
	return s.resolveHostISO(spec.GetIso())
}

// resolveHostISO resolves a host path ISO — an Admin's, or a VM's from before
// iso_scope was recorded — the way it worked before libraries: the path may
// be a link or pass through one (virtio-win ships virtio-win.iso as a link to
// a versioned file; /var/lib/libvirt/images is often a link to a data disk).
// It is resolved ONCE, here, and the file it names is judged in full: not in
// a refused place (as named and as resolved), a regular file, no link left
// in the resolved path, and opened without following one. The caller hands
// qemu the resolved path, so qemu never follows a link a later swap could
// redirect. A hard link is accepted where the kernel stops a user linking a
// file they do not own (fs.protected_hardlinks=1).
func (s *Server) resolveHostISO(p string) (string, error) {
	if err := storage.CheckReadFile(p, s.dataDir, s.pkiDir); err != nil {
		return "", status.Errorf(codes.InvalidArgument, "iso: %v", err)
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "iso %q: %v", p, err)
	}
	if err := s.checkISOFile(r, true); err != nil {
		return "", err
	}
	return r, nil
}

// protectedHardlinks reports fs.protected_hardlinks=1. A variable so a test
// can say either.
var protectedHardlinks = func() bool {
	b, err := os.ReadFile("/proc/sys/fs/protected_hardlinks")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// checkVMISOFile is the judgement of a pool or library file qemu is handed,
// at create and again at every start (checkISOFile, no hard links).
func (s *Server) checkVMISOFile(iso string) error { return s.checkISOFile(iso, false) }

// checkISOFile is the host's judgement of the file qemu is handed, because
// qemu reopens the file each time and whoever controls the directory can
// replace it in between:
//
//   - no component of the path is a symlink (the name is the file);
//   - it is a regular file with a single link, so it is not a second name
//     for some other file — for a host path (hostPath), a second link is
//     accepted under fs.protected_hardlinks=1;
//   - it is not in a refused directory (storage.CheckReadFile).
func (s *Server) checkISOFile(iso string, hostPath bool) error {
	if iso == "" {
		return nil
	}
	if err := storage.CheckReadFile(iso, s.dataDir, s.pkiDir); err != nil {
		return status.Errorf(codes.InvalidArgument, "iso: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(iso); err != nil || resolved != iso {
		return status.Errorf(codes.InvalidArgument,
			"iso %q is reached through a symlink; an ISO must be the file itself", iso)
	}
	fi, err := os.Lstat(iso)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "iso %q: %v", iso, err)
	}
	if !fi.Mode().IsRegular() {
		return status.Errorf(codes.InvalidArgument, "iso %q is not a regular file", iso)
	}
	links := func(fi os.FileInfo) error {
		n, ok := linkCount(fi)
		if !ok || n == 1 {
			return nil
		}
		if !hostPath {
			return status.Errorf(codes.InvalidArgument,
				"iso %q has %d hard links, so it is also another file; put a copy in a library instead (`lv iso pull`)", iso, n)
		}
		if !protectedHardlinks() {
			return status.Errorf(codes.InvalidArgument,
				"iso %q has %d hard links, and this host has fs.protected_hardlinks=0, so any local user could have made it a second name for a file they cannot read; copy the ISO, or set fs.protected_hardlinks=1", iso, n)
		}
		return nil
	}
	if err := links(fi); err != nil {
		return err
	}
	// The checks above name the file; the last check before the VM starts
	// opens it without following a link and confirms the open file is that
	// same file at that same path. (qemu opens the path again itself.)
	if isoBeforeOpen != nil {
		isoBeforeOpen(iso)
	}
	f, ofi, openedAs, err := openNoFollow(iso)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "iso %q could not be opened as the file itself (%v); an ISO must not be a link", iso, err)
	}
	f.Close()
	if !os.SameFile(fi, ofi) || (openedAs != "" && openedAs != iso) {
		return status.Errorf(codes.InvalidArgument, "iso %q changed while it was being checked; an ISO must be the file itself", iso)
	}
	return links(ofi)
}

// isoBeforeOpen is a test seam: it runs between checkVMISOFile's checks of the
// name and its no-follow open, where a swap would land.
var isoBeforeOpen func(path string)

// domainInstallerISOs returns the file sources of the CD-ROMs in a domain
// definition, other than the VM's own cloud-init seed (litevirt writes that
// one into its data directory itself).
func (s *Server) domainInstallerISOs(vmName, domXML string) []string {
	out, _ := s.domainInstallerISOsErr(vmName, domXML)
	return out
}

// domainInstallerISOsErr is domainInstallerISOs, reporting a definition that
// does not parse.
func (s *Server) domainInstallerISOsErr(vmName, domXML string) ([]string, error) {
	var dom struct {
		Disks []struct {
			Device string `xml:"device,attr"`
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
		} `xml:"devices>disk"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		return nil, err
	}
	seed := filepath.Join(s.dataDir, "cloudinit", vmName+".iso")
	var out []string
	for _, d := range dom.Disks {
		if d.Device != "cdrom" || d.Source.File == "" || d.Source.File == seed {
			continue
		}
		out = append(out, d.Source.File)
	}
	return out, nil
}

// vmSpecFor parses a VM row's spec; nil when it has none or it does not parse.
func vmSpecFor(vm *corrosion.VMRecord) *pb.VMSpec {
	if vm == nil || vm.Spec == "" {
		return nil
	}
	var spec pb.VMSpec
	if json.Unmarshal([]byte(vm.Spec), &spec) != nil {
		return nil
	}
	return &spec
}

// verifyVMISOForStart judges, on this host, every installer CD-ROM the VM's
// defined domain will hand qemu at its next start: a start, a snapshot revert
// that can start it, a replace cutover. A domain with no installer CD-ROM
// (failover, the reconciler, UpdateVM regenerate without it) starts even
// after the ISO is gone. An ISO in a pool is resolved again through this
// host's pool, held to the kind recorded at create and to the VM's project;
// an Admin's host path (or a VM's from before iso_scope) is resolved again
// from the path the VM was given (resolveHostISO). Either way the domain is
// pointed at the file resolved here when it names another path. A refusal
// keeps the VM down, loudly.
func (s *Server) verifyVMISOForStart(vm *corrosion.VMRecord) error {
	if vm == nil || s.virt == nil {
		return nil
	}
	domXML, err := s.virt.DumpXMLInactive(vm.Name)
	if err != nil {
		return nil
	}
	cdroms := s.domainInstallerISOs(vm.Name, domXML)
	if len(cdroms) == 0 {
		return nil
	}
	ctx := context.Background()
	repoint := func(to func(c string) string, iso string) error {
		updated := domXML
		for _, c := range cdroms {
			if t := to(c); t != c {
				updated = repointCDROM(updated, c, t)
			}
		}
		if updated != domXML {
			if err := s.virt.DefineDomain(updated); err != nil {
				return status.Errorf(codes.Internal, "point %s's installer CD-ROM at this host's file: %v", vm.Name, err)
			}
			slog.Info("installer ISO: domain pointed at the file resolved on this host", "vm", vm.Name, "iso", iso)
		}
		return nil
	}
	spec := vmSpecFor(vm)
	if spec != nil {
		path, viaPool, err := s.resolveSpecISO(ctx, vm.Name, vm.Project, spec)
		if err != nil {
			return s.refuseISO(vm.Name, spec.GetIso(), err)
		}
		if viaPool {
			return repoint(func(string) string { return path }, spec.GetIso())
		}
		if filepath.IsAbs(spec.GetIso()) {
			r, err := s.resolveHostISO(spec.GetIso())
			if err != nil {
				return s.refuseISO(vm.Name, spec.GetIso(), err)
			}
			return repoint(func(string) string { return r }, spec.GetIso())
		}
	}
	resolved := map[string]string{}
	for _, c := range cdroms {
		r, err := s.resolveHostISO(c)
		if err != nil {
			return s.refuseISO(vm.Name, c, err)
		}
		resolved[c] = r
	}
	return repoint(func(c string) string { return resolved[c] }, "")
}

// repointCDROM replaces a CD-ROM's file source in a domain definition.
func repointCDROM(domXML, from, to string) string {
	for _, q := range []string{"'", `"`} {
		domXML = strings.ReplaceAll(domXML, "file="+q+from+q, "file="+q+to+q)
	}
	return domXML
}

// verifyIncomingVMISO is the migration target's judgement, before a domain
// carrying the VM's installer ISO lands here. The source lists the CD-ROM
// paths its domain carries (none: nothing to judge). An ISO in a pool is
// resolved through this host's pool, held to the recorded kind and the VM's
// project, and for a runtime migration — where libvirt hands qemu here the
// source's path — that resolution must be the very same path. A host path is
// judged as the file it resolves to here (resolveHostISO).
//
// A stopped VM's move (not runtime) to a host without the pool or the file is
// accepted with a warning — the start there judges the ISO again, and refuses
// until it is present — while one that names a pool of another kind or
// another project here is refused, file or no file.
//
// A source on an older build lists nothing (installer_iso_listed=false). On
// main the only caller of EnsureDisks is the storage-copy path of a RUNNING
// VM's libvirt runtime migration (a stopped or cold move from an older source
// never calls the target, and its start here judges the ISO), so an unlisted
// call is a runtime move: an absent pool or file is refused, because qemu here
// would open the source's path.
func (s *Server) verifyIncomingVMISO(vm *corrosion.VMRecord, req *pb.EnsureDisksRequest) (string, error) {
	spec := vmSpecFor(vm)
	if spec == nil {
		spec = &pb.VMSpec{}
	}
	ctx := context.Background()
	runtime := req.GetInstallerIsoRuntime()
	absentWarning := func(what string) string {
		w := fmt.Sprintf("VM %q is moving to %s, which cannot attach its installer ISO yet (%s); it will not start there until the ISO is present (upload or pull it there, or wait for the library to sync)",
			vm.Name, s.hostName, what)
		slog.Warn("installer ISO: a stopped VM moves to a host without its ISO", "vm", vm.Name, "host", s.hostName, "iso", spec.GetIso(), "reason", what)
		return w
	}
	if req.GetInstallerIsoListed() {
		paths := req.GetInstallerIsoPaths()
		if len(paths) == 0 {
			return "", nil
		}
		path, viaPool, err := s.resolveSpecISO(ctx, vm.Name, vm.Project, spec)
		if err != nil && !runtime && isISOAbsent(err) {
			return absentWarning(status.Convert(err).Message()), nil
		}
		if err != nil {
			return "", s.refuseISO(vm.Name, spec.GetIso(), err)
		}
		if viaPool {
			if runtime {
				for _, p := range paths {
					if p != path {
						return "", s.refuseISO(vm.Name, spec.GetIso(), status.Errorf(codes.FailedPrecondition,
							"the running VM's domain opens it at %s, and on this host it is %s; a running VM's CD-ROM path cannot change in a migration, so stop the VM and migrate it stopped, or give the library the same directory on both hosts",
							p, path))
					}
				}
			}
			return "", nil
		}
		var warnings []string
		for _, p := range paths {
			if _, serr := os.Stat(p); os.IsNotExist(serr) && !runtime {
				warnings = append(warnings, absentWarning("no file "+p))
				continue
			}
			if _, err := s.resolveHostISO(p); err != nil {
				return "", s.refuseISO(vm.Name, p, err)
			}
		}
		return strings.Join(warnings, "; "), nil
	}
	// Unlisted: an older source's runtime move (see above). Strict — an absent
	// pool or file is refused, never waved through with a warning.
	if spec.GetIso() == "" {
		return "", nil
	}
	_, viaPool, err := s.resolveSpecISO(ctx, vm.Name, vm.Project, spec)
	if err != nil {
		return "", s.refuseISO(vm.Name, spec.GetIso(), err)
	}
	if viaPool {
		return "", nil
	}
	if _, err := os.Lstat(spec.Iso); os.IsNotExist(err) {
		if rerr := storage.CheckRefusedReadPath(spec.Iso, s.dataDir, s.pkiDir); rerr != nil {
			return "", s.refuseISO(vm.Name, spec.Iso, status.Errorf(codes.InvalidArgument, "iso: %v", rerr))
		}
		return "", nil
	}
	if _, err := s.resolveHostISO(spec.Iso); err != nil {
		return "", s.refuseISO(vm.Name, spec.Iso, err)
	}
	return "", nil
}

func (s *Server) refuseISO(vmName, iso string, err error) error {
	reason := status.Convert(err).Message()
	slog.Error("refusing to hand a VM its installer ISO: the file is not the plain file the VM was given; "+
		"the guest would read whatever it now names",
		"vm", vmName, "host", s.hostName, "iso", iso, "reason", reason)
	return status.Errorf(codes.FailedPrecondition,
		"VM %q has installer ISO %q, which this host will not attach (%s); put the ISO in a library (`lv iso pull`) or recreate the VM without it",
		vmName, iso, reason)
}

// domainInstallerISOPaths returns the installer CD-ROM paths the VM's domain
// on THIS host (the migration source) carries, which the target would open.
// For a runtime move it reads the RUNNING domain — libvirt migrates the live
// definition — and a read or parse failure is an error, never "no CD-ROM"
// (a domain that does not exist carries nothing to migrate).
// For a stopped move it reads the persistent definition; a failure there
// lists nothing, and the start on the target judges the ISO.
func (s *Server) domainInstallerISOPaths(name string, live bool) ([]string, error) {
	if s.virt == nil {
		return nil, nil
	}
	if !live {
		domXML, err := s.virt.DumpXMLInactive(name)
		if err != nil {
			return nil, nil
		}
		return s.domainInstallerISOs(name, domXML), nil
	}
	domXML, err := s.virt.DumpXML(name)
	if err != nil && lv.IsNotFound(err) {
		return nil, nil // no domain here: nothing is migrated, so nothing is opened there
	}
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"cannot read the running domain of VM %q to list its installer CD-ROMs: %v", name, err)
	}
	paths, err := s.domainInstallerISOsErr(name, domXML)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"cannot parse the running domain of VM %q to list its installer CD-ROMs: %v", name, err)
	}
	return paths, nil
}

func isISOName(name string) bool {
	return !strings.HasPrefix(name, ".") && strings.EqualFold(filepath.Ext(name), ".iso")
}
