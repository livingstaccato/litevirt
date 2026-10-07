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
		got, err := probeDirCtx(ctx, dir)
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
	return s.resolveSpecISOWith(ctx, vmName, project, spec, "")
}

// resolveSpecISOWith is resolveSpecISO on a migration target, which holds the
// sha256 of the file the source judged (isoFileOwnershipAllows).
func (s *Server) resolveSpecISOWith(ctx context.Context, vmName, project string, spec *pb.VMSpec, wantSHA string) (path string, viaPool bool, err error) {
	iso, scope := spec.GetIso(), spec.GetIsoScope()
	if iso == "" {
		return "", false, nil
	}
	key := isoIdentityKey(vmName, spec)
	if pool, file, ok := parseISORef(iso); ok {
		path, err := s.resolveISOForVM(ctx, project, scope, pool, file, true, key, wantSHA)
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
		path, err := s.resolveISOForVM(ctx, project, scope, pool, file, true, key, wantSHA)
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
	defer f.Close()
	if !os.SameFile(fi, ofi) || (openedAs != "" && openedAs != iso) {
		return status.Errorf(codes.InvalidArgument, "iso %q changed while it was being checked; an ISO must be the file itself", iso)
	}
	// Under /home or /run, only an optical disc image is a file a guest may
	// read: judged on the file just opened, not on a name.
	if storage.UnderUserDataRoot(iso) {
		if err := storage.OpticalImageAt(f); err != nil {
			return status.Errorf(codes.InvalidArgument,
				"iso %q is under a home or runtime directory, where only an ISO image may be attached: %v", iso, err)
		}
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
// after the ISO is gone. The VM's ISO is resolved again here
// (installerISOResolution) and the domain is pointed at the files resolved
// here where it names other paths. A refusal keeps the VM down, loudly.
func (s *Server) verifyVMISOForStart(vm *corrosion.VMRecord) error {
	if vm == nil || s.virt == nil {
		return nil
	}
	domXML, err := s.virt.DumpXMLInactive(vm.Name)
	if err != nil {
		return nil
	}
	updated, err := s.judgedCDROMDefinition(vm, domXML)
	if err != nil {
		return err
	}
	if updated == domXML {
		return nil
	}
	if err := s.virt.DefineDomain(updated); err != nil {
		return status.Errorf(codes.Internal, "point %s's installer CD-ROM at this host's file: %v", vm.Name, err)
	}
	slog.Info("installer ISO: domain pointed at the file resolved on this host", "vm", vm.Name, "iso", vmSpecFor(vm).GetIso())
	return nil
}

// judgedCDROMDefinition judges, on this host, the installer CD-ROMs a domain
// definition of vm carries (installerISOResolution) and returns the definition
// with each pointed at the file judged here (unchanged when they all are). It
// serves a start's defined domain and a memory snapshot's saved image alike.
func (s *Server) judgedCDROMDefinition(vm *corrosion.VMRecord, domXML string) (string, error) {
	cdroms, err := s.domainInstallerISOsErr(vm.Name, domXML)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "cannot read the installer CD-ROMs of VM %q: %v", vm.Name, err)
	}
	if len(cdroms) == 0 {
		return domXML, nil
	}
	resolved, _, err := s.installerISOResolution(context.Background(), vm, vmSpecFor(vm), cdroms, "", false)
	if err != nil {
		return "", err
	}
	remap := map[string]string{}
	for from, to := range resolved {
		if from != to {
			remap[from] = to
		}
	}
	if len(remap) == 0 {
		return domXML, nil
	}
	updated, _, err := lv.RewriteCDROMSources(domXML, remap)
	if err != nil {
		return "", status.Errorf(codes.Internal, "point %s's installer CD-ROM at this host's file: %v", vm.Name, err)
	}
	return updated, nil
}

// installerISOResolution resolves, on this host, the installer CD-ROMs a VM's
// domain carries (cdroms: their paths in the domain, on this host or on a
// migration source) to the files qemu here is to open:
//
//   - the CD-ROM that is the VM's ISO follows the ISO: through its pool
//     (resolveSpecISOWith — the kind recorded at create, the VM's project, the
//     file's ownership), or an Admin's host path (or a VM's from before
//     iso_scope) resolved once from the path the VM was given
//     (resolveHostISO). With one CD-ROM it is that one; with several, the one
//     whose path is the ISO as named or as resolved (for a library, the same
//     file name);
//   - any other CD-ROM is judged as itself (resolveHostISO).
//
// wantSHA is a migration source's hash of the file it judged. With
// tolerateAbsent (a stopped VM's move), an ISO that is not here — its pool,
// its directory or its file — is left out with a warning instead of refused;
// the start here judges it again.
func (s *Server) installerISOResolution(ctx context.Context, vm *corrosion.VMRecord, spec *pb.VMSpec, cdroms []string, wantSHA string, tolerateAbsent bool) (map[string]string, []string, error) {
	out := map[string]string{}
	var warnings []string
	absent := func(what string) {
		warnings = append(warnings, fmt.Sprintf("VM %q is moving to %s, which cannot attach its installer ISO yet (%s); it will not start there until the ISO is present (upload or pull it there, or wait for the library to sync)",
			vm.Name, s.hostName, what))
		slog.Warn("installer ISO: a stopped VM moves to a host without its ISO", "vm", vm.Name, "host", s.hostName, "iso", spec.GetIso(), "reason", what)
	}
	const (
		specNone   = ""
		specPool   = "pool"
		specHost   = "host"
		specAbsent = "absent"
	)
	specKind, specPath := specNone, ""
	if spec != nil && spec.GetIso() != "" {
		path, viaPool, err := s.resolveSpecISOWith(ctx, vm.Name, vm.Project, spec, wantSHA)
		kind := specPool
		if err == nil && !viaPool {
			kind = specHost
			if filepath.IsAbs(spec.GetIso()) {
				path, err = s.resolveHostISO(spec.GetIso())
				if err != nil && hostFileAbsent(spec.GetIso()) &&
					storage.CheckRefusedReadPath(spec.GetIso(), s.dataDir, s.pkiDir) == nil {
					err = isoAbsent(err)
				}
			} else {
				kind, path = specNone, "" // not a path or a reference: each CD-ROM as itself
			}
		}
		switch {
		case err != nil && tolerateAbsent && isISOAbsent(err):
			absent(status.Convert(err).Message())
			specKind = specAbsent
		case err != nil:
			return nil, nil, s.refuseISO(vm.Name, spec.GetIso(), err)
		default:
			specKind, specPath = kind, path
		}
	}
	isSpecs := func(c string) bool {
		switch {
		case specKind == specNone:
			return false
		case len(cdroms) == 1, c == spec.GetIso():
			return true
		case specPath != "" && c == specPath:
			return true
		case specKind == specPool && specPath != "":
			return filepath.Base(c) == filepath.Base(specPath)
		}
		return false
	}
	for _, c := range cdroms {
		if isSpecs(c) {
			if specKind != specAbsent {
				out[c] = specPath
			}
			continue
		}
		if tolerateAbsent && hostFileAbsent(c) && storage.CheckRefusedReadPath(c, s.dataDir, s.pkiDir) == nil {
			absent("no file " + c)
			continue
		}
		r, err := s.resolveHostISO(c)
		if err != nil {
			return nil, nil, s.refuseISO(vm.Name, c, err)
		}
		out[c] = r
	}
	return out, warnings, nil
}

// hostFileAbsent reports that p names nothing on this host (a dangling link
// included).
func hostFileAbsent(p string) bool {
	_, err := os.Stat(p)
	return os.IsNotExist(err)
}

// verifyIncomingVMISO is the migration target's judgement, before a domain
// carrying the VM's installer ISO lands here. The source lists the CD-ROM
// paths its domain carries (none: nothing to judge). This host resolves the
// VM's ISO itself (installerISOResolution), never trusting the source's path:
// an ISO in a pool through this host's pool, held to the recorded kind, the
// VM's project and the file's ownership; a host path as the file it resolves
// to here.
//
// For a runtime migration — where libvirt hands qemu here a definition — it
// returns, for each listed path, the file resolved here, and the source puts
// those in the destination definition (MigrateParams.CDROMSources), so a link
// or a library directory that names another file here than there is followed
// here. Anything that does not resolve and pass here is refused.
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
// call is a runtime move, and the domain arrives unchanged: a pool ISO must
// resolve here, and a host path is judged as itself.
func (s *Server) verifyIncomingVMISO(vm *corrosion.VMRecord, req *pb.EnsureDisksRequest) (string, map[string]string, error) {
	spec := vmSpecFor(vm)
	if spec == nil {
		spec = &pb.VMSpec{}
	}
	ctx := context.Background()
	runtime := req.GetInstallerIsoRuntime()
	if req.GetInstallerIsoListed() {
		paths := req.GetInstallerIsoPaths()
		if len(paths) == 0 {
			return "", nil, nil
		}
		resolved, warnings, err := s.installerISOResolution(ctx, vm, spec, paths, singleSHA(req.GetInstallerIsoSha256()), !runtime)
		if err != nil {
			return "", nil, err
		}
		if !runtime {
			return strings.Join(warnings, "; "), nil, nil
		}
		return "", resolved, nil
	}
	// Unlisted: an older source's runtime move (see above). A pool ISO must
	// resolve here — an absent pool or file is refused, never waved through
	// with a warning. A host path is judged where it exists; one that does not
	// exist here is refused only in a protected place (qemu here fails to open
	// it, as on main).
	if spec.GetIso() == "" {
		return "", nil, nil
	}
	_, viaPool, err := s.resolveSpecISO(ctx, vm.Name, vm.Project, spec)
	if err != nil {
		return "", nil, s.refuseISO(vm.Name, spec.GetIso(), err)
	}
	if viaPool {
		return "", nil, nil
	}
	if _, err := os.Lstat(spec.Iso); os.IsNotExist(err) {
		if rerr := storage.CheckRefusedReadPath(spec.Iso, s.dataDir, s.pkiDir); rerr != nil {
			return "", nil, s.refuseISO(vm.Name, spec.Iso, status.Errorf(codes.InvalidArgument, "iso: %v", rerr))
		}
		return "", nil, nil
	}
	if _, err := s.resolveHostISO(spec.Iso); err != nil {
		return "", nil, s.refuseISO(vm.Name, spec.Iso, err)
	}
	return "", nil, nil
}

// singleSHA is the one hash a source sent (it sends one, for the ISO it
// judged); "" for none or several.
func singleSHA(m map[string]string) string {
	if len(m) != 1 {
		return ""
	}
	for _, v := range m {
		return v
	}
	return ""
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
