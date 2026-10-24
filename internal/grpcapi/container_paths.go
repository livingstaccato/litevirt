package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Host paths a container operation accepts.
//
// A rootfs template is copied whole into the new container, as root, and a
// local OCI layout is unpacked by root; the container's owner then reads what
// was there. These are the VM rules for a host path (vm_iso.go, vmimport.go):
// naming one needs storage.hostpath at the cluster root (Admin), and
// storage.CheckReadDir refuses the protected places for everyone, Admin
// included. A non-admin names an OCI library item (<data_dir>/oci/<name>,
// what `lv ct pull --dest <name>` stages) instead.

// authorizeContainerTemplate is the authority half, run on the node that took
// the request (only there is the caller's identity real; a forwarded call runs
// as the peer). A template name passes; so does a library item.
func (s *Server) authorizeContainerTemplate(ctx context.Context, template string) error {
	p, isPath, err := lxc.TemplatePath(template)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "template: %v", err)
	}
	if !isPath {
		if template != "" && template != "download" {
			// lxc-create reads a template name as a script under its own
			// template directory; a '/' would make it a path to run.
			if strings.ContainsAny(template, "/\x00\n") || template == "." || template == ".." {
				return status.Errorf(codes.InvalidArgument, "template name %q: a path is named as rootfs:<path>", template)
			}
		}
		return nil
	}
	if storage.OCILibraryItem(p, s.dataDir) {
		return nil
	}
	return s.requireHostPathAuthority(ctx, "the container template", storage.HostPaths{ReadPaths: []string{p}})
}

// checkContainerTemplate is the backstop half, run on the host that reads the
// template: the protected places are refused whoever asked.
func (s *Server) checkContainerTemplate(template, name string) error {
	p, isPath, err := lxc.TemplatePath(template)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "template: %v", err)
	}
	if !isPath {
		return nil
	}
	store := s.containerLxcpath()
	if err := storage.CheckTemplateDir(p, s.dataDir, s.pkiDir, store, filepath.Join(store, name)); err != nil {
		return status.Errorf(codes.InvalidArgument, "container template: %v", err)
	}
	return nil
}

// checkPullSource judges a local pull source at path, one rule per kind
// wherever the path is: a directory for oci: and dir: (CheckReadDir), a
// regular file for the archives, and never a protected place or a link
// into a dot-directory (CheckRefusedReadPath). The runtime runs it again on
// the object it opened (lxc.PullOCIOptions.CheckSource).
func (s *Server) checkPullSource(transport, path string) error {
	var err error
	switch transport {
	case "oci", "dir":
		err = storage.CheckReadDir(path, s.dataDir, s.pkiDir)
	default:
		err = storage.CheckReadPathLexical(path, s.dataDir, s.pkiDir)
		if err == nil {
			err = storage.CheckRefusedReadPath(path, s.dataDir, s.pkiDir)
		}
		if err == nil {
			fi, serr := os.Stat(path)
			switch {
			case errors.Is(serr, fs.ErrNotExist):
				err = fmt.Errorf("%q does not exist on this host", path)
			case serr != nil:
				err = fmt.Errorf("%q: %w", path, serr)
			case !fi.Mode().IsRegular():
				err = fmt.Errorf("%q is not a regular file", path)
			case storage.DataDirDisksFile(path, s.dataDir):
				err = fmt.Errorf("%q is VM disk storage (the daemon's disks directory), not an image archive", path)
			default:
				err = s.refuseInDiskPool(path)
			}
		}
	}
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "%s source: %v", transport, err)
	}
	return nil
}

// refuseInDiskPool refuses VM disk storage as an archive source: any VM's
// disk (every host's rows), and anything inside a storage pool on this host,
// at the directory the daemon uses for it (its Target; a target-less local
// pool's own directory and the shared disks directory; a target-less NFS
// pool's mount under <data_dir>/mounts; a btrfs pool's source). A lookup
// that fails refuses too.
func (s *Server) refuseInDiskPool(path string) error {
	if s.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	forms := func(p string) []string {
		out := []string{filepath.Clean(p)}
		if r, err := filepath.EvalSymlinks(p); err == nil && r != out[0] {
			out = append(out, r)
		}
		return out
	}
	disks, err := corrosion.VMDiskPaths(ctx, s.db)
	if err != nil {
		return fmt.Errorf("cannot tell whether %q is a VM's disk: %v", path, err)
	}
	for d, vm := range disks {
		for _, dd := range forms(d) {
			for _, c := range forms(path) {
				if c == dd {
					return fmt.Errorf("%q is VM %s's disk, not an image archive", path, vm)
				}
			}
		}
	}
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return fmt.Errorf("cannot tell whether %q is VM disk storage: %v", path, err)
	}
	for _, pool := range pools {
		for _, dir := range s.poolDiskDirs(pool) {
			if dir == "" || !filepath.IsAbs(dir) {
				continue
			}
			for _, t := range forms(dir) {
				for _, c := range forms(path) {
					if c == t || strings.HasPrefix(c, t+string(filepath.Separator)) {
						return fmt.Errorf("%q is in storage pool %q, VM disk storage, not an image archive", path, pool.Name)
					}
				}
			}
		}
	}
	return nil
}

// poolDiskDirs are the directories a pool on this host keeps disks in.
func (s *Server) poolDiskDirs(p corrosion.StoragePoolRecord) []string {
	if p.Target != "" {
		return []string{p.Target}
	}
	switch strings.ToLower(p.Driver) {
	case "", "local":
		// localPoolDir is "" for a row whose name is not a valid pool name;
		// the caller skips "".
		return []string{localPoolDir(s.dataDir, p.Name), filepath.Join(s.dataDir, "disks")}
	case "nfs":
		return []string{filepath.Join(s.dataDir, "mounts", storage.NFSMountName(p.Source))}
	case "btrfs":
		return []string{p.Source}
	}
	return nil
}

// checkOCIPullPaths is the backstop for a pull's host paths, run on the host
// that unpacks: an absolute dest is a directory root writes an untrusted
// image into (the OCI library itself is the daemon's own), and a local source
// is a path it reads: a directory (oci:, dir:) or a regular file (the
// archives), at the path skopeo will read (lxc.ParseOCISource).
func (s *Server) checkOCIPullPaths(image, dest string) error {
	src, err := lxc.ParseOCISource(image)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if src.Local {
		if err := s.checkPullSource(src.Transport, src.Path); err != nil {
			return err
		}
	}
	if filepath.IsAbs(dest) {
		lib := filepath.Join(s.dataDir, storage.OCILibraryDir)
		inLib := s.dataDir != "" && filepath.Dir(filepath.Clean(dest)) == lib
		if inLib {
			// An item in the library is named like any other item, however
			// the path names it: no "+" (the staging directory's own).
			if err := safename.ValidateName(filepath.Base(dest)); err != nil {
				return status.Errorf(codes.InvalidArgument, "oci dest: %v", err)
			}
		} else {
			if err := storage.CheckWriteRoot(dest, s.dataDir, s.pkiDir); err != nil {
				return status.Errorf(codes.InvalidArgument, "oci dest: %v", err)
			}
		}
	}
	return nil
}

// ociOwnersDir holds one owner record per OCI library item, by item name. A
// directory beside the library, not inside it, so a record is never taken for
// an item.
const ociOwnersDir = "oci-owners"

// ociLibraryName returns the item name when p is (or is the rootfs of) an
// OCI library item under dataDir, else "".
func ociLibraryName(p, dataDir string) string {
	if !storage.OCILibraryItem(p, dataDir) {
		return ""
	}
	rel, err := filepath.Rel(filepath.Join(dataDir, storage.OCILibraryDir), p)
	if err != nil {
		return ""
	}
	name, _, _ := strings.Cut(rel, string(filepath.Separator))
	return name
}

// readOCIOwner returns the project that owns library item name, "" when it
// has no record (an image pulled before records, or by hand): everyone's.
// The record in the item's bundle (lxc.OwnerFile), published with its
// content, is the authority; <data_dir>/oci-owners is read for an item an
// earlier build pulled.
func (s *Server) readOCIOwner(name string) (string, error) {
	if owner, ok, err := lxc.ReadOwner(filepath.Join(s.dataDir, storage.OCILibraryDir, name)); err != nil {
		return "", err
	} else if ok {
		return owner, nil
	}
	b, err := os.ReadFile(filepath.Join(s.dataDir, ociOwnersDir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ociOwnerPending is what <data_dir>/oci-owners/<name> holds while a pull
// with a project is under way (markOCIOwnerPending). It is no project's
// name, so an owner-bound caller is refused the item.
const ociOwnerPending = "!a-claim-of-this-image-was-interrupted"

// markOCIOwnerPending sets the owner record of item to ociOwnerPending for
// a pull with a project, and returns what puts it back as it was.
func (s *Server) markOCIOwnerPending(item string) (restore func()) {
	path := filepath.Join(s.dataDir, ociOwnersDir, item)
	prev, err := os.ReadFile(path)
	had := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return func() {}
	}
	if err := s.writeOCIOwner(item, ociOwnerPending); err != nil {
		slog.Warn("oci pull: could not mark the image's owner record for earlier builds as pending", "image", item, "error", err)
		return func() {}
	}
	return func() {
		if had {
			if err := s.writeOCIOwner(item, strings.TrimSpace(string(prev))); err != nil {
				slog.Warn("oci pull: could not put the image's owner record back", "image", item, "error", err)
			}
			return
		}
		_ = os.Remove(path)
	}
}

// writeOCIOwner records project in <data_dir>/oci-owners/<name>, whole or
// not at all (a temporary file renamed over it).
func (s *Server) writeOCIOwner(name, project string) error {
	dir := filepath.Join(s.dataDir, ociOwnersDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.WriteString(project + "\n")
	if serr := f.Sync(); err == nil {
		err = serr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, name))
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// refuseForeignOCIItem refuses an owner-bound caller (not an admin, or a peer
// forwarding for one) using another project's library item for project. An
// unreadable record cannot prove the item is the caller's. Run on the host
// that holds the library.
func (s *Server) refuseForeignOCIItem(ctx context.Context, name, project, verb string) error {
	if name == "" || s.dataDir == "" || !s.ownerStrict(ctx) {
		return nil
	}
	owner, err := s.readOCIOwner(name)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "OCI image %q: its owner record is unreadable: %v", name, err)
	}
	if owner == "" || owner == tenancy.NormalizeProject(project) {
		return nil
	}
	return status.Errorf(codes.PermissionDenied,
		"OCI image %q was pulled by project %q; a container in project %q may not %s it (pull it into your project under another name)",
		name, owner, tenancy.NormalizeProject(project), verb)
}

// refuseClaimingOwnerlessItem refuses an owner-bound caller (not an admin,
// or a peer forwarding for one) a pull with --project over a library item
// that exists with no owner record. Such an item was pulled before owners
// were recorded, or without --project, and is everyone's: containers of any
// project may run from it, and claiming it for one project would refuse
// every other project a new container from it, and a compose redeploy of a
// member already built from it (refused before its delete). The first claim
// of an existing ownerless item is the Admin's; a pull without --project, or
// into a new name, is not.
func (s *Server) refuseClaimingOwnerlessItem(ctx context.Context, name, dest, project string) error {
	if name == "" || project == "" || s.dataDir == "" || !s.ownerStrict(ctx) {
		return nil
	}
	if _, err := os.Stat(dest); err != nil {
		return nil // a new item: its puller's project owns it
	}
	owner, err := s.readOCIOwner(name)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "OCI image %q: its owner record is unreadable: %v", name, err)
	}
	if owner != "" {
		return nil
	}
	return status.Errorf(codes.PermissionDenied,
		"OCI image %q exists and belongs to no project, so containers of any project may run from it; "+
			"claiming it for project %q needs the Admin role (pull without --project, or into another name)",
		name, tenancy.NormalizeProject(project))
}

// SetContainerLxcpath sets the LXC container store the runtime uses (its
// lxcpath; default /var/lib/lxc), inside which an Admin's template may be read.
func (s *Server) SetContainerLxcpath(p string) { s.lxcStore = p }

func (s *Server) containerLxcpath() string {
	if s.lxcStore != "" {
		return s.lxcStore
	}
	return "/var/lib/lxc"
}
