package grpcapi

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/lxc"
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

// localOCISource returns the directory a local "oci:<dir>[:tag]" image
// reference reads, or "" for a registry reference.
func localOCISource(image string) string {
	rest, ok := strings.CutPrefix(image, "oci:")
	if !ok {
		return ""
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[i:], "/") {
		rest = rest[:i]
	}
	return rest
}

// checkOCIPullPaths is the backstop for a pull's host paths, run on the host
// that unpacks: an absolute dest is a directory root writes an untrusted
// image into (the OCI library itself is the daemon's own), and a local source
// is a directory it reads.
func (s *Server) checkOCIPullPaths(image, dest string) error {
	if src := localOCISource(image); src != "" {
		if err := storage.CheckReadDir(filepath.Clean(src), s.dataDir, s.pkiDir); err != nil {
			return status.Errorf(codes.InvalidArgument, "oci source: %v", err)
		}
	}
	if filepath.IsAbs(dest) {
		lib := filepath.Join(s.dataDir, storage.OCILibraryDir)
		inLib := s.dataDir != "" && filepath.Dir(filepath.Clean(dest)) == lib
		if !inLib {
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
func (s *Server) readOCIOwner(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(s.dataDir, ociOwnersDir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (s *Server) writeOCIOwner(name, project string) error {
	dir := filepath.Join(s.dataDir, ociOwnersDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), []byte(project+"\n"), 0o600)
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
// every other project's container at its next create from it (a compose
// recreate, after its delete). The first claim of an existing ownerless item
// is the Admin's; a pull without --project, or into a new name, is not.
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
