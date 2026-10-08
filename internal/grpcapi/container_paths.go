package grpcapi

import (
	"context"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/storage"
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
func (s *Server) checkContainerTemplate(template string) error {
	p, isPath, err := lxc.TemplatePath(template)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "template: %v", err)
	}
	if !isPath {
		return nil
	}
	if err := storage.CheckReadDir(p, s.dataDir, s.pkiDir); err != nil {
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
