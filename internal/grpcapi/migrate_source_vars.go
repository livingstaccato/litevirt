package grpcapi

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// SetLibvirtNvramDir points this server at the directory libvirt keeps a plain
// UEFI domain's vars file in (default health.LibvirtNvramDir). Tests only.
func (s *Server) SetLibvirtNvramDir(dir string) { s.libvirtNvramDir = dir }

func (s *Server) libvirtVarsPath(vmName string) string {
	dir := s.libvirtNvramDir
	if dir == "" {
		dir = health.LibvirtNvramDir
	}
	return filepath.Join(dir, vmName+"_VARS.fd")
}

// removeMigratedSourceVars removes the UEFI vars file libvirt kept for a plain
// UEFI VM (no Secure Boot, no vTPM) on this host once the VM has moved to
// another one.
//
// libvirt's migration undefine (VIR_MIGRATE_UNDEFINE_SOURCE) and the cold
// move's keep-state undefine both leave the file: neither passes
// VIR_DOMAIN_UNDEFINE_NVRAM. Left there, nothing removed it: a delete of the
// VM runs on its new host, and a later create of the name here would have its
// first boot read the old VM's boot entries and variables.
//
// It runs only after the move committed on the target, and it removes nothing
// while a domain of the name is still defined here (a rollback or a held move
// may still need it), nor when the VM's row names this host. A Secure Boot or
// vTPM VM's vars are name-keyed under <data_dir>/nvram and belong to the
// firmware move; they are not touched here.
func (s *Server) removeMigratedSourceVars(ctx context.Context, vmName string) {
	if s.virt == nil || s.virt.DomainExists(vmName) {
		return
	}
	if s.db != nil {
		row, err := corrosion.GetVM(ctx, s.db, vmName)
		if err != nil || row == nil || row.HostName == "" || row.HostName == s.hostName {
			return
		}
	}
	p := s.libvirtVarsPath(vmName)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	if err := os.Remove(p); err != nil {
		slog.Warn("post-migration: could not remove the source's UEFI vars", "vm", vmName, "path", p, "error", err)
		return
	}
	slog.Info("post-migration: removed the source's UEFI vars", "vm", vmName, "path", p)
}
