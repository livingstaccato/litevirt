package grpcapi

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// verifyDiskChainForStart judges, before a start, every backing of local
// disk d (its file on this host) by the rule every copy path judges it by
// (diskChainRule): qemu and libvirt's relabelling follow the chain, so a
// layer naming a file the VM's project may not read would hand the guest
// that file. A backing that is missing, or that the rule refuses, refuses
// the start, saying which.
//
// Disks from an earlier build start as they did: a pool root disk whose
// header names its image by a bare relative name finds it beside the disk,
// as qemu does, and that file — placed there with the disk, recorded by no
// one — passes (diskChain.legacyPoolBase). A file a user uploaded there under
// that name passes too, but its own header is the uploader's to write: what
// it names is judged by record, never by the directory it is in
// (diskChain.judge).
func (s *Server) verifyDiskChainForStart(ctx context.Context, vm *corrosion.VMRecord, d corrosion.DiskRecord, file string) error {
	if fi, err := os.Stat(file); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	if _, err := precheckChain(file, s.diskChainRule(ctx, d)); err != nil {
		slog.Error("start refused: a disk's backing chain names a file the VM may not read", "vm", vm.Name, "disk", d.DiskName, "file", file, "error", err)
		return status.Errorf(codes.FailedPrecondition,
			"disk %q of %q (%s) cannot be started: its backing chain is refused: %v", d.DiskName, vm.Name, filepath.Base(file), err)
	}
	return nil
}
