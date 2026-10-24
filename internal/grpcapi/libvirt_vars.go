package grpcapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// The UEFI vars file libvirt keeps for a plain UEFI VM (no Secure Boot, no
// vTPM) in its own directory, <libvirt nvram dir>/<vm>_VARS.fd. A Secure Boot
// or vTPM VM's are name-keyed under <data_dir>/nvram and belong to the
// firmware store and its move guard; nothing here touches them.

// maxLibvirtVarsBytes bounds the vars file a cold move carries (OVMF's are
// about 0.5 MiB).
const maxLibvirtVarsBytes = 16 << 20

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

// setAsideStaleVars renames the regular file at path, UEFI vars an earlier VM
// of the name left, to <path>.superseded-<time> (`lv host superseded-disks`
// lists it), so a domain defined now starts from a fresh template instead of
// another VM's boot entries and keys. Nothing is removed. The name-keyed Secure
// Boot / vTPM path is never touched: that state is the firmware store's.
func (s *Server) setAsideStaleVars(vmName, path string) (string, error) {
	if path == "" || filepath.Clean(path) == filepath.Clean(s.fw().NvramPath(vmName)) {
		return "", nil
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	to := health.SupersededName(path, time.Now())
	if err := os.Rename(path, to); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	slog.Warn("set aside the UEFI vars an earlier VM of the name left", "vm", vmName, "path", path, "to", to)
	return to, nil
}

// setAsideStaleLibvirtVars is setAsideStaleVars at the path libvirt gives the
// domain by default, for the definers that run before the domain exists (clone,
// import, restore, promote, a cold move's target).
func (s *Server) setAsideStaleLibvirtVars(vmName string) error {
	if _, err := s.setAsideStaleVars(vmName, s.libvirtVarsPath(vmName)); err != nil {
		return fmt.Errorf("UEFI vars of an earlier VM %s at %s could not be set aside: %w", vmName, s.libvirtVarsPath(vmName), err)
	}
	return nil
}

func varsSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// readSourceLibvirtVars is the stopped VM's libvirt-managed vars file for a
// cold move: nil when the VM has none, or when its definition names another
// path (a name-keyed Secure Boot / vTPM one).
func (s *Server) readSourceLibvirtVars(vmName, domXML string) ([]byte, error) {
	p := s.libvirtVarsPath(vmName)
	if x := lv.NvramPathFromXML(domXML); x != "" && filepath.Clean(x) != filepath.Clean(p) {
		return nil, nil
	}
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the UEFI vars of %q: %v", vmName, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxLibvirtVarsBytes {
		return nil, status.Errorf(codes.FailedPrecondition,
			"the UEFI vars of %q at %s are not a regular file of at most %d bytes; nothing was changed", vmName, p, maxLibvirtVarsBytes)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the UEFI vars of %q: %v", vmName, err)
	}
	return b, nil
}

// writeTargetLibvirtVars is the target half of a cold move's vars: the file is
// written durably where libvirt looks for the domain's vars (a file of the
// name already there is set aside first), and read back, and the hash of what
// was read is returned.
func (s *Server) writeTargetLibvirtVars(vmName, domXML string, data []byte, want string) (string, error) {
	p := s.libvirtVarsPath(vmName)
	if x := lv.NvramPathFromXML(domXML); x != "" && filepath.Clean(x) != filepath.Clean(p) {
		return "", status.Errorf(codes.FailedPrecondition,
			"the domain's vars are at %s, not where this host's libvirt keeps them (%s)", x, p)
	}
	if varsSHA256(data) != want {
		return "", status.Error(codes.InvalidArgument, "the UEFI vars do not match their hash")
	}
	if len(data) > maxLibvirtVarsBytes {
		return "", status.Error(codes.InvalidArgument, "the UEFI vars are too large")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", status.Errorf(codes.Internal, "make %s: %v", filepath.Dir(p), err)
	}
	if _, err := s.setAsideStaleVars(vmName, p); err != nil {
		return "", status.Errorf(codes.Internal, "set aside the UEFI vars already at %s: %v", p, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "."+vmName+"_VARS.fd.tmp-")
	if err != nil {
		return "", status.Errorf(codes.Internal, "write the UEFI vars: %v", err)
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Chmod(0o600)
	}
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), p)
	}
	if werr != nil {
		return "", status.Errorf(codes.Internal, "write the UEFI vars: %v", werr)
	}
	if d, derr := os.Open(filepath.Dir(p)); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, data) {
		return "", status.Errorf(codes.Internal, "the UEFI vars read back from %s differ from what was written (%v)", p, err)
	}
	return varsSHA256(got), nil
}

// removeMigratedSourceVars removes the UEFI vars file libvirt kept for a plain
// UEFI VM on this host once the VM has moved to another one.
//
// libvirt's migration undefine (VIR_MIGRATE_UNDEFINE_SOURCE) and the cold
// move's keep-state undefine both leave the file: neither passes
// VIR_DOMAIN_UNDEFINE_NVRAM. Left there, nothing removed it: a delete of the
// VM runs on its new host, and a later create of the name here would have its
// first boot read the old VM's boot entries and variables.
//
// It runs only after the move committed on the target, and it removes nothing
// while a domain of the name is still defined here (a rollback or a held move
// may still need it), nor when the VM's row names this host. A live move's
// vars travel in the migration stream. A cold move passes the hash the target
// confirmed it holds (wantSHA): the file goes only while it is still those
// bytes, so the source's copy is never the only one.
func (s *Server) removeMigratedSourceVars(ctx context.Context, vmName, wantSHA string) {
	if s.virt == nil || s.virt.DomainExists(vmName) {
		return
	}
	if s.db != nil {
		row, err := corrosion.GetVM(ctx, s.db, vmName)
		if err != nil || row == nil || row.HostName == "" || row.HostName == s.hostName {
			slog.Debug("post-migration: the source's UEFI vars kept; the VM's row does not name another host", "vm", vmName, "error", err)
			return
		}
	}
	p := s.libvirtVarsPath(vmName)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	if wantSHA != "" {
		b, rerr := os.ReadFile(p)
		if rerr != nil || varsSHA256(b) != wantSHA {
			slog.Warn("post-migration: the source's UEFI vars kept; they are not the copy the target confirmed", "vm", vmName, "path", p, "error", rerr)
			return
		}
	}
	if err := os.Remove(p); err != nil {
		slog.Warn("post-migration: could not remove the source's UEFI vars", "vm", vmName, "path", p, "error", err)
		return
	}
	slog.Info("post-migration: removed the source's UEFI vars", "vm", vmName, "path", p)
}
