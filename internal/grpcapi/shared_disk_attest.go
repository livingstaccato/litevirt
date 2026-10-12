package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// AttestSharedDiskUnused is the attestation `lv doctor repair-owner` asks of
// the host a shared disk's row names when that host is active (review c2b):
// a migration whose ownership commit declined leaves the rows naming the
// source, which is up and in service, and fence-confirming it would be too
// heavy a remedy. Peer-only. Under the start lock (health.LockSharedDiskStarts,
// which every start on this host takes for its check and its StartDomain) and
// the VM's own lock, it lists every domain defined here, running or not, and
// answers unused only when none names the path as a disk source; it then
// records the release durably, so no later start here of a domain using the
// path runs until the VM's own row for the disk names this host again. Any
// error fails closed (an error, never unused).
func (s *Server) AttestSharedDiskUnused(ctx context.Context, req *pb.AttestSharedDiskUnusedRequest) (*pb.AttestSharedDiskUnusedResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	path := req.GetPath()
	if req.GetVmName() == "" || req.GetDiskName() == "" || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, status.Error(codes.InvalidArgument, "an attestation names a VM, a disk and its absolute path")
	}
	if s.virt == nil {
		return nil, status.Error(codes.Unavailable, "libvirt not wired on this host")
	}
	// The VM's lock first, then the start lock: the order startVMLocked takes
	// them in (review m3).
	unlock := s.lockVM(req.GetVmName())
	defer unlock()
	release := health.LockSharedDiskStarts()
	defer release()
	names, err := s.virt.ListDomains()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "list the domains on %s: %v", s.hostName, err)
	}
	for _, name := range names {
		inactive, ierr := s.virt.DumpXMLInactive(name)
		live, lerr := s.virt.DumpXML(name)
		if ierr != nil && lerr != nil {
			return nil, status.Errorf(codes.Unavailable, "read the definition of %s on %s: %v", name, s.hostName, ierr)
		}
		if health.DomainXMLUsesPath(inactive, path) || health.DomainXMLUsesPath(live, path) ||
			domainSourcesName(inactive, path) || domainSourcesName(live, path) {
			return &pb.AttestSharedDiskUnusedResponse{Unused: false,
				Detail: fmt.Sprintf("domain %s on %s uses %s", name, s.hostName, path)}, nil
		}
	}
	if err := health.RecordSharedDiskRelease(s.dataDir, health.SharedDiskRelease{
		Path: path, VM: req.GetVmName(), Disk: req.GetDiskName(), Requester: req.GetRequester(),
	}); err != nil {
		return nil, status.Errorf(codes.Unavailable, "record the release of %s on %s: %v", path, s.hostName, err)
	}
	slog.Warn("shared disk released: no domain here uses it; its row may be re-homed", "vm", req.GetVmName(),
		"disk", req.GetDiskName(), "path", path, "to", req.GetRequester())
	s.audit(ctx, "shared_disk.release", req.GetVmName(), fmt.Sprintf("disk %s at %s released to %s", req.GetDiskName(), path, req.GetRequester()), "ok")
	return &pb.AttestSharedDiskUnusedResponse{Unused: true}, nil
}

// attestSharedDiskUnused asks host to attest d unused (AttestSharedDiskUnused).
// Any failure — unreachable, an error, an older host without the RPC, or a
// domain there using the disk — is returned as an error: fail closed.
func (s *Server) attestSharedDiskUnused(ctx context.Context, host string, vm string, d corrosion.DiskRecord) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cl, closer, err := s.dialPeer(cctx, host)
	if err != nil {
		return fmt.Errorf("%s cannot be reached: %v", host, err)
	}
	defer closer()
	resp, err := cl.AttestSharedDiskUnused(cctx, &pb.AttestSharedDiskUnusedRequest{
		VmName: vm, DiskName: d.DiskName, Path: d.Path, Requester: s.hostName})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return fmt.Errorf("%s runs a build that cannot attest it", host)
		}
		return fmt.Errorf("%s did not attest it: %v", host, err)
	}
	if !resp.GetUnused() {
		return fmt.Errorf("%s still uses it: %s", host, resp.GetDetail())
	}
	return nil
}

// domainSourcesName reports whether a parsed disk source of xml (file or
// device, backing chain included) is path once cleaned: the XML-escaped forms
// a substring match misses (review m5). A device reached through another
// alias (/dev/mapper against /dev/disk/by-path) is not recognised; litevirt
// records canonical pool paths, and a network (RBD) disk has no absolute path
// and so is never attested — its row needs fence-confirm.
func domainSourcesName(xml, path string) bool {
	for _, src := range domainDiskSources(xml) {
		if filepath.Clean(src.path) == path {
			return true
		}
	}
	return false
}
