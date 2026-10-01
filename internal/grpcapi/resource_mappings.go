package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Resource mappings (#14) are cluster-wide aliases for equivalent passthrough
// devices on one or more hosts. A VM requesting a device by mapping name can be
// placed on / migrated to any host registered under that mapping. The rows are
// CRDT-replicated, so any daemon serves a consistent view.
//
// A mapping decides which host PCI device a VM is handed, so every mutation
// writes one audit row: the caller, the mapping (the target), and the state
// before and after, as `before=<state> after=<state>` (firewall_audit.go). The
// before-state is read ahead of the write: a removed device is tombstoned, and
// after that the row is the only record of which device the mapping named. A
// write that fails is recorded as "error" with an after-state of
// unknown(<error>), a removal that names nothing live is NotFound and recorded
// as "error", and a caller without resourcemap.write is recorded as "denied"
// with what they asked for — the backup-repo convention (backup_repo_ops.go).

const (
	auditResourceMapAdd       = "resourcemap.add"
	auditResourceMapRm        = "resourcemap.rm"
	auditResourceMapDeviceAdd = "resourcemap.device.add"
	auditResourceMapDeviceRm  = "resourcemap.device.rm"
)

func toPbResourceMapping(m corrosion.ResourceMappingRecord) *pb.ResourceMapping {
	out := &pb.ResourceMapping{Name: m.Name, Description: m.Description}
	for _, d := range m.Devices {
		out.Devices = append(out.Devices, &pb.ResourceMappingDevice{
			HostName: d.HostName, Address: d.Address, Vendor: d.Vendor, Device: d.Device,
		})
	}
	return out
}

// resourceMapWriteAllowed checks resourcemap.write at `/`, auditing a refusal
// against target with what the caller asked for. A refused attempt to repoint
// a passthrough device is worth a row.
func (s *Server) resourceMapWriteAllowed(ctx context.Context, action, target, requested string) error {
	err := s.RequirePerm(ctx, "/", "resourcemap.write", "operator")
	if err != nil && status.Code(err) == codes.PermissionDenied {
		s.audit(ctx, action, target, requested+" "+err.Error(), "denied")
	}
	return err
}

// mappingDeviceKey renders the device a removal names, for the rows that have
// no before-state to show it.
func mappingDeviceKey(host, address string) string {
	return "device=" + corrosion.MappingDevice{HostName: host, Address: address}.AuditText()
}

func (s *Server) CreateResourceMapping(ctx context.Context, req *pb.CreateResourceMappingRequest) (*pb.ResourceMapping, error) {
	requested := corrosion.ResourceMappingRecord{Name: req.Name, Description: req.Description}.AuditText()
	if err := s.resourceMapWriteAllowed(ctx, auditResourceMapAdd, req.Name, "requested="+requested); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "mapping name required")
	}
	// Creating a mapping that exists rewrites its description: read what it was.
	before := corrosion.ResourceMappingAuditState(ctx, s.db, req.Name)
	if err := corrosion.CreateResourceMapping(ctx, s.db, req.Name, req.Description); err != nil {
		s.audit(ctx, auditResourceMapAdd, req.Name, corrosion.AuditChange(before, corrosion.AuditUnknown(err)), "error")
		return nil, status.Errorf(codes.Internal, "create resource mapping: %v", err)
	}
	slog.Info("resource mapping created", "name", req.Name)
	m, err := corrosion.GetResourceMapping(ctx, s.db, req.Name)
	after := corrosion.AuditStateNone
	switch {
	case err != nil:
		after = corrosion.AuditUnknown(err)
	case m != nil:
		after = m.AuditText()
	}
	s.audit(ctx, auditResourceMapAdd, req.Name, corrosion.AuditChange(before, after), "ok")
	if err != nil || m == nil {
		return &pb.ResourceMapping{Name: req.Name, Description: req.Description}, nil
	}
	return toPbResourceMapping(*m), nil
}

func (s *Server) ListResourceMappings(ctx context.Context, _ *pb.ListResourceMappingsRequest) (*pb.ListResourceMappingsResponse, error) {
	if err := s.RequirePerm(ctx, "/", "resourcemap.read", "viewer"); err != nil {
		return nil, err
	}
	mappings, err := corrosion.ListResourceMappings(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list resource mappings: %v", err)
	}
	resp := &pb.ListResourceMappingsResponse{}
	for _, m := range mappings {
		resp.Mappings = append(resp.Mappings, toPbResourceMapping(m))
	}
	return resp, nil
}

func (s *Server) DeleteResourceMapping(ctx context.Context, req *pb.DeleteResourceMappingRequest) (*emptypb.Empty, error) {
	if err := s.resourceMapWriteAllowed(ctx, auditResourceMapRm, req.Name, "requested="+corrosion.AuditStateNone); err != nil {
		return nil, err
	}
	// Read what is about to go, devices included: after this the audit row is
	// the only record of which host devices the mapping handed out.
	before := corrosion.ResourceMappingAuditState(ctx, s.db, req.Name)
	if before == corrosion.AuditStateNone {
		// A name that matches no live mapping would tombstone nothing and
		// still record an "ok" removal.
		s.audit(ctx, auditResourceMapRm, req.Name,
			corrosion.AuditChange(before, corrosion.AuditStateNone)+" (no such mapping)", "error")
		return nil, status.Errorf(codes.NotFound, "no resource mapping %q (lv mapping ls shows them)", req.Name)
	}
	if err := corrosion.DeleteResourceMapping(ctx, s.db, req.Name); err != nil {
		s.audit(ctx, auditResourceMapRm, req.Name, corrosion.AuditChange(before, corrosion.AuditUnknown(err)), "error")
		return nil, status.Errorf(codes.Internal, "delete resource mapping: %v", err)
	}
	slog.Info("resource mapping deleted", "name", req.Name)
	s.audit(ctx, auditResourceMapRm, req.Name, corrosion.AuditChange(before, corrosion.AuditStateNone), "ok")
	return &emptypb.Empty{}, nil
}

func (s *Server) AddMappingDevice(ctx context.Context, req *pb.AddMappingDeviceRequest) (*pb.ResourceMapping, error) {
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	requested := corrosion.MappingDevice{HostName: host, Address: req.Address, Vendor: req.Vendor, Device: req.Device}.AuditText()
	if err := s.resourceMapWriteAllowed(ctx, auditResourceMapDeviceAdd, req.Mapping, "requested="+requested); err != nil {
		return nil, err
	}
	if req.Mapping == "" || req.Address == "" {
		return nil, status.Error(codes.InvalidArgument, "mapping and address required")
	}
	// Re-adding the same (mapping, host, address) rewrites vendor and device:
	// read what it replaces.
	before := corrosion.MappingDeviceAuditState(ctx, s.db, req.Mapping, host, req.Address)
	if err := corrosion.AddMappingDevice(ctx, s.db, req.Mapping, host, req.Address, req.Vendor, req.Device); err != nil {
		s.audit(ctx, auditResourceMapDeviceAdd, req.Mapping, corrosion.AuditChange(before, corrosion.AuditUnknown(err)), "error")
		return nil, status.Errorf(codes.Internal, "add mapping device: %v", err)
	}
	slog.Info("resource mapping device added", "mapping", req.Mapping, "host", host, "address", req.Address)
	// Read back, so the "after" is the device as stored.
	after := corrosion.MappingDeviceAuditState(ctx, s.db, req.Mapping, host, req.Address)
	s.audit(ctx, auditResourceMapDeviceAdd, req.Mapping, corrosion.AuditChange(before, after), "ok")
	m, err := corrosion.GetResourceMapping(ctx, s.db, req.Mapping)
	if err != nil || m == nil {
		return nil, status.Errorf(codes.Internal, "reload mapping: %v", err)
	}
	return toPbResourceMapping(*m), nil
}

func (s *Server) RemoveMappingDevice(ctx context.Context, req *pb.RemoveMappingDeviceRequest) (*pb.ResourceMapping, error) {
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	device := mappingDeviceKey(host, req.Address)
	if err := s.resourceMapWriteAllowed(ctx, auditResourceMapDeviceRm, req.Mapping, device+" requested="+corrosion.AuditStateNone); err != nil {
		return nil, err
	}
	// Read the device before it is tombstoned: after this the row is the only
	// record of which device the mapping used to name.
	before := corrosion.MappingDeviceAuditState(ctx, s.db, req.Mapping, host, req.Address)
	if before == corrosion.AuditStateNone {
		// Tombstoning nothing would still have recorded an "ok" removal.
		s.audit(ctx, auditResourceMapDeviceRm, req.Mapping,
			corrosion.AuditChange(before, corrosion.AuditStateNone)+" "+device+" (no such device)", "error")
		return nil, status.Errorf(codes.NotFound, "mapping %q has no device %s on host %q", req.Mapping, req.Address, host)
	}
	if err := corrosion.RemoveMappingDevice(ctx, s.db, req.Mapping, host, req.Address); err != nil {
		s.audit(ctx, auditResourceMapDeviceRm, req.Mapping, corrosion.AuditChange(before, corrosion.AuditUnknown(err)), "error")
		return nil, status.Errorf(codes.Internal, "remove mapping device: %v", err)
	}
	slog.Info("resource mapping device removed", "mapping", req.Mapping, "host", host, "address", req.Address)
	s.audit(ctx, auditResourceMapDeviceRm, req.Mapping, corrosion.AuditChange(before, corrosion.AuditStateNone), "ok")
	m, err := corrosion.GetResourceMapping(ctx, s.db, req.Mapping)
	if err != nil || m == nil {
		return &pb.ResourceMapping{Name: req.Mapping}, nil
	}
	return toPbResourceMapping(*m), nil
}
