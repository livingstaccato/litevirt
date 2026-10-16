package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A VM's desired spec is edited on its owner. Every edit is a compare-and-swap
// on spec_generation, and two hosts that each make one from the same
// generation produce two versions of the spec that replication cannot merge:
// one of them is dropped. Made on the owner, the second edit re-reads the
// first and keeps both. UpdateVM has always forwarded; the metadata writers
// (labels, a deploy's live metadata and recorded size) wrote wherever the call
// entered.
//
// An owner that cannot be reached does not refuse the edit: it is made here,
// as before, and replication resolves it against anything the owner wrote
// meanwhile (corrosion/spec_conflict.go).

// forwardedByPeer reports whether the call came from another cluster host:
// a forward. A forwarded edit is made where it lands and never forwarded
// again, so two hosts whose replicas each name the other as the owner (an
// ownership move half replicated) do not pass it back and forth. A call
// over this host's own certificate (its local CLI) is not a forward.
func (s *Server) forwardedByPeer(ctx context.Context) bool {
	if callerPrincipalKind(ctx) != principalKindPeer {
		return false
	}
	cn := callerMTLSCommonName(ctx)
	return cn != "" && cn != s.hostName
}

// ownerForwardTimeout bounds asking a VM's owner to make a spec edit. A
// partitioned owner can leave the call hanging; past this the edit is made
// on this host.
const ownerForwardTimeout = 10 * time.Second

// ownerUnreachable reports whether err, from an edit forwarded to a VM's
// owner, means the owner was not reached, so the edit may be made here. The
// caller's own context ending is not that: the edit is abandoned.
// Unimplemented is an owner on a build without the RPC. Unavailable also
// covers an owner that refused because its replica is stale or cannot see
// the forwarded identity; the edit is made here then too.
//
// Unavailable and DeadlineExceeded can arrive after the owner committed the
// edit (a slow lock, a lost reply). The edit made here is then a second one
// at the same generation, usually with the same content, which the spec
// conflict resolution settles without dropping anything. That is the price
// of never refusing an edit main allowed.
func ownerUnreachable(parent context.Context, err error) bool {
	if err == nil || parent.Err() != nil {
		return false
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Unimplemented:
		return true
	}
	return false
}

// forwardSpecEdit runs call against host, the VM's owner. done=false means
// the owner could not be reached and the caller makes the edit itself.
func forwardSpecEdit[T any](ctx context.Context, s *Server, vmName, host string, call func(context.Context, pb.LiteVirtClient) (T, error)) (out T, done bool, err error) {
	client, conn, derr := s.peerClient(ctx, host)
	if derr != nil {
		slog.Warn("spec edit: the VM's owner cannot be dialled; editing here", "vm", vmName, "owner", host, "error", derr)
		return out, false, nil
	}
	defer conn.Close()
	fctx, cancel := context.WithTimeout(ctx, ownerForwardTimeout)
	defer cancel()
	out, err = call(fctx, client)
	if ownerUnreachable(ctx, err) {
		slog.Warn("spec edit: the VM's owner did not answer; editing here", "vm", vmName, "owner", host, "error", err)
		var zero T
		return zero, false, nil
	}
	return out, true, err
}

// patchSpecFields writes the named fields of desired onto spec. The field
// names are compose's live-metadata fields plus "cpu" and "memory".
func patchSpecFields(name string, spec, desired *pb.VMSpec, fields []string) {
	for _, f := range fields {
		switch f {
		case "cpu":
			spec.Cpu = desired.Cpu
		case "memory":
			spec.MemoryMib = desired.MemoryMib
		case "disk_io":
			// applied and recorded by applyDesiredDiskIO
		case "restart":
			spec.Restart = desired.Restart
		case "onboot":
			spec.Onboot = desired.Onboot
		case "startup_order":
			spec.StartupOrder = desired.StartupOrder
		case "start_delay":
			spec.StartDelaySec = desired.StartDelaySec
		case "stop_delay":
			spec.StopDelaySec = desired.StopDelaySec
		case "labels":
			spec.Labels = desired.Labels
		case "placement":
			spec.Placement = desired.Placement
		case "migrate":
			// With its top-level mirror, which is all the failover
			// coordinator reads (compose.BuildVMSpec; a create stores both).
			spec.Migrate = desired.Migrate
			spec.OnHostFailure = desired.OnHostFailure
		case "healthcheck":
			spec.Healthcheck = desired.Healthcheck
		case "hooks":
			spec.Hooks = desired.Hooks
		case "stop_timeout":
			spec.StopTimeoutSec = desired.StopTimeoutSec
		default:
			slog.Warn("spec patch: ignoring unknown field", "vm", name, "field", f)
		}
	}
}

// patchSpecHere writes fields of desired onto name's stored spec on this
// host. applied=false: an operation holds the VM's barrier.
func (s *Server) patchSpecHere(ctx context.Context, name string, desired *pb.VMSpec, fields []string) (bool, error) {
	applied, _, err := corrosion.MutateDesiredSpec(ctx, s.db, name, func(old string) (string, error) {
		fresh := &pb.VMSpec{}
		if old != "" {
			if uerr := json.Unmarshal([]byte(old), fresh); uerr != nil {
				return "", uerr
			}
		}
		patchSpecFields(name, fresh, desired, fields)
		b, merr := json.Marshal(fresh)
		return string(b), merr
	})
	return applied, err
}

// patchSpecAtOwner writes fields of desired onto name's stored spec on the
// VM's owner, or here when this host is the owner or the owner cannot be
// reached. applied=false: an operation holds the VM's barrier.
func (s *Server) patchSpecAtOwner(ctx context.Context, name string, desired *pb.VMSpec, fields []string) (bool, error) {
	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil {
		return false, err
	}
	if vm != nil && vm.HostName != "" && vm.HostName != s.hostName {
		_, done, ferr := forwardSpecEdit(ctx, s, name, vm.HostName, func(fctx context.Context, c pb.LiteVirtClient) (*emptypb.Empty, error) {
			return c.PatchVMSpec(fctx, &pb.PatchVMSpecRequest{Name: name, Desired: desired, Fields: fields})
		})
		if done {
			if status.Code(ferr) == codes.FailedPrecondition {
				return false, nil
			}
			return ferr == nil, ferr
		}
	}
	return s.patchSpecHere(ctx, name, desired, fields)
}

// PatchVMSpec writes the named fields of a desired spec onto a VM's stored
// spec on this host. Peer only: it is the owner's end of patchSpecAtOwner, and
// every permission was checked on the host the call entered.
func (s *Server) PatchVMSpec(ctx context.Context, req *pb.PatchVMSpecRequest) (*emptypb.Empty, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.Name == "" || req.Desired == nil {
		return nil, status.Error(codes.InvalidArgument, "name and desired required")
	}
	applied, err := s.patchSpecHere(ctx, req.Name, req.Desired, req.Fields)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "patch the spec of %q: %v", req.Name, err)
	}
	if !applied {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot update %q: an operation is in progress", req.Name)
	}
	return &emptypb.Empty{}, nil
}
