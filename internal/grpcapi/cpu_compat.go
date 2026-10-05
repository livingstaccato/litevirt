package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// CheckCPUCompatibility reports whether THIS host can run a guest requiring the
// CPU described by req.CpuXml. Peer-only, read-only, decides nothing: it is the
// destination half of the migration CPU preflight.
func (s *Server) CheckCPUCompatibility(ctx context.Context, req *pb.CheckCPUCompatibilityRequest) (*pb.CheckCPUCompatibilityResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, status.Error(codes.PermissionDenied, "CheckCPUCompatibility is peer-only")
	}
	if req.GetCpuXml() == "" {
		return nil, status.Error(codes.InvalidArgument, "cpu_xml is required")
	}
	verdict, err := s.virt.CompareCPU(req.GetCpuXml(), req.GetMachine())
	if err != nil {
		// Unavailable, not Internal: the caller cannot tell whether this host is
		// compatible, which is a "could not verify" — and the caller is built to
		// proceed on that rather than block a migration on a compare it could not
		// run. Saying Internal would read as a defect on this host.
		return nil, status.Errorf(codes.Unavailable, "compare cpu: %v", err)
	}
	return &pb.CheckCPUCompatibilityResponse{
		Runnable: verdict.Runnable(),
		Verdict:  verdict.String(),
	}, nil
}

// parseSpecCPUMode reads cpu_mode out of a stored spec JSON. An unreadable or
// absent value yields "" — the pre-default shape, which needs no CPU preflight.
func parseSpecCPUMode(specJSON string) string {
	var spec struct {
		CPUMode string `json:"cpu_mode"`
	}
	_ = json.Unmarshal([]byte(specJSON), &spec)
	return spec.CPUMode
}

// effectiveDefaultCPUMode is this node's configured cpu_mode default, falling
// back to the built-in one. Every path that DEFINES a brand-new domain goes
// through here, so none of them can quietly leave a guest on QEMU's qemu64.
func (s *Server) effectiveDefaultCPUMode() string {
	if s.defaultCPUModeCfg != "" {
		return s.defaultCPUModeCfg
	}
	return lv.DefaultCPUMode
}

// mergeCPUModeUpdate folds an update request's cpu_mode/cpu_model onto a stored
// spec's pair and returns the result, or an error if the operator asked for
// something libvirt would reject.
//
// The only subtlety is moving OFF custom: a host-* mode carries no model, so the
// stored one is dropped. Keeping it would fail validation on
// `--cpu-mode host-model` alone — an edit with an obvious intent — and force the
// operator to discover they must also clear a field the new mode does not use.
func mergeCPUModeUpdate(specMode, specModel, reqMode, reqModel string) (mode, model string, err error) {
	mode, model = specMode, specModel
	if reqMode != "" {
		mode = reqMode
		if reqMode != lv.CPUModeCustom {
			model = ""
		}
	}
	if reqModel != "" {
		model = reqModel
	}
	if err := lv.ValidateCPUMode(mode, model); err != nil {
		return "", "", err
	}
	return mode, model, nil
}

// cpuRequirementForMigration derives the CPU requirement a migration of vm must
// satisfy on its destination, and the guest's machine type, reading the
// SOURCE's live domain XML.
//
// It returns ok=false whenever there is nothing meaningful to check, which is
// the common case and deliberately cheap:
//   - a VM with no <cpu> element at all (an empty cpu_mode — QEMU's qemu64),
//     which is identical on every host and so always compatible;
//   - a custom mode pinned to a named model, likewise identical everywhere.
//
// For host-model, libvirt has already expanded the live XML to a concrete model
// plus feature list, and the requirement is that list CREDITED against this
// host's own host-model (lv.CreditCPURequirement): a required feature the
// source's hypervisor does not list is one the compare cannot judge on any
// host, so it is dropped rather than left to make every host — the source
// included — look incompatible. If the host-model cannot be read the live
// element is used as is, and sourceRunsGuestCPU is the backstop.
//
// For host-passthrough the live XML names no model, so the requirement is the
// SOURCE HOST's own CPU — which is precisely what such a guest is running on.
// It is not credited.
func (s *Server) cpuRequirementForMigration(vm *corrosion.VMRecord) (cpuXML, machine string, ok bool) {
	mode := parseSpecCPUMode(vm.Spec)
	if !lv.CPUModeExposesHostFeatures(mode) {
		return "", "", false
	}
	if xmlDesc, err := s.virt.DumpXML(vm.Name); err == nil {
		machine = lv.DomainMachineType(xmlDesc)
		if req, found := lv.DomainCPURequirement(xmlDesc); found {
			if mode == lv.CPUModeHostModel {
				req = s.creditHostModelRequirement(vm.Name, req, machine)
			}
			return req, machine, true
		}
	}
	// host-passthrough (or a live XML we could not read): the guest requires this
	// host's CPU.
	if mode == lv.CPUModeHostPassthrough {
		if hostCPU, err := s.virt.HostCPUXML(); err == nil && hostCPU != "" {
			return hostCPU, machine, true
		}
	}
	return "", "", false
}

// creditHostModelRequirement strips from a host-model guest's live <cpu> the
// required features this host's own host-model does not provide.
func (s *Server) creditHostModelRequirement(vmName, cpuXML, machine string) string {
	hostModel, err := s.virt.HostModelCPUFeatures(machine)
	if err != nil {
		slog.Info("migration CPU preflight: source host-model unreadable; comparing the live CPU as is",
			"vm", vmName, "err", err)
		return cpuXML
	}
	credited, dropped := lv.CreditCPURequirement(cpuXML, hostModel)
	if len(dropped) > 0 {
		slog.Info("migration CPU preflight: not requiring features the source's own host-model does not provide",
			"vm", vmName, "features", strings.Join(dropped, ","))
	}
	return credited
}

// preflightTargetCPU refuses a migration whose destination cannot run the
// guest's CPU, BEFORE any target-side provisioning.
//
// Fail-open by design, and the failure modes matter more than the happy path:
//
//   - an older peer does not implement the RPC (codes.Unimplemented), so during a
//     rolling upgrade the check must be a no-op rather than the reason migration
//     stops working;
//   - a peer that cannot run the compare answers Unavailable, which is "could not
//     verify", not "incompatible";
//   - a source that, asked the same question, rejects the guest it is running
//     shows the compare cannot decide for this guest (sourceRunsGuestCPU).
//
// Only an explicit, positive "this host cannot run that guest" from the target,
// confirmed by the source running it, refuses. That is the one answer libvirt
// would otherwise deliver mid-copy, after the target has been provisioned and
// the guest's memory is already moving.
func (s *Server) preflightTargetCPU(ctx context.Context, vm *corrosion.VMRecord, targetHost string) error {
	cpuXML, machine, ok := s.cpuRequirementForMigration(vm)
	if !ok {
		return nil
	}
	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		// Reaching the target is checked for real by the phases that follow; a
		// preflight must not invent its own unreachability failure here.
		return nil
	}
	defer conn.Close()

	resp, err := client.CheckCPUCompatibility(ctx, &pb.CheckCPUCompatibilityRequest{CpuXml: cpuXML, Machine: machine})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			slog.Info("skipping migration CPU preflight: target does not implement it",
				"vm", vm.Name, "target", targetHost)
			return nil
		}
		slog.Warn("migration CPU preflight could not verify the target",
			"vm", vm.Name, "target", targetHost, "err", err)
		return nil
	}
	if resp.GetRunnable() {
		return nil
	}
	// The target says no. Believe it only if the source says yes to the guest
	// it is running: otherwise the compare cannot tell this guest's hosts apart.
	sourceVerdict, believe := s.sourceRunsGuestCPU(vm.Name, targetHost, cpuXML, machine)
	if !believe {
		return nil
	}
	// source_verdict is in the text so that a refusal by a target still on an
	// older build (whose compare is the legacy one) can be told from a real one.
	return status.Errorf(codes.FailedPrecondition,
		"target host %q cannot run VM %q: its CPU does not provide what the guest is running on "+
			"(cpu_mode=%s, verdict=%s, source_verdict=%s). Migrate to a host with an equal-or-newer CPU, or stop the VM "+
			"and `lv update %s --cpu-mode custom --cpu-model <baseline>` to pin a model both hosts support.",
		targetHost, vm.Name, parseSpecCPUMode(vm.Spec), resp.GetVerdict(), sourceVerdict, vm.Name)
}

// sourceRunsGuestCPU asks THIS host — the source, running the guest right now —
// the same question the target just answered "no" to, and reports its verdict
// and whether the target's refusal can be believed.
//
// A source that calls its own running guest unrunnable proves the compare is
// wrong about this guest even after crediting, so the target's "no" decides
// nothing either. That is logged and the migration proceeds;
// libvirt still has the final say at cutover. A source that cannot run the
// compare at all is the same "could not verify".
func (s *Server) sourceRunsGuestCPU(vmName, targetHost, cpuXML, machine string) (string, bool) {
	verdict, err := s.virt.CompareCPU(cpuXML, machine)
	if err != nil {
		slog.Warn("migration CPU preflight cannot decide: the source could not compare the guest's CPU against itself",
			"vm", vmName, "source", s.hostName, "target", targetHost, "err", err)
		return "error", false
	}
	if !verdict.Runnable() {
		slog.Warn("migration CPU preflight cannot decide: the source rejects the CPU of the guest it is running, "+
			"so the target's refusal is not evidence; proceeding",
			"vm", vmName, "source", s.hostName, "target", targetHost, "source_verdict", verdict.String())
		return verdict.String(), false
	}
	return verdict.String(), true
}
