package grpcapi

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The NIC an UpdateVM names in nic_mtu, nic_queues or nic_rate is named by a
// number N, read one of two ways:
//
//   - With nic_by_list_position (`lv update --nic-mtu N=`, `--nic-rate N=`),
//     N is the NIC at position N of the VM's NIC list: its live NICs in
//     ordinal order, as `lv inspect` lists them under spec.network. The NIC's
//     spec entry is the one that records its MAC; only an entry that records
//     no MAC is matched by the NIC's ordinal (compose.SpecEntryIndexForNIC). A
//     position past the end of the list names the spec entry at that index
//     when no live NIC carries it (the entry of a detached NIC).
//   - Without it (an older client, a stack deploy, whose values are its
//     compose file's entry by entry), N is the index of a spec entry, as on
//     every earlier build.
//
// N is never the NIC's ordinal: an ordinal is never reused (nextNICOrdinal),
// so a NIC detached and attached again takes a new one, often past the end of
// the spec's network list, while the entry that records its MAC keeps its
// place. On a VM whose ordinals run 0, 1, 2, ... with one entry per NIC, the
// two readings and the ordinal are the same number.

// nicIndex resolves the NICs one UpdateVM names.
type nicIndex struct {
	// nics are the VM's live NICs in ordinal order (MergedVMNICs).
	nics []corrosion.NICRecord
	// byListPosition reads every number as a position in nics
	// (UpdateVMRequest.nic_by_list_position); else as a spec index.
	byListPosition bool
}

// requestNamesNICs reports whether req names a NIC by number.
func requestNamesNICs(req *pb.UpdateVMRequest) bool {
	return len(req.GetNicMtu()) > 0 || len(req.GetNicQueues()) > 0 || len(req.GetNicRate()) > 0
}

// loadNICIndex reads the VM's NIC list for the NICs req names. A request
// that names none reads nothing.
func (s *Server) loadNICIndex(ctx context.Context, req *pb.UpdateVMRequest) (nicIndex, error) {
	ix := nicIndex{byListPosition: req.GetNicByListPosition()}
	if !requestNamesNICs(req) {
		return ix, nil
	}
	nics, err := corrosion.MergedVMNICs(ctx, s.db, req.GetName())
	if err != nil {
		return ix, status.Errorf(codes.Internal, "list NICs of %q: %v", req.GetName(), err)
	}
	ix.nics = nics
	return ix, nil
}

// sameNICs reports whether two reads of a VM's NIC list name the same NICs
// in the same order.
func (x nicIndex) sameNICs(y nicIndex) bool {
	if len(x.nics) != len(y.nics) {
		return false
	}
	for i := range x.nics {
		a, b := x.nics[i], y.nics[i]
		if a.Ordinal != b.Ordinal || !strings.EqualFold(a.MAC, b.MAC) {
			return false
		}
	}
	return true
}

// liveNICForEntry is the live NIC spec entry e describes, nil when none does.
func liveNICForEntry(spec *pb.VMSpec, nics []corrosion.NICRecord, e int) *corrosion.NICRecord {
	if e < 0 {
		return nil
	}
	for i := range nics {
		if compose.SpecEntryIndexForNIC(spec, nics[i].MAC, nics[i].Ordinal) == e {
			return &nics[i]
		}
	}
	return nil
}

// resolve finds the NIC numbered i: the index of its spec entry (-1 when the
// spec has none: a NIC attached after the create that nothing has described
// since, or whose entry records another MAC), and the live NIC (nil for an
// entry no live NIC carries). ok is false when i names nothing.
func (x nicIndex) resolve(spec *pb.VMSpec, i int) (entry int, nic *corrosion.NICRecord, ok bool) {
	if i < 0 {
		return -1, nil, false
	}
	if !x.byListPosition {
		if i >= len(spec.GetNetwork()) {
			return -1, nil, false
		}
		return i, liveNICForEntry(spec, x.nics, i), true
	}
	if i < len(x.nics) {
		n := &x.nics[i]
		return compose.SpecEntryIndexForNIC(spec, n.MAC, n.Ordinal), n, true
	}
	if i < len(spec.GetNetwork()) && liveNICForEntry(spec, x.nics, i) == nil {
		return i, nil, true
	}
	return -1, nil, false
}

// noEntry is the refusal of a rate or queue count for NIC i, which resolved
// to nic (nil: nothing) and no spec entry to hold it. what is "a rate" or "a
// queue count"; code is the refusal's code. A request by spec index keeps
// main's words (legacy).
func (x nicIndex) noEntry(code codes.Code, vm string, spec *pb.VMSpec, i int, nic *corrosion.NICRecord, what, legacy string) error {
	if !x.byListPosition {
		return status.Error(code, legacy)
	}
	if nic == nil {
		return status.Errorf(code, "VM %q has no NIC %d: it has %d (numbered from 0 as `lv inspect %s` lists them under spec.network)",
			vm, i, len(x.nics), vm)
	}
	why := "it was attached after the VM was created"
	if len(spec.GetNetwork()) > 0 {
		why += ", or its entry records another MAC"
	}
	return status.Errorf(code,
		"NIC %d (MAC %s) has no spec entry to hold %s: %s. Give it one with `lv update %s --nic-mtu %d=0` "+
			"(the VM stopped, or --restart-if-needed), then set %s; on a VM of a stack, list the NIC in its compose file",
		i, nic.MAC, what, why, vm, i, what)
}

// peerReadsNICListPosition asks a peer whether its build reads
// UpdateVMRequest.nic_by_list_position. A peer that cannot be asked is
// treated as one that does not.
func (s *Server) peerReadsNICListPosition(ctx context.Context, client pb.LiteVirtClient) bool {
	resp, err := client.Ping(ctx, &pb.PingRequest{})
	return err == nil && resp.GetNicListPosition()
}
