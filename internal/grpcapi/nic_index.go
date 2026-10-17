package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The NIC an UpdateVM names in nic_mtu, nic_queues or nic_rate (`lv update
// --nic-mtu N=`, `--nic-rate N=`) is the one at position N of the VM's NIC
// list: its live NICs in ordinal order, as `lv inspect` lists them under
// spec.network. N is not the NIC's ordinal, and not its spec entry's index:
// an ordinal is never reused (nextNICOrdinal), so a NIC detached and attached
// again takes a new one, often past the end of the spec's network list, while
// the entry that records its MAC keeps its place. On a VM whose ordinals run
// 0, 1, 2, ... with one entry per NIC, all three are the same number.
//
// The NIC's spec entry is the one that records its MAC; only an entry that
// records no MAC is matched by the NIC's ordinal
// (compose.SpecEntryIndexForNIC).
//
// A position past the end of the list keeps main's meaning: the spec entry at
// that index, when no live NIC carries it (the entry of a detached NIC). A
// stack deploy sets nic_by_spec_entry, and then every N is a spec index: its
// values are its compose file's, entry by entry.

// nicIndex resolves the NICs one UpdateVM names.
type nicIndex struct {
	// nics are the VM's live NICs in ordinal order (MergedVMNICs).
	nics []corrosion.NICRecord
	// bySpecEntry reads every index as a spec entry's
	// (UpdateVMRequest.nic_by_spec_entry).
	bySpecEntry bool
}

// requestNamesNICs reports whether req names a NIC by index.
func requestNamesNICs(req *pb.UpdateVMRequest) bool {
	return len(req.GetNicMtu()) > 0 || len(req.GetNicQueues()) > 0 || len(req.GetNicRate()) > 0
}

// loadNICIndex reads the VM's NIC list for the NICs req names. A request
// that names none reads nothing.
func (s *Server) loadNICIndex(ctx context.Context, req *pb.UpdateVMRequest) (nicIndex, error) {
	ix := nicIndex{bySpecEntry: req.GetNicBySpecEntry()}
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

// resolve finds the NIC at index i: the index of its spec entry (-1 when the
// spec has none: a NIC attached after the create that nothing has described
// since), and the live NIC (nil for an entry no live NIC carries). ok is false
// when i names nothing.
func (x nicIndex) resolve(spec *pb.VMSpec, i int) (entry int, nic *corrosion.NICRecord, ok bool) {
	if i < 0 {
		return -1, nil, false
	}
	if x.bySpecEntry {
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
