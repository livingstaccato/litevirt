package grpcapi

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A NIC ordinal is never reused (nextNICOrdinal): a NIC detached and attached
// again takes a fresh one, often past the end of the spec's network list. With
// nic_by_list_position (`lv update --nic-mtu N=`, `--nic-rate N=`) the NIC an
// update names is the one at position N of the VM's NIC list (its live NICs
// in ordinal order, as `lv inspect` lists them under spec.network), and its
// spec entry is the one that records its MAC. Without it N is a spec index,
// as on every earlier build.

const (
	ixMACA = "52:54:00:00:61:0a" // detached, then attached again: ordinal 2
	ixMACB = "52:54:00:00:61:0b" // kept: ordinal 1
	ixMACC = "52:54:00:00:61:0c"
)

// ixVM inserts a stopped VM "rx" whose spec lists A (lan) and B (lan2), and
// whose NIC rows are as a build that never reuses ordinals leaves them after
// A was detached and attached again: B at ordinal 1, A at ordinal 2. The NIC
// list is therefore B, A. Both bridges are at 9000.
func ixVM(t *testing.T, stack string, rows []corrosion.NICRecord, entries ...*pb.NetworkAttachment) (*Server, *libvirtfake.Fake) {
	t.Helper()
	return ixVMOn(t, "", stack, rows, entries...)
}

// ixVMOn is ixVM with the VM owned by host ("" for the server's own).
func ixVMOn(t *testing.T, host, stack string, rows []corrosion.NICRecord, entries ...*pb.NetworkAttachment) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.SetReleaseFeatureGate(newMTUGate(t, true))
	fake := s.virt.(*libvirtfake.Fake)
	for _, b := range []string{"lan", "lan2", "lan3"} {
		fake.SetBridgeMTU(b, 9000)
	}
	ctx := adminCtx()
	spec := &pb.VMSpec{Name: "rx", Cpu: 2, MemoryMib: 512, Network: entries}
	if host == "" {
		host = s.hostName
	}
	if err := corrosion.InsertVMWithHardware(ctx, s.db, corrosion.VMRecord{Name: "rx", StackName: stack, HostName: host,
		State: "stopped", CPUActual: 2, MemActual: 512, Spec: seedSpecJSON(t, spec)}, nil, nil, rows, nil, false); err != nil {
		t.Fatal(err)
	}
	var nets []lv.NetworkConfig
	for _, r := range rows {
		nets = append(nets, lv.NetworkConfig{Bridge: r.NetworkName, Model: "virtio", MAC: r.MAC})
	}
	x, err := lv.GenerateDomainXML(lv.VMConfig{Name: "rx", CPU: 2, MemoryMiB: 512, Networks: nets})
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	return s, fake
}

func ixRow(mac, network string, ordinal int) corrosion.NICRecord {
	return corrosion.NICRecord{VMName: "rx", ID: corrosion.DeterministicNICID("rx", mac), NetworkName: network,
		Model: "virtio", MAC: mac, Ordinal: ordinal}
}

// ixReattached is the VM of the doc comment above: spec A, B; rows B@1, A@2.
func ixReattached(t *testing.T, stack string) (*Server, *libvirtfake.Fake) {
	return ixReattachedOn(t, "", stack)
}

func ixReattachedOn(t *testing.T, host, stack string) (*Server, *libvirtfake.Fake) {
	return ixVMOn(t, host, stack, []corrosion.NICRecord{ixRow(ixMACB, "lan2", 1), ixRow(ixMACA, "lan", 2)},
		&pb.NetworkAttachment{Name: "lan", Model: "virtio", Mac: ixMACA},
		&pb.NetworkAttachment{Name: "lan2", Model: "virtio", Mac: ixMACB})
}

// ifaceXML is the <interface> element of x whose MAC is mac, re-marshalled
// on its own; "" when there is none.
func ifaceXML(t *testing.T, x, mac string) string {
	t.Helper()
	var d struct {
		Interfaces []struct {
			Inner string `xml:",innerxml"`
			MAC   struct {
				Address string `xml:"address,attr"`
			} `xml:"mac"`
		} `xml:"devices>interface"`
	}
	if err := xml.Unmarshal([]byte(x), &d); err != nil {
		t.Fatalf("parse domain XML: %v\n%s", err, x)
	}
	for _, i := range d.Interfaces {
		if strings.EqualFold(i.MAC.Address, mac) {
			return strings.ReplaceAll(i.Inner, `'`, `"`)
		}
	}
	return ""
}

// ixMark puts a marker in the persistent definition that only an in-place
// patch keeps: a regenerate drops it, with what libvirt assigned
// (TestUpdateVM_TuningRequestPatchesTheDefinitionInPlace).
func ixMark(t *testing.T, fake *libvirtfake.Fake) {
	t.Helper()
	x := ixInactive(t, fake)
	fake.SetInactiveXML("rx", strings.Replace(x, "<name>rx</name>", "<name>rx</name><description>libvirt-assigned-marker</description>", 1))
}

func ixPatched(t *testing.T, fake *libvirtfake.Fake) {
	t.Helper()
	if x := ixInactive(t, fake); !strings.Contains(x, "libvirt-assigned-marker") {
		t.Errorf("the definition was regenerated, not patched in place:\n%s", x)
	}
}

// byPos is an UpdateVMRequest for rx that numbers NICs by list position, as
// lv update does.
func byPos(req *pb.UpdateVMRequest) *pb.UpdateVMRequest {
	req.Name, req.NicByListPosition = "rx", true
	return req
}

func ixInactive(t *testing.T, fake *libvirtfake.Fake) string {
	t.Helper()
	x, err := fake.DumpXMLInactive("rx")
	if err != nil {
		t.Fatalf("DumpXMLInactive: %v", err)
	}
	return x
}

// Lab 2 (dombld P2): a non-stack VM made with no NIC, given one by
// attach-nic, which was detached and attached again under its MAC. Its only
// NIC has ordinal 1, and `lv update --nic-mtu 0=9000` answered
// `NotFound ... has no NIC 0`: the entry for an unlisted NIC was made by
// counting ordinals from 0. NIC 0 is the VM's only NIC; it gets an entry
// carrying its MAC, and the definition its MTU.
//
// Mutation: make the entry from the row at ordinal len(spec.Network) again —
// NotFound, red.
func TestUpdateVM_NICMTUReachesANICAttachedAgainAfterADetach(t *testing.T) {
	s, fake := ixVM(t, "", []corrosion.NICRecord{ixRow(ixMACA, "lan", 1)})
	if _, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{
		NicMtu: []*pb.NICMTUUpdate{{Ordinal: 0, Mtu: 9000}}})); err != nil {
		t.Fatalf("--nic-mtu 0=9000 on the NIC attached again: %v", err)
	}
	spec := loadStoredSpec(t, s, "rx")
	if len(spec.Network) != 1 || !strings.EqualFold(spec.Network[0].GetMac(), ixMACA) || spec.Network[0].GetMtu() != 9000 {
		t.Fatalf("stored network = %+v, want one entry for %s with mtu 9000", spec.Network, ixMACA)
	}
	if got := interfaceMTU(t, ixInactive(t, fake), ixMACA); got != 9000 {
		t.Errorf("the NIC's <mtu> = %d, want 9000", got)
	}
}

// A NIC with no spec entry, past the end of the spec and with gaps in the
// ordinals before it, takes an entry too. NIC 1 is C (ordinal 3).
//
// Mutation: as above — NotFound for ordinal 1, red.
func TestUpdateVM_NICMTUMakesAnEntryForANICPastTheSpecsEnd(t *testing.T) {
	s, fake := ixVM(t, "", []corrosion.NICRecord{ixRow(ixMACA, "lan", 0), ixRow(ixMACC, "lan3", 3)},
		&pb.NetworkAttachment{Name: "lan", Model: "virtio", Mac: ixMACA})
	if _, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{
		NicMtu: []*pb.NICMTUUpdate{{Ordinal: 1, Mtu: 9000}}})); err != nil {
		t.Fatalf("--nic-mtu 1=9000: %v", err)
	}
	spec := loadStoredSpec(t, s, "rx")
	if len(spec.Network) != 2 || spec.Network[0].GetMtu() != 0 ||
		!strings.EqualFold(spec.Network[1].GetMac(), ixMACC) || spec.Network[1].GetName() != "lan3" || spec.Network[1].GetMtu() != 9000 {
		t.Fatalf("stored network = %+v, want A untouched and a new lan3 entry for %s with mtu 9000", spec.Network, ixMACC)
	}
	x := ixInactive(t, fake)
	if interfaceMTU(t, x, ixMACC) != 9000 || interfaceMTU(t, x, ixMACA) != 0 {
		t.Errorf("want <mtu> 9000 on C only:\n%s", x)
	}
}

// By list position, NIC 0 is B, whose entry is index 1; main read 0 as
// entry 0, A's. The definition is patched in place, the NIC found by MAC.
//
// Mutations: read the position as a spec index — A gets the MTU, red; make
// patchNICMTUInPlace fail — the marker is lost, red.
func TestUpdateVM_NICMTUIndexIsThePositionInTheNICList(t *testing.T) {
	s, fake := ixReattached(t, "")
	ixMark(t, fake)
	if _, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{
		NicMtu: []*pb.NICMTUUpdate{{Ordinal: 0, Mtu: 9000}}})); err != nil {
		t.Fatalf("--nic-mtu 0=9000: %v", err)
	}
	spec := loadStoredSpec(t, s, "rx")
	if spec.Network[0].GetMtu() != 0 || spec.Network[1].GetMtu() != 9000 {
		t.Fatalf("stored network = %+v, want the MTU on B's entry (index 1)", spec.Network)
	}
	x := ixInactive(t, fake)
	if interfaceMTU(t, x, ixMACB) != 9000 || interfaceMTU(t, x, ixMACA) != 0 {
		t.Errorf("want <mtu> 9000 on B only:\n%s", x)
	}
	ixPatched(t, fake)
	// NIC 1 is A, attached again past the spec's end.
	if _, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{
		NicMtu: []*pb.NICMTUUpdate{{Ordinal: 1, Mtu: compose.NICMTUBridge}}})); err != nil {
		t.Fatalf("--nic-mtu 1=bridge: %v", err)
	}
	if got := loadStoredSpec(t, s, "rx").Network[0].GetMtu(); got != compose.NICMTUBridge {
		t.Errorf("A's entry mtu = %d, want bridge", got)
	}
	if got := interfaceMTU(t, ixInactive(t, fake), ixMACA); got != 9000 {
		t.Errorf("A's <mtu> = %d, want the bridge's 9000", got)
	}
	ixPatched(t, fake)
}

// nic_queues by list position resolves the same way: NIC 0 is B. The
// definition is patched in place.
//
// Mutations: read the position as a spec index — A gets the queues, red;
// make patchTuningInPlace fail for a NIC — the marker is lost, red.
func TestUpdateVM_NICQueuesIndexIsThePositionInTheNICList(t *testing.T) {
	s, fake := ixReattached(t, "")
	ixMark(t, fake)
	if _, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{
		NicQueues: []*pb.NICQueuesUpdate{{Ordinal: 0, Queues: 2}}})); err != nil {
		t.Fatalf("nic_queues 0=2: %v", err)
	}
	spec := loadStoredSpec(t, s, "rx")
	if spec.Network[0].GetQueues() != 0 || spec.Network[1].GetQueues() != 2 {
		t.Fatalf("stored network = %+v, want 2 queues on B's entry (index 1)", spec.Network)
	}
	x := ixInactive(t, fake)
	if !strings.Contains(ifaceXML(t, x, ixMACB), `queues="2"`) || strings.Contains(ifaceXML(t, x, ixMACA), "queues=") {
		t.Errorf("want queues on B only:\n%s", x)
	}
	ixPatched(t, fake)
}

// --nic-rate by list position resolves the same way, and its cap reaches the
// NIC the position names: live, and patched into the definition in place when
// it rides a redefine. Main put it on A's entry and then found no NIC at
// ordinal 0 (FailedPrecondition).
//
// Mutations: read the position as a spec index — red; patch the bandwidth of
// the NIC at the entry's index read as an ordinal — the redefine leaves A
// uncapped, red.
func TestUpdateVM_NICRateIndexIsThePositionInTheNICList(t *testing.T) {
	s, fake := ixReattached(t, "")
	if _, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{
		NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 5}}})); err != nil {
		t.Fatalf("--nic-rate 0=5: %v", err)
	}
	spec := loadStoredSpec(t, s, "rx")
	if spec.Network[0].GetRateMbSec() != 0 || spec.Network[1].GetRateMbSec() != 5 {
		t.Fatalf("stored network = %+v, want rate 5 on B's entry (index 1)", spec.Network)
	}
	x := ixInactive(t, fake)
	if !strings.Contains(ifaceXML(t, x, ixMACB), `<inbound average="5000"`) || strings.Contains(ifaceXML(t, x, ixMACA), "<bandwidth") {
		t.Errorf("want the cap on B only:\n%s", x)
	}
	// NIC 1 is A, with a redefine (the vCPU count named): the cap is patched
	// into the definition in place.
	ixMark(t, fake)
	if _, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{Cpu: 2,
		NicRate: []*pb.NICRateUpdate{{Ordinal: 1, RateMbSec: 3}}})); err != nil {
		t.Fatalf("--nic-rate 1=3 --cpu 2: %v", err)
	}
	if got := loadStoredSpec(t, s, "rx").Network[0].GetRateMbSec(); got != 3 {
		t.Errorf("A's entry rate = %v, want 3", got)
	}
	if !strings.Contains(ifaceXML(t, ixInactive(t, fake), ixMACA), `<inbound average="3000"`) {
		t.Errorf("A has no cap:\n%s", ixInactive(t, fake))
	}
	ixPatched(t, fake)
}

// A regenerate renders each NIC's cap from its own spec entry, found by MAC:
// A's entry is index 0 and its ordinal is 2.
//
// Mutation: take the rate from spec.Network[ordinal] again — A renders no
// cap, red.
func TestUpdateVM_RegenerateRendersTheRateOfANICAttachedAgain(t *testing.T) {
	s, fake := ixVM(t, "", []corrosion.NICRecord{ixRow(ixMACB, "lan2", 1), ixRow(ixMACA, "lan", 2)},
		&pb.NetworkAttachment{Name: "lan", Model: "virtio", Mac: ixMACA, RateMbSec: 2},
		&pb.NetworkAttachment{Name: "lan2", Model: "virtio", Mac: ixMACB})
	if _, err := s.UpdateVM(adminCtx(), &pb.UpdateVMRequest{Name: "rx", Machine: "pc"}); err != nil {
		t.Fatalf("UpdateVM --machine pc: %v", err)
	}
	x := ixInactive(t, fake)
	if !strings.Contains(ifaceXML(t, x, ixMACA), `<inbound average="2000"`) || strings.Contains(ifaceXML(t, x, ixMACB), "<bandwidth") {
		t.Errorf("want A's cap on A only:\n%s", x)
	}
}

// Review I-1: a request that does not set nic_by_list_position — an older
// lv, an older deploy node, any API client written against main — means a
// spec index, on this build as on main. Entry 0 is A's, at position 1.
//
// Mutation: read a request without the field by list position — B gets the
// MTU and the rate, red.
func TestUpdateVM_WithoutListPositionANumberIsASpecIndex(t *testing.T) {
	s, fake := ixReattached(t, "")
	if _, err := s.UpdateVM(adminCtx(), &pb.UpdateVMRequest{Name: "rx",
		NicMtu:    []*pb.NICMTUUpdate{{Ordinal: 0, Mtu: 9000}},
		NicQueues: []*pb.NICQueuesUpdate{{Ordinal: 0, Queues: 2}},
		NicRate:   []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 4}}}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	spec := loadStoredSpec(t, s, "rx")
	if a, b := spec.Network[0], spec.Network[1]; a.GetMtu() != 9000 || a.GetQueues() != 2 || a.GetRateMbSec() != 4 ||
		b.GetMtu() != 0 || b.GetQueues() != 0 || b.GetRateMbSec() != 0 {
		t.Fatalf("stored network = %+v, want MTU, queues and rate on entry 0 (A)", spec.Network)
	}
	x := ixInactive(t, fake)
	if interfaceMTU(t, x, ixMACA) != 9000 || interfaceMTU(t, x, ixMACB) != 0 {
		t.Errorf("want <mtu> 9000 on A only:\n%s", x)
	}
}

// Every request a stack deploy builds names spec entries, and leaves
// nic_by_list_position unset, so an owner of any build reads it the same: a
// compose file's MTU for its first NIC reaches A, whose entry is index 0,
// although A is at position 1 of the NIC list.
//
// Mutation: set the field in either builder — red.
func TestStackUpdateRequestsNameSpecEntries(t *testing.T) {
	desired := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "a", RateMbSec: 2}}}
	if limitUpdateFromDesired("vm", desired, []string{compose.NICRateFieldPrefix + "0"}).GetNicByListPosition() {
		t.Error("limitUpdateFromDesired sets nic_by_list_position")
	}

	s, fake := ixReattached(t, "web")
	want := loadStoredSpec(t, s, "rx")
	want.Network[0].Mtu = 9000
	if err := s.reconfigureWithRestart(adminCtx(), "rx", want, compose.ChangePlan{TuningRedefine: true}); err != nil {
		t.Fatalf("reconfigureWithRestart: %v", err)
	}
	spec := loadStoredSpec(t, s, "rx")
	if spec.Network[0].GetMtu() != 9000 || spec.Network[1].GetMtu() != 0 {
		t.Fatalf("stored network = %+v, want the file's MTU on entry 0 (A)", spec.Network)
	}
	if got := interfaceMTU(t, ixInactive(t, fake), ixMACA); got != 9000 {
		t.Errorf("A's <mtu> = %d, want 9000", got)
	}
}

// A stack VM's NIC list is its compose file's: --nic-mtu on a NIC the file
// does not list is refused, here the NIC attached again under a MAC no entry
// records, at position 1.
//
// Mutation: drop the stack refusal — an entry is made, red.
func TestUpdateVM_NICMTUOnAStackVMRefusesANICItsFileDoesNotList(t *testing.T) {
	s, _ := ixVM(t, "web", []corrosion.NICRecord{ixRow(ixMACA, "lan", 0), ixRow(ixMACC, "lan3", 2)},
		&pb.NetworkAttachment{Name: "lan", Model: "virtio", Mac: ixMACA})
	_, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{NicMtu: []*pb.NICMTUUpdate{{Ordinal: 1, Mtu: 9000}}}))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "set mtu: in the stack's compose file") {
		t.Fatalf("unlisted NIC on a stack VM: %v", err)
	}
	if n := len(loadStoredSpec(t, s, "rx").Network); n != 1 {
		t.Errorf("the refused update left %d entries, want 1", n)
	}
}

// Main's meaning is kept where the list ends: a position past the NIC list
// names the spec entry at that index when no live NIC carries it (B was
// detached, its entry kept). And a position nothing answers to is NotFound.
//
// Mutation: drop the past-the-list fallback — red.
func TestUpdateVM_AnIndexPastTheNICListNamesAnEntryNoNICCarries(t *testing.T) {
	s, _ := ixVM(t, "", []corrosion.NICRecord{ixRow(ixMACA, "lan", 0)},
		&pb.NetworkAttachment{Name: "lan", Model: "virtio", Mac: ixMACA},
		&pb.NetworkAttachment{Name: "lan2", Model: "virtio", Mac: ixMACB})
	if _, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{
		NicQueues: []*pb.NICQueuesUpdate{{Ordinal: 1, Queues: 2}}})); err != nil {
		t.Fatalf("nic_queues 1=2 on the detached NIC's entry: %v", err)
	}
	if got := loadStoredSpec(t, s, "rx").Network[1].GetQueues(); got != 2 {
		t.Errorf("B's entry queues = %d, want 2", got)
	}
	_, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{NicMtu: []*pb.NICMTUUpdate{{Ordinal: 2, Mtu: 9000}}}))
	if status.Code(err) != codes.NotFound {
		t.Errorf("--nic-mtu 2=: err %v, want NotFound", err)
	}
}

// Review m-1: a rate or queue count for a NIC with no spec entry (here C,
// attached after the create, with A's entry recording A's MAC) is refused
// naming the NIC by its number and MAC, and how to give it an entry; that
// route works, and then the rate is taken.
//
// Mutation: answer with main's message ("the VM declares 1 NIC(s)") — red.
func TestUpdateVM_ARateForANICWithNoEntrySaysHowToGiveItOne(t *testing.T) {
	s, _ := ixVM(t, "", []corrosion.NICRecord{ixRow(ixMACA, "lan", 0), ixRow(ixMACC, "lan3", 3)},
		&pb.NetworkAttachment{Name: "lan", Model: "virtio", Mac: ixMACA})
	_, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{NicRate: []*pb.NICRateUpdate{{Ordinal: 1, RateMbSec: 5}}}))
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "NIC 1 (MAC "+ixMACC+") has no spec entry to hold a rate") ||
		!strings.Contains(err.Error(), "lv update rx --nic-mtu 1=0") {
		t.Fatalf("rate on C: %v", err)
	}
	_, err = s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{NicQueues: []*pb.NICQueuesUpdate{{Ordinal: 1, Queues: 2}}}))
	if status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "has no spec entry to hold a queue count") {
		t.Fatalf("queues on C: %v", err)
	}
	if _, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{NicMtu: []*pb.NICMTUUpdate{{Ordinal: 1, Mtu: 0}}})); err != nil {
		t.Fatalf("--nic-mtu 1=0: %v", err)
	}
	if _, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{NicRate: []*pb.NICRateUpdate{{Ordinal: 1, RateMbSec: 5}}})); err != nil {
		t.Fatalf("the rate once C has an entry: %v", err)
	}
	if e := loadStoredSpec(t, s, "rx").Network; len(e) != 2 || !strings.EqualFold(e[1].GetMac(), ixMACC) || e[1].GetRateMbSec() != 5 {
		t.Errorf("stored network = %+v, want C's entry with rate 5", e)
	}
}

// ownerSpy is an owner a forwarded UpdateVM reaches, answering Ping with or
// without nic_list_position.
type ownerSpy struct {
	pb.LiteVirtClient
	listPosition bool
	updates      []*pb.UpdateVMRequest
}

func (o *ownerSpy) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	return &pb.PingResponse{NicListPosition: o.listPosition}, nil
}

func (o *ownerSpy) UpdateVM(_ context.Context, r *pb.UpdateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	o.updates = append(o.updates, r)
	return &pb.VM{Name: r.GetName()}, nil
}

func ixForward(t *testing.T, s *Server, listPosition bool, req *pb.UpdateVMRequest) (*ownerSpy, error) {
	t.Helper()
	spy := &ownerSpy{listPosition: listPosition}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return spy, func() {}, nil }
	_, err := s.UpdateVM(adminCtx(), req)
	return spy, err
}

// An owner whose Ping lacks nic_list_position reads every NIC number as a
// spec index, which can name another NIC: an update naming NICs by position
// is refused for it, naming the owner to upgrade, and nothing is forwarded.
// An owner that has the bit gets the request as it is, and one that names no
// NIC goes to an older owner unchanged.
//
// Mutation: forward to an older owner regardless — red.
func TestUpdateVM_AnOlderOwnerIsRefusedNICPositions(t *testing.T) {
	s, _ := ixReattachedOn(t, "other-host", "")
	spy, err := ixForward(t, s, false, byPos(&pb.UpdateVMRequest{
		NicMtu: []*pb.NICMTUUpdate{{Ordinal: 0, Mtu: 9000}}}))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "owner other-host runs an older build") ||
		!strings.Contains(err.Error(), "upgrade other-host first") || len(spy.updates) != 0 {
		t.Errorf("older owner: err %v, %d forwarded; want FailedPrecondition naming the owner, nothing forwarded", err, len(spy.updates))
	}

	spy, err = ixForward(t, s, true, byPos(&pb.UpdateVMRequest{NicMtu: []*pb.NICMTUUpdate{{Ordinal: 0, Mtu: 9000}}}))
	if err != nil || len(spy.updates) != 1 || !spy.updates[0].GetNicByListPosition() || spy.updates[0].NicMtu[0].Ordinal != 0 {
		t.Errorf("an owner with the bit: %v, %v; want the request as sent", err, spy.updates)
	}

	req := byPos(&pb.UpdateVMRequest{})
	spy, err = ixForward(t, s, false, req)
	if err != nil || len(spy.updates) != 1 || !proto.Equal(spy.updates[0], req) {
		t.Errorf("no NIC named, older owner: forwarded %v (err %v), want the request unchanged", spy.updates, err)
	}
}

// Review m-4: the positions were resolved against the NIC list read before
// the stop and the VM lock; a NIC attached before the definition is built
// moves them, and the update is aborted, not applied to another NIC.
//
// Mutation: drop the recheck — the MTU lands although the list moved, red.
func TestUpdateVM_ANICListThatChangesUnderTheUpdateAbortsIt(t *testing.T) {
	s, _ := ixReattached(t, "")
	s.updateVMNICsHookForTest = func() {
		if err := corrosion.UpsertNIC(adminCtx(), s.db, ixRow(ixMACC, "lan3", 0)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.UpdateVM(adminCtx(), byPos(&pb.UpdateVMRequest{NicMtu: []*pb.NICMTUUpdate{{Ordinal: 0, Mtu: 9000}}}))
	if status.Code(err) != codes.Aborted {
		t.Fatalf("err = %v, want Aborted", err)
	}
	for _, e := range loadStoredSpec(t, s, "rx").Network {
		if e.GetMtu() != 0 {
			t.Errorf("entry %+v took an MTU", e)
		}
	}
}

// A NIC move finds the spec entry of a NIC attached again past the spec's
// end by its MAC. Main skipped any NIC whose ordinal was at or past
// len(spec.Network), so the NIC stayed on the flat bridge for good.
//
// Mutation: index the spec by the NIC's ordinal again — no retarget, red.
func TestPendingNICRetargets_FindsANICAttachedAgainPastTheSpecsEnd(t *testing.T) {
	spec := &pb.VMSpec{StackName: "prod", Network: []*pb.NetworkAttachment{
		{Name: "lan", Mac: ixMACA},
		{Name: "prod_db"}, // records no MAC: found by ordinal
	}}
	nics := []corrosion.NICRecord{
		{MAC: ixMACC, NetworkName: "prod_db", Ordinal: 1},
		{MAC: strings.ToUpper(ixMACA), NetworkName: "prod_lan", Ordinal: 4},
	}
	got := pendingNICRetargets(spec, nics)
	if len(got) != 1 || got[0].Ordinal != 4 || got[0].From != "prod_lan" || got[0].To != "lan" {
		t.Fatalf("retargets = %+v, want the NIC at ordinal 4 from prod_lan to lan", got)
	}
	// The MAC-less entry still moves its NIC by ordinal.
	spec.Network[1].Name = "db"
	if got := pendingNICRetargets(spec, nics); len(got) != 2 {
		t.Errorf("retargets = %+v, want both NICs", got)
	}
}

// Ping advertises nic_list_position, which a forwarding entry node reads to
// decide whether to send NIC numbers by list position.
//
// Mutation: advertise false — red.
func TestPing_AdvertisesNICListPosition(t *testing.T) {
	s := testServer(t)
	resp, err := s.Ping(context.Background(), &pb.PingRequest{})
	if err != nil || !resp.GetNicListPosition() {
		t.Fatalf("Ping = %v, %v; want nic_list_position", resp, err)
	}
}
