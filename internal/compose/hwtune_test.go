package compose

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirt"
)

const tuneYAML = `name: tune
images:
  img:
    source: file:///dev/null
vms:
  db:
    image: img
    cpu: 4
    disks:
      root:
        size: 10G
        discard: on
        detect_zeroes: unmap
        iotune:
          read_bytes_sec: 50M
          write_iops_sec: 500
          write_iops_sec_max: 2000
          burst_seconds: 10
      data:
        size: 20G
    network:
      - name: lan
        queues: auto
      - name: back
        queues: 3
`

func TestParse_DiskAndNICTuningReachTheSpec(t *testing.T) {
	f, err := ParseBytes([]byte(tuneYAML))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	vm := f.VMs["db"]
	spec, err := BuildVMSpec("db", "db", &vm, f)
	if err != nil {
		t.Fatal(err)
	}
	root, data := spec.Disks[0], spec.Disks[1]
	if root.Name != "root" || root.Discard != "unmap" || root.DetectZeroes != "unmap" {
		t.Errorf("root = %+v, want discard on normalized to unmap and detect_zeroes unmap", root)
	}
	if got := IOTuneFromSpec(root.Io); got != (libvirt.IOTune{ReadBytesSec: 50 << 20, WriteIopsSec: 500, WriteIopsSecMax: 2000, BurstSec: 10}) {
		t.Errorf("root iotune = %+v", got)
	}
	if data.Discard != "" || data.Io != nil {
		t.Errorf("data disk names no tuning but carries %+v", data)
	}
	if spec.Network[0].Queues != 4 || spec.Network[1].Queues != 3 {
		t.Errorf("queues = %d, %d; want auto at 4 vcpus = 4, and 3", spec.Network[0].Queues, spec.Network[1].Queues)
	}
}

func TestParse_TuningValidation(t *testing.T) {
	for name, tc := range map[string]struct{ old, new, want string }{
		"total with read":   {"read_bytes_sec: 50M", "total_bytes_sec: 50M\n          read_bytes_sec: 1M", "cannot be combined"},
		"bad discard":       {"discard: on", "discard: sometimes", "want unmap or ignore"},
		"zeroes no discard": {"discard: on", "discard: off", "detect_zeroes unmap needs discard unmap"},
		"too many queues":   {"queues: 3", "queues: 99", "queues 99"},
		"unknown iotune":    {"write_iops_sec: 500", "write_iops: 500", `unknown field "write_iops"`},
		"bad rate":          {"read_bytes_sec: 50M", "read_bytes_sec: fast", "invalid byte rate"},
	} {
		_, err := ParseBytes([]byte(strings.Replace(tuneYAML, tc.old, tc.new, 1)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want one containing %q", name, err, tc.want)
		}
	}
	// queues on a model that has no multiqueue.
	y := strings.Replace(tuneYAML, "      - name: back\n", "      - name: back\n        model: e1000\n", 1)
	if _, err := ParseBytes([]byte(y)); err == nil || !strings.Contains(err.Error(), "needs the virtio model") {
		t.Errorf("queues on e1000: %v", err)
	}
}

func tunedStored() *pb.VMSpec {
	s := baseSpec()
	s.Disks[0].Discard = "unmap"
	s.Disks[0].Io = &pb.DiskIOLimits{ReadIopsSec: 100}
	s.Network[0].Queues = 4
	return s
}

func desiredFrom(mut func(*pb.VMSpec)) *pb.VMSpec {
	d := baseSpec()
	mut(d)
	return d
}

func TestClassify_TuningUnsetInheritsStored(t *testing.T) {
	p := Classify(baseSpec(), tunedStored(), StoredDisksFromSpec(tunedStored()))
	if p.Max() != ActionNoChange || p.TuningRedefine {
		t.Fatalf("compose that names no tuning against a tuned VM: %v %+v", p.Max(), p)
	}
}

func TestClassify_IOTuneChangeIsLive(t *testing.T) {
	d := desiredFrom(func(s *pb.VMSpec) { s.Disks[0].Io = &pb.DiskIOLimits{ReadIopsSec: 200} })
	p := Classify(d, tunedStored(), StoredDisksFromSpec(tunedStored()))
	if p.Max() != ActionLive || len(p.MetadataChanges) != 1 || p.MetadataChanges[0].Field != "disk_io" || p.TuningRedefine {
		t.Fatalf("an iotune change: %v %+v", p.Max(), p)
	}
	// The same limits again, and an empty iotune against an untuned disk, are no change.
	same := desiredFrom(func(s *pb.VMSpec) { s.Disks[0].Io = &pb.DiskIOLimits{ReadIopsSec: 100} })
	if p := Classify(same, tunedStored(), StoredDisksFromSpec(tunedStored())); p.Max() != ActionNoChange {
		t.Errorf("unchanged iotune: %v", p.Max())
	}
	empty := desiredFrom(func(s *pb.VMSpec) { s.Disks[0].Io = &pb.DiskIOLimits{} })
	if p := Classify(empty, baseSpec(), StoredDisksFromSpec(baseSpec())); p.Max() != ActionNoChange {
		t.Errorf("empty iotune against an untuned disk: %v", p.Max())
	}
	// An empty iotune against a throttled disk clears it.
	if p := Classify(empty, tunedStored(), StoredDisksFromSpec(tunedStored())); p.Max() != ActionLive {
		t.Errorf("empty iotune against a throttled disk: %v, want live (a clear)", p.Max())
	}
}

func TestClassify_DiscardAndQueuesNeedARedefine(t *testing.T) {
	d := desiredFrom(func(s *pb.VMSpec) { s.Disks[0].Discard = "ignore" })
	p := Classify(d, tunedStored(), StoredDisksFromSpec(tunedStored()))
	if p.Max() != ActionRestart || !p.TuningRedefine || len(p.NotReconfigurable) != 0 {
		t.Errorf("discard change: %v %+v (must be a restart-class change, never a recreate)", p.Max(), p)
	}
	q := desiredFrom(func(s *pb.VMSpec) { s.Network[0].Queues = 8 })
	if p := Classify(q, tunedStored(), StoredDisksFromSpec(tunedStored())); p.Max() != ActionRestart || !p.TuningRedefine {
		t.Errorf("queues change: %v", p.Max())
	}
	// One queue and none are the same thing.
	one := desiredFrom(func(s *pb.VMSpec) { s.Network[0].Queues = 1 })
	if p := Classify(one, baseSpec(), StoredDisksFromSpec(baseSpec())); p.Max() != ActionNoChange {
		t.Errorf("queues 1 against no queues: %v", p.Max())
	}
	// Turning multiqueue off is a change.
	if p := Classify(one, tunedStored(), StoredDisksFromSpec(tunedStored())); p.Max() != ActionRestart {
		t.Errorf("queues 1 against 4 queues: %v", p.Max())
	}
}

func TestApplyTuning(t *testing.T) {
	spec := &pb.VMSpec{
		Disks:   []*pb.DiskSpec{{Name: "root", Discard: "unmap", Io: &pb.DiskIOLimits{TotalIopsSec: 9}}, {Name: "data"}},
		Network: []*pb.NetworkAttachment{{Name: "a", Mac: "52:54:00:00:00:01", Queues: 2}, {Name: "b", Queues: 6}},
	}
	disks := []libvirt.DiskConfig{{Name: "root"}, {Name: "data"}, {Name: "hot"}, {Name: "iso", IsISO: true}}
	ApplyDiskTuning(disks, spec)
	if disks[0].Discard != "unmap" || disks[0].IOTune.TotalIopsSec != 9 || disks[1].Discard != "" || disks[2].Discard != "" {
		t.Errorf("disks = %+v", disks)
	}
	// Matched by MAC when the spec recorded one, whatever the order; by position
	// only onto a spec entry that recorded no MAC; a NIC the spec does not hold
	// at its position is another device.
	nets := []libvirt.NetworkConfig{{MAC: "52:54:00:00:00:99"}, {MAC: "52:54:00:00:00:01"}}
	ApplyNICTuning(nets, spec)
	if nets[1].Queues != 2 || nets[0].Queues != 0 {
		t.Errorf("reordered nets = %+v, want the ...01 NIC at 2 queues by its MAC and the stranger at none", nets)
	}
	nets = []libvirt.NetworkConfig{{MAC: "52:54:00:00:00:01"}, {MAC: "52:54:00:00:00:99"}}
	ApplyNICTuning(nets, spec)
	if nets[0].Queues != 2 || nets[1].Queues != 6 {
		t.Errorf("nets = %+v, want 2 by MAC and 6 by position (its spec entry recorded no MAC)", nets)
	}
	// A clone's NICs are the spec's own, in order, under fresh MACs.
	nets = []libvirt.NetworkConfig{{MAC: "52:54:00:00:77:01"}, {MAC: "52:54:00:00:77:02"}}
	ApplyNICTuningByPosition(nets, spec)
	if nets[0].Queues != 2 || nets[1].Queues != 6 {
		t.Errorf("by position nets = %+v", nets)
	}
	if ResolveAutoQueues(1) != 0 || ResolveAutoQueues(4) != 4 || ResolveAutoQueues(64) != 8 {
		t.Error("auto queues is one per vCPU up to 8, none for one vCPU")
	}
}

// A NIC hot-plugged after the create has a vm_interfaces row but no spec entry,
// and a compose NIC without `mac:` has a spec entry that recorded none. Matching
// by ordinal keeps the tuned NIC's queues when another NIC comes or goes.
//
// Mutation: drop the ordinal branch — the hot-plug case goes red.
func TestApplyNICTuning_SurvivesHotPlugAndDetachByOrdinal(t *testing.T) {
	spec := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "a", Queues: 4}}} // no MAC recorded
	// Hot-plug: the DB has two NICs (ordinals 1, 2 -> SpecOrdinal 1, 2), one more than the spec.
	nets := []libvirt.NetworkConfig{{MAC: "52:54:00:00:00:01", SpecOrdinal: 1}, {MAC: "52:54:00:00:00:02", SpecOrdinal: 2}}
	ApplyNICTuning(nets, spec)
	if nets[0].Queues != 4 || nets[1].Queues != 0 {
		t.Errorf("after a hot-plug nets = %+v, want NIC 1 keeps 4 queues and the new NIC none", nets)
	}
	// The tuned NIC detached and another stays: it is not given NIC 1's queues.
	nets = []libvirt.NetworkConfig{{MAC: "52:54:00:00:00:02", SpecOrdinal: 2}}
	spec.Network[0].Mac = "52:54:00:00:00:01"
	ApplyNICTuning(nets, spec)
	if nets[0].Queues != 0 {
		t.Errorf("a different NIC took the detached NIC's queues: %+v", nets)
	}
}

// One name rule everywhere: an empty disk name is "root".
func TestDiskKeyAndEmptyNameMatching(t *testing.T) {
	if DiskKey("") != "root" || DiskKey("data") != "data" {
		t.Error("DiskKey")
	}
	stored := &pb.VMSpec{Disks: []*pb.DiskSpec{{Name: "", Bus: "virtio", Discard: "unmap"}}}
	same := &pb.VMSpec{Disks: []*pb.DiskSpec{{Name: "root", Bus: "virtio", Discard: "unmap"}}}
	if p := Classify(same, stored, StoredDisksFromSpec(stored)); p.TuningRedefine {
		t.Errorf("a stored empty-name disk is root: an unchanged discard was seen as a change: %+v", p)
	}
	d := &pb.VMSpec{Disks: []*pb.DiskSpec{{Name: "root", Bus: "virtio", Discard: "ignore"}}}
	if p := Classify(d, stored, StoredDisksFromSpec(stored)); !p.TuningRedefine {
		t.Errorf("a stored empty-name disk is root: the discard change was not seen: %+v", p)
	}
}

// A NIC rendered with another model than its spec entry records (a NIC of a
// stack VM swapped under its MAC, whose entry the attach leaves as the
// compose file wrote it) keeps only the entry's tuning its rendered model
// can take: no MTU and no multiqueue on an e1000. A NIC rendered with the
// entry's own model keeps the entry's tuning as it is, so a define still
// refuses an MTU recorded for an e1000.
//
// Mutation: copy the entry's tuning whatever the rendered model — the
// "virtio entry, e1000 NIC" case goes red.
func TestApplyNICTuning_ANICOfAnotherModelKeepsOnlyWhatItCanTake(t *testing.T) {
	const mac = "52:54:00:aa:cc:01"
	for _, tc := range []struct {
		name, entry, rendered string
		wantMTU, wantQueues   int
	}{
		{"virtio entry, e1000 NIC", "virtio", "e1000", 0, 0},
		{"virtio entry, virtio NIC", "virtio", "virtio", 9000, 4},
		{"unset entry, virtio NIC", "", "", 9000, 4},
		{"e1000 entry, virtio NIC", "e1000", "virtio", 9000, 4},
		{"e1000 entry, e1000 NIC", "e1000", "e1000", 9000, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", Model: tc.entry, Mac: mac, Mtu: 9000, Queues: 4}}}
			nets := []libvirt.NetworkConfig{{Bridge: "lan", Model: tc.rendered, MAC: mac, SpecOrdinal: 1}}
			ApplyNICTuning(nets, spec)
			if nets[0].MTU != tc.wantMTU || nets[0].Queues != tc.wantQueues {
				t.Fatalf("MTU %d queues %d, want %d and %d", nets[0].MTU, nets[0].Queues, tc.wantMTU, tc.wantQueues)
			}
		})
	}
}
