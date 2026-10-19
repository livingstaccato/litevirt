package grpcapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// writeStampedSeed puts a seed for name in dataDir, stamped for owner.
func writeStampedSeed(t *testing.T, dataDir, name, owner string) string {
	t.Helper()
	iso := filepath.Join(dataDir, "cloudinit", name+".iso")
	if err := os.MkdirAll(filepath.Dir(iso), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(iso, []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cloudinit.StampSeed(iso, owner); err != nil {
		t.Fatal(err)
	}
	return iso
}

// cdromSources lists the file of every CD-ROM in a definition.
func cdromSources(domXML string) []string {
	var out []string
	for _, chunk := range strings.Split(domXML, "<disk ")[1:] {
		if !strings.Contains(chunk, `device="cdrom"`) {
			continue
		}
		if i := strings.Index(chunk, `file="`); i >= 0 {
			rest := chunk[i+len(`file="`):]
			out = append(out, rest[:strings.Index(rest, `"`)])
		}
	}
	return out
}

// A promotion and a live restore define a new domain, and built it without
// the cloud-init seed CreateVM attaches. A seed on this host stamped for the
// VM (its name, its spec uuid) is attached as the create attaches it; one
// stamped for another VM of the name is not.
//
// Mutation: drop the seed from either builder — that builder's "stamped"
// case goes red; attach the file whatever its stamp — the "foreign" case
// goes red.
func TestNewDomainBuilders_AttachTheVMsStampedSeed(t *testing.T) {
	const uuid = "0b7c6a8e-1111-4c2d-9e0f-000000000001"
	for _, tc := range []struct {
		name  string
		owner string
		want  bool
	}{
		{"stamped", uuid, true},
		{"foreign", "0b7c6a8e-2222-4c2d-9e0f-000000000002", false},
	} {
		t.Run("promote/"+tc.name, func(t *testing.T) {
			s := testServer(t)
			fake := libvirtfake.New()
			s.virt = fake
			s.dataDir = t.TempDir()
			ctx := adminCtx()
			poolDir := t.TempDir()
			s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})
			specJSON, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Uuid: uuid, Cpu: 1, MemoryMib: 512,
				CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\n"}})
			if err := corrosion.InsertVM(ctx, s.db,
				corrosion.VMRecord{Name: "vm1", HostName: "dead-host", State: "running", Spec: string(specJSON)}, nil,
				[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host", Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "local"}},
			); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			seedReplica(t, poolDir, "", "vm1", "root", "20260101-000000", "raw", 1<<20)
			// A same-name takeover: the VM keeps its uuid. (A promotion to a
			// new name is a new VM with a fresh uuid, which no seed already
			// on the host is stamped for.)
			iso := writeStampedSeed(t, s.dataDir, "vm1", tc.owner)

			stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}
			if err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "vm1", TargetPool: "replica-pool", NoLocalize: true, Force: true}, stream); err != nil {
				t.Fatalf("PromoteReplica: %v", err)
			}
			checkSeed(t, fake.DefinedXML("vm1"), iso, tc.want)
		})

		t.Run("restore/"+tc.name, func(t *testing.T) {
			s := testServer(t)
			s.hostName = "host-a"
			fake := libvirtfake.New()
			s.virt = fake
			s.dataDir = t.TempDir()
			// A restore to the VM's own name (its row gone): it keeps its
			// uuid. (A restore beside it under a new name gets a fresh one.)
			spec, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Uuid: uuid, Cpu: 1, MemoryMib: 512,
				CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\n"}})
			iso := writeStampedSeed(t, s.dataDir, "vm1", tc.owner)
			repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), string(spec))
			_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
				RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
				TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
			}, pb.RestoreLiveProgress_STARTED)
			x := fake.DefinedXML("vm1")
			cancel()
			<-done
			checkSeed(t, x, iso, tc.want)
		})
	}
}

func checkSeed(t *testing.T, domXML, iso string, want bool) {
	t.Helper()
	got := cdromSources(domXML)
	has := len(got) == 1 && got[0] == iso
	if want && !has {
		t.Fatalf("want the seed %s as the only CD-ROM, got %v:\n%s", iso, got, domXML)
	}
	if !want && len(got) != 0 {
		t.Fatalf("a seed stamped for another VM was attached: %v\n%s", got, domXML)
	}
}
