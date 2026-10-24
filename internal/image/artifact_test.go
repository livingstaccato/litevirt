//go:build linux

package image

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/qcow2"
	"golang.org/x/sys/unix"
)

func artifactQEMU(t *testing.T, args ...string) []byte {
	t.Helper()
	tool := os.Getenv("LITEVIRT_ARTIFACT_QEMU")
	if !filepath.IsAbs(tool) {
		t.Fatal("SETUP: immutable wrapper must supply pinned absolute qemu-img")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, tool, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("SETUP qemu-img %v: %v: %s", args, err, out)
	}
	return out
}

// Removing descriptor ownership stamping must fail after a real, externally
// checked disk exists. The initial RED binding deliberately uses the existing
// unowned effect; the approved owned entry replaces only that binding for GREEN.
func TestArtifactOverlayPersistsPhysicalOwnership(t *testing.T) {
	s := NewStore(t.TempDir())
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(s.imageDir, "base-stage.tmp")
	if err := qcow2.Create(base, 4<<20, nil); err != nil {
		t.Fatal(err)
	}
	digest, err := FileDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := s.Publish("base", base, digest)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.PrepareArtifactOverlay(artifactRecord(digest), "owned-vm", "root", "base", digest)
	if err != nil {
		t.Fatal(err)
	}
	disk := plan.Locator
	err = s.CreateArtifactOverlayDisk(plan)
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Format  string `json:"format"`
		Backing string `json:"backing-filename"`
		Size    uint64 `json:"virtual-size"`
	}
	if err := json.Unmarshal(artifactQEMU(t, "info", "--output=json", disk), &info); err != nil {
		t.Fatal(err)
	}
	if info.Format != "qcow2" || info.Backing != pub.Path || info.Size != 4<<20 {
		t.Fatalf("real overlay differs: %+v", info)
	}
	artifactQEMU(t, "check", disk)
	f, err := os.OpenFile(disk, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil || st.Nlink != 1 {
		t.Fatalf("real disk identity/link precondition: %+v %v", st, err)
	}
	t.Logf("REAL_QCOW2_EFFECT verified format=%s size=%d backing=%s inode=%d links=%d; native-authority=false", info.Format, info.Size, info.Backing, st.Ino, st.Nlink)
	marker := make([]byte, 1024)
	n, err := unix.Fgetxattr(int(f.Fd()), "user.litevirt.artifact", marker)
	if err != nil || n == 0 {
		t.Fatalf("PHYSICAL_OWNERSHIP_MISSING: completed real qcow2 has no descriptor-bound artifact ownership: bytes=%d err=%v", n, err)
	}
}

func artifactRecord(digest string) contract.ArtifactRecord {
	return contract.ArtifactRecord{ID: "artifact-disk-1", Key: "root", Kind: "disk", Backend: "local", ObjectID: "object-disk-1", ResourceUID: "resource-original", Incarnation: "incarnation-original", OperationID: "operation-original", Origin: contract.ExecutorReference{Generation: 1, Decision: contract.HistoryReference{Sequence: 12, Digest: strings.Repeat("a", 64)}}, HostUID: "host-original", HostIncarnation: "host-incarnation-original", PoolUID: "pool-original", ImageDigest: digest, State: "planned"}
}

func artifactFixture(t *testing.T) (*Store, ArtifactDiskPlan) {
	t.Helper()
	s := NewStore(t.TempDir())
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	publishArtifactBase(t, s, "base", 4<<20, "")
	digest, _ := RecordedDigest(s.ImagePath("base"))
	p, err := s.PrepareArtifactOverlay(artifactRecord(digest), "owned-vm", "root", "base", digest)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func publishArtifactBase(t *testing.T, s *Store, name string, size uint64, backing string) Published {
	t.Helper()
	f, err := os.CreateTemp(s.imageDir, "stage-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	os.Remove(path)
	if backing == "" {
		err = qcow2.Create(path, size, nil)
	} else {
		err = qcow2.CreateWithBacking(path, backing, size, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	digest, err := FileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Publish(name, path, digest)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestArtifactAliasMovementAndPhysicalReopen(t *testing.T) {
	s, p := artifactFixture(t)
	publishArtifactBase(t, s, "base", 8<<20, "")
	if s.ImagePath("base") == p.BaseLocator {
		t.Fatal("alias movement setup failed")
	}
	if err := s.CreateArtifactOverlayDisk(p); err != nil {
		t.Fatal(err)
	}
	artifactQEMU(t, "check", p.Locator)
	fresh := NewStore(filepath.Dir(s.imageDir))
	a, err := fresh.ObserveArtifactDisk(p)
	if err != nil || a.ID != "artifact-disk-1" || a.ObjectID != "object-disk-1" || a.ResourceUID != "resource-original" || a.Incarnation != "incarnation-original" || a.Locator != p.Locator || a.State != "active" {
		t.Fatalf("same physical artifact was not recovered: %+v %v", a, err)
	}
	if err := s.RemoveImageFile("base", p.BaseLocator); err == nil {
		t.Fatal("original backing was pruned")
	}
	if err := s.RemoveDeletedImageFile("base", p.BaseLocator); err == nil {
		t.Fatal("original backing was deleted")
	}
}

func TestArtifactLayeredBaseRefusesBeforeAnyDiskOrPin(t *testing.T) {
	s, p := artifactFixture(t)
	top := publishArtifactBase(t, s, "layered", 4<<20, p.BaseLocator)
	digest, _ := RecordedDigest(top.Path)
	if _, err := s.PrepareArtifactOverlay(artifactRecord(digest), "layered-vm", "root", "layered", digest); err == nil {
		t.Fatal("real layered base was admitted")
	}
	if Pinned(top.Path) {
		t.Fatal("unsupported layered top was pinned as sufficient")
	}
	if entries, err := os.ReadDir(s.diskDir); err != nil || len(entries) != 0 {
		t.Fatal("layer refusal created disk artifacts")
	}
	if err := os.Remove(p.BaseLocator); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareArtifactOverlay(artifactRecord(digest), "layered-vm", "root", "layered", digest); err == nil {
		t.Fatal("missing lower layer became admitted content")
	}
}

func TestArtifactChangedBaseBytesRefuseBeforeEffects(t *testing.T) {
	s, p := artifactFixture(t)
	f, err := os.OpenFile(p.BaseLocator, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteAt([]byte{1}, 4096)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateArtifactOverlayDisk(p); err == nil {
		t.Fatal("changed actual bytes under unchanged provenance were accepted")
	}
	if Pinned(p.BaseLocator) {
		t.Fatal("changed base was pinned")
	}
	if _, err = os.Stat(p.Locator); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("changed base produced a disk")
	}
}

func TestArtifactObservationRefusesForeignPhysicalObjects(t *testing.T) {
	for _, kind := range []string{"unmarked-replacement", "foreign-marker", "symlink", "hardlink", "missing-marker", "malformed-marker", "wrong-backing"} {
		t.Run(kind, func(t *testing.T) {
			s, p := artifactFixture(t)
			if err := s.CreateArtifactOverlayDisk(p); err != nil {
				t.Fatal(err)
			}
			original := p.Locator + ".original"
			if kind == "hardlink" {
				if err := os.Link(p.Locator, original); err != nil {
					t.Fatal(err)
				}
			} else if kind == "missing-marker" {
				if err := unix.Removexattr(p.Locator, "user.litevirt.artifact"); err != nil {
					t.Fatal(err)
				}
			} else if kind == "malformed-marker" {
				if err := unix.Setxattr(p.Locator, "user.litevirt.artifact", []byte("{}"), 0); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(p.Locator, original); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					if err := os.Symlink(original, p.Locator); err != nil {
						t.Fatal(err)
					}
				} else {
					backing := p.BaseLocator
					if kind == "wrong-backing" {
						backing = publishArtifactBase(t, s, "other", 4<<20, "").Path
					}
					if err := qcow2.CreateWithBacking(p.Locator, backing, 4<<20, nil); err != nil {
						t.Fatal(err)
					}
					if kind == "foreign-marker" || kind == "wrong-backing" {
						a := p.Artifact
						if kind == "foreign-marker" {
							a.ResourceUID = "foreign-resource"
							a.ObjectID = "foreign-object"
						}
						if err := unix.Setxattr(p.Locator, "user.litevirt.artifact", artifactOwnership(a), unix.XATTR_CREATE); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			before, err := os.ReadFile(p.Locator)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.ObserveArtifactDisk(p); err == nil {
				t.Fatal("uncertain physical ownership was recovered")
			}
			after, err := os.ReadFile(p.Locator)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("uncertain observation changed/deleted another object")
			}
		})
	}
}

func TestArtifactFrozenArgumentsRefuseBeforeDisk(t *testing.T) {
	for _, field := range []string{"size", "locator", "temp-directory", "base", "digest", "vm", "disk", "object"} {
		t.Run(field, func(t *testing.T) {
			s, p := artifactFixture(t)
			switch field {
			case "size":
				p.VirtualSize++
			case "locator":
				p.Locator += ".other"
			case "temp-directory":
				p.TemporaryLocator = filepath.Join(s.imageDir, ".other.tmp")
			case "base":
				p.BaseLocator = filepath.Join(s.imageDir, "foreign.qcow2")
			case "digest":
				p.ImageDigest = strings.Repeat("b", 64)
			case "vm":
				p.VMName = "other"
			case "disk":
				p.DiskName = "other"
			case "object":
				p.Artifact.ObjectID = ""
			}
			if err := s.CreateArtifactOverlayDisk(p); err == nil {
				t.Fatal("invalid frozen arguments issued a disk")
			}
			entries, err := os.ReadDir(s.diskDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("refused plan changed disk directory: %v %v", entries, err)
			}
		})
	}
}

func TestArtifactOwnershipBindsEveryImmutableIdentity(t *testing.T) {
	for _, field := range []string{"id", "key", "object", "uid", "incarnation", "operation", "host", "host-incarnation", "pool", "origin-generation", "origin-sequence", "origin-digest"} {
		t.Run(field, func(t *testing.T) {
			s, p := artifactFixture(t)
			if err := s.CreateArtifactOverlayDisk(p); err != nil {
				t.Fatal(err)
			}
			changed := p
			switch field {
			case "id":
				changed.Artifact.ID = "other-artifact"
			case "key":
				changed.Artifact.Key = "other-key"
			case "object":
				changed.Artifact.ObjectID = "other-object"
			case "uid":
				changed.Artifact.ResourceUID = "other-resource"
			case "incarnation":
				changed.Artifact.Incarnation = "other-incarnation"
			case "operation":
				changed.Artifact.OperationID = "other-operation"
			case "host":
				changed.Artifact.HostUID = "other-host"
			case "host-incarnation":
				changed.Artifact.HostIncarnation = "other-host-incarnation"
			case "pool":
				changed.Artifact.PoolUID = "other-pool"
			case "origin-generation":
				changed.Artifact.Origin.Generation = 2
			case "origin-sequence":
				changed.Artifact.Origin.Decision.Sequence = 13
			case "origin-digest":
				changed.Artifact.Origin.Decision.Digest = strings.Repeat("b", 64)
			}
			if _, err := s.ObserveArtifactDisk(changed); err == nil {
				t.Fatal("physical marker failed to bind immutable identity", field)
			}
			if a, err := s.ObserveArtifactDisk(p); err != nil || a.ObjectID != "object-disk-1" {
				t.Fatal("refusal damaged original object", err)
			}
		})
	}
}

func TestArtifactPlannedTemporaryRemainsUnknownAndIntact(t *testing.T) {
	s, p := artifactFixture(t)
	if err := s.CreateArtifactOverlayDisk(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p.Locator, p.TemporaryLocator); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p.TemporaryLocator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveArtifactDisk(p); !IsArtifactUnknown(err) {
		t.Fatalf("identified temp promoted to completed/absent work: %v", err)
	}
	after, err := os.ReadFile(p.TemporaryLocator)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("planned uncertain temp was removed/changed")
	}
	if _, err := os.Stat(p.Locator); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("observation reallocated missing final")
	}
}

// A honestly hashed unsupported header must refuse before retention or disk
// work. Digest/provenance equality cannot substitute for format support.
func TestArtifactUnsupportedHeaderRefusesPreparationAndFrozenExecution(t *testing.T) {
	for _, stage := range []string{"prepare", "execute"} {
		for _, field := range []string{"encryption", "snapshot-offset"} {
			t.Run(stage+"/"+field, func(t *testing.T) {
				s, p := artifactFixture(t)
				base, err := os.ReadFile(p.BaseLocator)
				if err != nil {
					t.Fatal(err)
				}
				if field == "encryption" {
					binary.BigEndian.PutUint32(base[32:36], 0xffffffff)
				} else {
					binary.BigEndian.PutUint64(base[64:72], 65536)
				}
				tmp := filepath.Join(s.imageDir, "unsupported-stage.tmp")
				if err := os.WriteFile(tmp, base, 0600); err != nil {
					t.Fatal(err)
				}
				digest, err := FileDigest(tmp)
				if err != nil {
					t.Fatal(err)
				}
				pub, err := s.Publish("unsupported", tmp, digest)
				if err != nil {
					t.Fatal(err)
				}
				if recorded, ok := RecordedDigest(pub.Path); !ok || recorded != digest {
					t.Fatal("SETUP honest unsupported provenance missing")
				}
				if stage == "prepare" {
					if _, err := s.PrepareArtifactOverlay(artifactRecord(digest), "bad-vm", "root", "unsupported", digest); err == nil {
						t.Error("UNSUPPORTED_HEADER_ADMITTED: actual unsupported standalone header passed preparation")
					}
				} else {
					// Inert typed plan data, not a permission or certified assignment.
					p.ImageName = "unsupported"
					p.BaseLocator = pub.Path
					p.ImageDigest = digest
					p.Artifact.ImageDigest = digest
					if err := p.Validate(); err != nil {
						t.Fatal("SETUP frozen plan shape", err)
					}
					if err := s.CreateArtifactOverlayDisk(p); err == nil {
						t.Error("UNSUPPORTED_HEADER_EFFECT: actual unsupported header published a disk")
					}
				}
				if Pinned(pub.Path) {
					t.Error("unsupported header was pinned before refusal")
				}
				entries, err := os.ReadDir(s.diskDir)
				if err != nil || len(entries) != 0 {
					t.Errorf("unsupported header made disk/temp effects: %v %v", entries, err)
				}
			})
		}
	}
}

func TestArtifactPinFailuresPrecedeEveryDiskEffect(t *testing.T) {
	for _, phase := range []string{"file", "directory"} {
		t.Run(phase, func(t *testing.T) {
			s, p := artifactFixture(t)
			oldFile, oldDir := artifactPinFileSync, artifactPinDirectorySync
			defer func() { artifactPinFileSync, artifactPinDirectorySync = oldFile, oldDir }()
			if phase == "file" {
				artifactPinFileSync = func(*os.File) error { return errors.New("pin file sync refused") }
			} else {
				artifactPinDirectorySync = func(*os.File) error { return errors.New("pin directory sync refused") }
			}
			if err := s.CreateArtifactOverlayDisk(p); err == nil {
				t.Fatal("failed pin durability permitted disk effect")
			}
			entries, err := os.ReadDir(s.diskDir)
			if err != nil || len(entries) != 0 {
				t.Fatal("disk/temp created before durable pin")
			}
			if !Pinned(p.BaseLocator) {
				t.Fatal("uncertain permanent pin was removed")
			}
		})
	}
}

func TestArtifactBothRemovalOwnersSharePinLifetime(t *testing.T) {
	for _, method := range []string{"RemoveImageFile", "RemoveDeletedImageFile"} {
		for _, winner := range []string{"remove", "create"} {
			t.Run(method+"/"+winner, func(t *testing.T) {
				s, p := artifactFixture(t)
				publishArtifactBase(t, s, "base", 8<<20, "")
				oldChecked, oldSync := artifactRemovalChecked, artifactPinDirectorySync
				defer func() { artifactRemovalChecked, artifactPinDirectorySync = oldChecked, oldSync }()
				checked := make(chan struct{})
				release := make(chan struct{})
				contended := make(chan struct{}, 1)
				s.testHooks.nameContended = func(string) {
					select {
					case contended <- struct{}{}:
					default:
					}
				}
				remove := func() error {
					if method == "RemoveImageFile" {
						return s.RemoveImageFile("base", p.BaseLocator)
					}
					return s.RemoveDeletedImageFile("base", p.BaseLocator)
				}
				first, second := make(chan error, 1), make(chan error, 1)
				if winner == "remove" {
					artifactRemovalChecked = func(store *Store, kind string) {
						if store == s && kind == method {
							close(checked)
							<-release
						}
					}
					go func() { first <- remove() }()
					<-checked
					go func() { second <- s.CreateArtifactOverlayDisk(p) }()
				} else {
					artifactPinDirectorySync = func(f *os.File) error {
						if err := f.Sync(); err != nil {
							return err
						}
						close(checked)
						<-release
						return nil
					}
					go func() { first <- s.CreateArtifactOverlayDisk(p) }()
					<-checked
					go func() { second <- remove() }()
				}
				select {
				case <-contended:
				case <-time.After(3 * time.Second):
					close(release)
					t.Fatal("other owner did not take the same Store name lock")
				}
				close(release)
				if err := <-first; err != nil {
					t.Fatal("winning owner failed", err)
				}
				if err := <-second; err == nil {
					t.Fatal("losing owner bypassed removal/pin state")
				}
				if winner == "create" {
					artifactQEMU(t, "check", p.Locator)
					if _, err := os.Stat(p.BaseLocator); err != nil {
						t.Fatal("pinned backing disappeared")
					}
				} else if _, err := os.Stat(p.Locator); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("removed base allowed disk creation")
				}
			})
		}
	}
}
