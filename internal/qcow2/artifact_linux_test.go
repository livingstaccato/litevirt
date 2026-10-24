//go:build linux

package qcow2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func artifactWriterFixture(t *testing.T) (string, string, *Options) {
	t.Helper()
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	disk := filepath.Join(dir, "disk.qcow2")
	if err := Create(base, 4<<20, nil); err != nil {
		t.Fatal(err)
	}
	return base, disk, &Options{Artifact: &ArtifactOptions{Ownership: []byte("original-physical-object"), TemporaryPath: filepath.Join(dir, ".planned-original.tmp")}}
}

func TestArtifactOwnedPublicationPreservesUnknownObjects(t *testing.T) {
	for _, fault := range []string{"temp-unlink", "directory-sync", "close", "foreign-final"} {
		t.Run(fault, func(t *testing.T) {
			base, disk, opts := artifactWriterFixture(t)
			oldUnlink, oldSync, oldClose := artifactTempUnlink, artifactDirectorySync, artifactClose
			defer func() { artifactTempUnlink, artifactDirectorySync, artifactClose = oldUnlink, oldSync, oldClose }()
			if fault == "temp-unlink" || fault == "foreign-final" {
				artifactTempUnlink = func(int, string) error {
					if fault == "foreign-final" {
						if err := os.Rename(disk, disk+".original"); err != nil {
							t.Fatal(err)
						}
						if err := Create(disk, 8<<20, nil); err != nil {
							t.Fatal(err)
						}
					}
					return unix.EACCES
				}
			} else if fault == "directory-sync" {
				artifactDirectorySync = func(*os.File) error { return unix.EIO }
			} else {
				artifactClose = func(f *os.File) error {
					err := f.Close()
					if err != nil {
						return err
					}
					return unix.EIO
				}
			}
			err := CreateWithBacking(disk, base, 4<<20, opts)
			if !errors.Is(err, ErrArtifactUnknown) {
				t.Fatalf("post-visible failure did not return UNKNOWN: %v", err)
			}
			if fault == "foreign-final" {
				info, err := Info(disk)
				if err != nil || info.VirtualSize != 8<<20 {
					t.Fatal("foreign final was deleted or changed")
				}
				disk = disk + ".original"
			}
			f, err := os.Open(disk)
			if err != nil {
				t.Fatal("visible original was rolled back", err)
			}
			defer f.Close()
			marker, err := ReadArtifactOwnership(f)
			if err != nil || !bytes.Equal(marker, []byte("original-physical-object")) {
				t.Fatal("original descriptor ownership lost", err)
			}
			if err := CheckFile(f); err != nil {
				t.Fatal(err)
			}
			if fault == "temp-unlink" || fault == "foreign-final" {
				dir, err := OpenArtifactDirectory(filepath.Dir(disk))
				if err != nil {
					t.Fatal(err)
				}
				defer dir.Close()
				if f, err := OpenArtifactFileAt(dir, filepath.Base(disk)); err == nil {
					f.Close()
					t.Fatal("surviving second link was accepted as normal one-link artifact")
				}
			}
		})
	}
}

func TestArtifactOwnedPrepublicationFailuresPreservePlanAndDestination(t *testing.T) {
	for _, fault := range []string{"unsupported-xattr", "file-sync", "existing-final", "existing-temp", "symlink-temp"} {
		t.Run(fault, func(t *testing.T) {
			base, disk, opts := artifactWriterFixture(t)
			oldSet, oldSync := artifactSetOwnership, artifactFileSync
			defer func() { artifactSetOwnership, artifactFileSync = oldSet, oldSync }()
			var destination []byte
			switch fault {
			case "unsupported-xattr":
				artifactSetOwnership = func(int, []byte) error { return unix.EOPNOTSUPP }
			case "file-sync":
				artifactFileSync = func(*os.File) error { return unix.EIO }
			case "existing-final":
				if err := Create(disk, 8<<20, nil); err != nil {
					t.Fatal(err)
				}
				destination, _ = os.ReadFile(disk)
			case "existing-temp":
				if err := os.WriteFile(opts.Artifact.TemporaryPath, []byte("foreign-temp"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink-temp":
				if err := os.Symlink(base, opts.Artifact.TemporaryPath); err != nil {
					t.Fatal(err)
				}
			}
			if err := CreateWithBacking(disk, base, 4<<20, opts); err == nil {
				t.Fatal("unsafe owned publication succeeded")
			}
			if fault == "existing-final" {
				after, err := os.ReadFile(disk)
				if err != nil || !bytes.Equal(destination, after) {
					t.Fatal("existing final was changed")
				}
			} else if _, err := os.Lstat(disk); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("prepublication refusal made a disk visible")
			}
			if fault == "existing-temp" {
				b, err := os.ReadFile(opts.Artifact.TemporaryPath)
				if err != nil || string(b) != "foreign-temp" {
					t.Fatal("foreign temp was changed")
				}
			}
		})
	}
}

func TestArtifactStandaloneInspectionUsesActualHeader(t *testing.T) {
	for _, kind := range []string{"layered", "external-data", "backing-offset-only", "unknown-extension", "encryption", "snapshot-offset"} {
		t.Run(kind, func(t *testing.T) {
			base, disk, _ := artifactWriterFixture(t)
			if kind == "layered" {
				if err := CreateWithBacking(disk, base, 4<<20, nil); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := Create(disk, 4<<20, nil); err != nil {
					t.Fatal(err)
				}
				f, err := os.OpenFile(disk, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				h, err := readHeader(f)
				if err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "external-data":
					h.IncompatibleFeatures = 1 << 2
				case "backing-offset-only":
					h.BackingFileOffset = 128
				case "encryption":
					h.CryptMethod = 0xffffffff
				case "snapshot-offset":
					h.SnapshotsOffset = 65536
				case "unknown-extension":
					if _, err := writeHeaderExtension(f, 104, 0x44415441, []byte("external.raw")); err != nil {
						t.Fatal(err)
					}
				}
				if err := writeHeader(f, h); err != nil {
					t.Fatal(err)
				}
				f.Close()
			}
			f, err := os.Open(disk)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := InspectArtifactFile(f, true); err == nil {
				t.Fatal("non-standalone/unsupported actual header accepted")
			}
		})
	}
}

func TestArtifactOwnedRefusesDirectoryWritableByOtherOwners(t *testing.T) {
	base, disk, opts := artifactWriterFixture(t)
	if err := os.Chmod(filepath.Dir(disk), 0777); err != nil {
		t.Fatal(err)
	}
	if err := CreateWithBacking(disk, base, 4<<20, opts); err == nil {
		t.Fatal("uncontrolled directory permitted owned effect")
	}
	if _, err := os.Stat(opts.Artifact.TemporaryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsupported directory created temp")
	}
}
