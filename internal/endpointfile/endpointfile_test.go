package endpointfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRead_RoundTrip(t *testing.T) {
	p := filepath.Join(privDir(t), "endpoint")
	if err := Write(p, Endpoint{GRPCPort: 9443, PKIDir: "/etc/litevirt/pki"}); err != nil {
		t.Fatal(err)
	}
	e, err := Read(p)
	if err != nil || e != (Endpoint{GRPCPort: 9443, PKIDir: "/etc/litevirt/pki"}) {
		t.Fatalf("Read = %+v, %v", e, err)
	}
}

func TestRead_MissingIsNotExist(t *testing.T) {
	if _, err := Read(filepath.Join(privDir(t), "endpoint")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Read of a missing file = %v, want fs.ErrNotExist", err)
	}
}

// Nothing in a malformed file is trusted.
//
// Mutations: drop KnownFields, the port check, the absolute-path check or the
// size bound: the matching case red.
func TestRead_RefusesAMalformedFile(t *testing.T) {
	for name, body := range map[string]string{
		"not yaml":       "grpc_port: [\n",
		"empty":          "",
		"unknown key":    "grpc_port: 7443\npki_dir: /etc/litevirt/pki\nbind_password: x\n",
		"no port":        "pki_dir: /etc/litevirt/pki\n",
		"port too large": "grpc_port: 70000\npki_dir: /etc/litevirt/pki\n",
		"relative pki":   "grpc_port: 7443\npki_dir: pki\n",
		"no pki":         "grpc_port: 7443\n",
		"too large":      "grpc_port: 7443\npki_dir: /etc/litevirt/pki\n#" + strings.Repeat("x", maxSize),
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(privDir(t), "endpoint")
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if e, err := Read(p); err == nil || errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Read = %+v, %v; want a malformed-file error", e, err)
			}
		})
	}
}

func TestWrite_RefusesWhatReadWouldRefuse(t *testing.T) {
	p := filepath.Join(privDir(t), "endpoint")
	if err := Write(p, Endpoint{GRPCPort: 0, PKIDir: "/x"}); err == nil {
		t.Fatal("wrote port 0")
	}
	if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused write left a file: %v", err)
	}
}

// TestMain lets Read accept this test user's files: a test cannot create
// root's. TestRead_RefusesAFileNotOwnedByTheRequiredUser checks the owner.
func TestMain(m *testing.M) {
	SetReaderOwnerForTest(os.Getuid())
	os.Exit(m.Run())
}

// goodEndpoint writes a valid file the way the daemon does, in a fresh
// directory, and returns its path.
func goodEndpoint(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "run", "endpoint")
	if err := Write(p, Endpoint{GRPCPort: 7443, PKIDir: "/etc/litevirt/pki"}); err != nil {
		t.Fatal(err)
	}
	return p
}

// The file is a trust anchor (its pki_dir is the CA lv verifies against,
// before it sends a token): only a regular file owned by root and writable
// by root alone, in such a directory, is read.
//
// Mutations: skip the owner check, the mode check, the directory check, or
// follow a symlink: the matching case red.
func TestRead_RefusesAFileSomeoneElseCouldHaveWritten(t *testing.T) {
	cases := map[string]func(t *testing.T, p string){
		"owned by another user": func(t *testing.T, p string) {
			t.Cleanup(SetReaderOwnerForTest(os.Getuid() + 1))
		},
		"group-writable file": func(t *testing.T, p string) {
			if err := os.Chmod(p, 0o664); err != nil {
				t.Fatal(err)
			}
		},
		"other-writable file": func(t *testing.T, p string) {
			if err := os.Chmod(p, 0o646); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable directory": func(t *testing.T, p string) {
			if err := os.Chmod(filepath.Dir(p), 0o775); err != nil {
				t.Fatal(err)
			}
		},
		"other-writable directory": func(t *testing.T, p string) {
			if err := os.Chmod(filepath.Dir(p), 0o757); err != nil {
				t.Fatal(err)
			}
		},
		"a symlink to a good file": func(t *testing.T, p string) {
			real := filepath.Join(filepath.Dir(p), "real")
			if err := os.Rename(p, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, p); err != nil {
				t.Fatal(err)
			}
		},
		"a directory that is a symlink": func(t *testing.T, p string) {
			dir := filepath.Dir(p)
			real := dir + ".real"
			if err := os.Rename(dir, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, dir); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			p := goodEndpoint(t)
			if _, err := Read(p); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			spoil(t, p)
			if e, err := Read(p); err == nil || errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Read = %+v, %v; want a refusal", e, err)
			}
		})
	}
}

// The writer refuses a directory the reader would refuse, and writes
// nothing there. A directory it creates is 0755 whatever the umask: under
// 077 it would be 0700, and no non-root lv could reach the file.
//
// Mutations: skip the writer's directory check: the first case red. Leave
// a new directory to the umask: the second red.
func TestWrite_RefusesADirectoryOthersCanWrite(t *testing.T) {
	t.Run("group-writable", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "run")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o775); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "endpoint")
		if err := Write(p, Endpoint{GRPCPort: 7443, PKIDir: "/etc/litevirt/pki"}); err == nil {
			t.Fatal("wrote into a group-writable directory")
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Fatalf("a refused write left %v", ents)
		}
	})
	t.Run("created under umask 077", func(t *testing.T) {
		// 0700 would keep every non-root lv out of it.
		old := syscall.Umask(0o077)
		defer syscall.Umask(old)
		p := filepath.Join(t.TempDir(), "run", "endpoint")
		if err := Write(p, Endpoint{GRPCPort: 7443, PKIDir: "/etc/litevirt/pki"}); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(filepath.Dir(p))
		if err != nil || fi.Mode().Perm() != 0o755 {
			t.Fatalf("directory = %v, %v; want 0755", fi.Mode(), err)
		}
		if _, err := Read(p); err != nil {
			t.Fatalf("Read of what Write made: %v", err)
		}
	})
}

// privDir is a fresh directory only its owner can write, as /run/litevirt
// is: t.TempDir follows the umask, and a group-writable one is refused.
func privDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

// A /run/litevirt another component created first, 0700 (lxc's hook-policy
// MkdirAll of its private subdirectory gives the missing parent the same
// mode), is opened up to 0755 by the writer: left 0700, no non-root lv could
// reach the file, and on a non-default grpc_port it would fall back to 7443.
// The subdirectory keeps its own mode. (Made permanent from re-review 2's
// TestProbe_Writer0700Dir.)
//
// Mutation: drop the chmod of an existing directory others cannot search:
// red.
func TestWrite_OpensUpA0700DirectoryItOwns(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	sub := filepath.Join(dir, "lxc-hook-policy")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "endpoint")
	if err := Write(p, Endpoint{GRPCPort: 9443, PKIDir: "/etc/litevirt/pki"}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("directory = %v, %v; want 0755", fi.Mode(), err)
	}
	if fi, err := os.Stat(sub); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the private subdirectory = %v, %v; want it left 0700", fi.Mode(), err)
	}
	if e, err := Read(p); err != nil || e.GRPCPort != 9443 {
		t.Fatalf("Read = %+v, %v", e, err)
	}
}
