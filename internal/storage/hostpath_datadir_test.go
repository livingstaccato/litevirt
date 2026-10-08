package storage

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// lab-recheck-5 FAILs 2 and 3: main (3e4ba50b) had no directory check at all,
// so an admin could put a dir pool at <data_dir>/<x> — the lab's rc5pool at
// /var/lib/litevirt/rc5pool — and that pool held VM disks and uploads. Inside
// the data directory only the daemon's own state is refused now: the children
// the daemon itself creates (dataDirOwned) and anything at or above them. Any
// other child is an ordinary host path, which only storage.hostpath (admin)
// may name — grpcapi's authority check, not this one.

// TestCheckWriteRoot_AnOrdinaryChildOfTheDataDirIsAHostPath: the lab case,
// for the default data dir and for any other.
//
// Red against 1c105363: `"<data>/rc5pool" is inside the daemon's data
// directory …; only its disks/, pools/ and mounts/ hold pools`, and for
// /var/lib/litevirt/rc5pool `is under /var/lib/litevirt*, litevirt state`.
func TestCheckWriteRoot_AnOrdinaryChildOfTheDataDirIsAHostPath(t *testing.T) {
	data := t.TempDir()
	for _, p := range []string{
		filepath.Join(data, "rc5pool"),
		filepath.Join(data, "rc5pool", "deeper"),
		filepath.Join(data, "rc5-backup-repo"),
	} {
		if err := CheckWriteRoot(p, data, ""); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	// The default data dir: lexical only, nothing there needs to exist.
	if err := CheckWriteRoot("/var/lib/litevirt/rc5pool", "/var/lib/litevirt", "/etc/litevirt/pki"); err != nil {
		t.Errorf("/var/lib/litevirt/rc5pool with the default data dir: %v", err)
	}
}

// TestCheckWriteRoot_TheDaemonsOwnStateIsRefusedToEveryone: the data dir, its
// parents, every child the daemon owns and anything inside one, the area
// roots, and anything inside disks/ — refused whoever asks.
func TestCheckWriteRoot_TheDaemonsOwnStateIsRefusedToEveryone(t *testing.T) {
	data := t.TempDir()
	refused := []string{data, filepath.Dir(data), filepath.Join(data, "pools"), filepath.Join(data, "mounts"),
		filepath.Join(data, "disks", "sub"), filepath.Join(data, "disks", ".replicas")}
	for _, name := range dataDirOwned {
		refused = append(refused, filepath.Join(data, name), filepath.Join(data, name, "sub"))
	}
	for _, prefix := range dataDirOwnedPrefixes {
		refused = append(refused, filepath.Join(data, prefix), filepath.Join(data, prefix+"x"), filepath.Join(data, prefix+".tok", "sub"))
	}
	for _, name := range []string{"state.db", "state.db-wal", "state.db-shm", "pki", "vms", "images", "imports", "imports/staging",
		"import-placements", "iso-identity", "pool-uploads.json", "audit-seeded-assert", "split_brain_activated.voter_config_v1",
		"nowts.hwm.lock", ".audit-seeded.json.tmp", ".pool-uploads.json-123"} {
		refused = append(refused, filepath.Join(data, name))
	}
	for _, p := range refused {
		if err := CheckWriteRoot(p, data, ""); err == nil {
			t.Errorf("%s allowed", p)
		}
	}
	// A link at an innocent name that reaches the daemon's state.
	if err := os.MkdirAll(filepath.Join(data, "pki"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(data, "innocent")
	if err := os.Symlink(filepath.Join(data, "pki"), link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, filepath.Join(link, "new")} {
		if err := CheckWriteRoot(p, data, ""); err == nil {
			t.Errorf("%s (a link into <data_dir>/pki) allowed", p)
		}
	}
	// Default layout, lexically: the gitops working tree's default home and
	// the paths the daemon hardcodes under /var/lib/litevirt stay refused —
	// with the data dir there or elsewhere, since they do not follow it.
	for _, dd := range []string{"/var/lib/litevirt", data} {
		for _, p := range []string{"/var/lib/litevirt-gitops", "/var/lib/litevirt-gitops/repo",
			"/var/lib/litevirt/backup-scratch", "/var/lib/litevirt/backup-sock", "/var/lib/litevirt/state.db",
			"/var/lib/litevirt", "/var/lib"} {
			if err := CheckWriteRoot(p, dd, "/etc/litevirt/pki"); err == nil {
				t.Errorf("%s allowed with data dir %s", p, dd)
			}
		}
	}
}

// lab-recheck-5 line 76: a btrfs pool source /var/lib/litevirt-labtest/btrfs
// was refused as "under /var/lib/litevirt*, litevirt state" — a string-prefix
// match that caught a SIBLING of the data directory. The data directory is
// judged by whole path components: <data_dir> itself or <data_dir>/…; a
// sibling whose name merely starts the same is an ordinary host path, as on
// main. (Only an admin may name it; that is grpcapi's authority check.)
//
// Red against 63ea3a06: `"/var/lib/litevirt-labtest/btrfs" is under
// /var/lib/litevirt*, litevirt state`.
func TestCheckWriteRoot_ASiblingOfTheDataDirIsNotInsideIt(t *testing.T) {
	for _, dd := range []string{"/var/lib/litevirt", t.TempDir()} {
		for _, p := range []string{"/var/lib/litevirt-labtest/btrfs", "/var/lib/litevirt-labtest",
			"/var/lib/litevirt2/x", "/var/lib/litevirt.old/x"} {
			if err := CheckWriteRoot(p, dd, "/etc/litevirt/pki"); err != nil {
				t.Errorf("%s (data dir %s): %v", p, dd, err)
			}
		}
		if err := CheckConfig(Config{Driver: "btrfs", Source: "/var/lib/litevirt-labtest/btrfs"}, dd, "/etc/litevirt/pki"); err != nil {
			t.Errorf("btrfs source /var/lib/litevirt-labtest/btrfs (data dir %s): %v", dd, err)
		}
	}
	// The same with a data dir of any name: its sibling is not inside it.
	base := t.TempDir()
	data := filepath.Join(base, "litevirt")
	if err := CheckWriteRoot(filepath.Join(base, "litevirt-labtest", "x"), data, ""); err != nil {
		t.Errorf("a sibling of the data dir: %v", err)
	}
	if err := CheckWriteRoot(filepath.Join(data, "pki"), data, ""); err == nil {
		t.Error("<data_dir>/pki allowed")
	}
}

// The read side follows the same rule: an ISO in an ordinary child of the
// data dir (a main-era pool's upload) may be given to a guest; the daemon's
// own state may not.
//
// Red against 1c105363: `is inside the daemon's data directory …; only its
// pools/, mounts/, disks/uploads/ and the ISO images directly in disks/ hold
// pool content`.
func TestCheckReadFile_AnOrdinaryChildOfTheDataDir(t *testing.T) {
	data := t.TempDir()
	write := func(p string) string {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, opticalImage("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := write(filepath.Join(data, "rc5pool", "rc5-pool-upload.iso"))
	if err := CheckReadFile(ok, data, ""); err != nil {
		t.Errorf("an ISO in a main-era pool at <data_dir>/rc5pool: %v", err)
	}
	if err := CheckReadPathLexical(ok, data, ""); err != nil {
		t.Errorf("lexically: %v", err)
	}
	for _, p := range []string{
		write(filepath.Join(data, "state.db")),
		write(filepath.Join(data, "cloudinit", "vm.iso")),
		write(filepath.Join(data, "images", "x.iso")),
		write(filepath.Join(data, "imports", "staging", "x.iso")),
		write(filepath.Join(data, "audit-seeded-assert")),
		write(filepath.Join(data, "split_brain_activated.voter_config_v1")),
	} {
		if err := CheckReadFile(p, data, ""); err == nil {
			t.Errorf("%s allowed", p)
		}
	}
}

// dataDirJoinRe matches a join onto the data directory whose next element is
// a string literal or an identifier: filepath.Join(s.dataDir, "vms", …),
// filepath.Join(d.cfg.DataDir, genesisMarkerName).
var dataDirJoinRe = regexp.MustCompile(`Join\(\s*[A-Za-z_.]*[dD]ata[dD]ir(?:\(\))?\s*,\s*("[^"]*"|[A-Za-z_][A-Za-z0-9_.]*)`)

// constLineRe matches `const X = "v"`, and constSpecRe `X = "v"` inside a
// const ( … ) block.
var (
	constLineRe = regexp.MustCompile(`^\s*const\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:string\s*)?=\s*("[^"]*")`)
	constSpecRe = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:string\s*)?=\s*("[^"]*")`)
)

// stringConsts returns the string constants src declares.
func stringConsts(src string, into map[string]string) {
	inBlock := false
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "const (":
			inBlock = true
			continue
		case inBlock && trimmed == ")":
			inBlock = false
			continue
		}
		re := constLineRe
		if inBlock {
			re = constSpecRe
		}
		if m := re.FindStringSubmatch(line); m != nil {
			if v, err := strconv.Unquote(m[2]); err == nil {
				into[m[1]] = v
			}
		}
	}
}

// hardcodedRe matches a path the daemon hardcodes under the default data dir.
var hardcodedRe = regexp.MustCompile(`"/var/lib/litevirt/([^"/]+)`)

// TestDataDirOwned_CoversEverythingTheDaemonCreates is the drift guard for the
// deny-list: every name the daemon's code joins onto its data directory — as a
// literal, or a string constant — and every path it hardcodes under
// /var/lib/litevirt is owned, so a pool can never be aimed at it. A new child
// the daemon starts creating fails here until it is added to dataDirOwned.
func TestDataDirOwned_CoversEverythingTheDaemonCreates(t *testing.T) {
	root := filepath.Join("..", "..")
	consts := map[string]string{}
	var sources []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				switch fi.Name() {
				case "libvirtfake", "testkit":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			src := string(b)
			sources = append(sources, p+"\x00"+src)
			stringConsts(src, consts)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := 0
	check := func(where, name string) {
		first, _, _ := strings.Cut(filepath.Clean(name), string(filepath.Separator))
		if first == "" || first == "." {
			return
		}
		seen++
		switch first {
		case dataDirDisks, "pools", "mounts":
			return // judged by their own rule (dataDirChildRefusal)
		}
		if !dataDirChildOwned(first) {
			t.Errorf("%s puts %q in the data directory, and it is not in dataDirOwned", where, first)
		}
	}
	for _, s := range sources {
		file, src, _ := strings.Cut(s, "\x00")
		for _, m := range dataDirJoinRe.FindAllStringSubmatch(src, -1) {
			arg := m[1]
			if strings.HasPrefix(arg, `"`) {
				v, _ := strconv.Unquote(arg)
				check(file, v)
				continue
			}
			// A (possibly package-qualified) constant; a variable is a VM or
			// pool name, not a fixed child.
			id := arg[strings.LastIndex(arg, ".")+1:]
			if v, ok := consts[id]; ok {
				check(file+" ("+id+")", v)
			}
		}
		for _, m := range hardcodedRe.FindAllStringSubmatch(src, -1) {
			check(file, m[1])
		}
	}
	if seen < 30 {
		t.Fatalf("the scan found only %d data-dir children; it no longer reads the code", seen)
	}
}
