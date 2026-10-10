package filerestore

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// bytesDev is a BlockDevice over memory that counts the bytes read.
type bytesDev struct {
	b    []byte
	read atomic.Int64
}

func (d *bytesDev) ReadAt(p []byte, off int64) (int, error) {
	n, err := bytes.NewReader(d.b).ReadAt(p, off)
	d.read.Add(int64(n))
	return n, err
}
func (d *bytesDev) Size() int64 { return int64(len(d.b)) }

// guestTree builds a directory like a mounted guest filesystem, with a
// symlink pointing out of it and a symlinked directory.
func guestTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "etc", "ssh"), 0o755))
	must(os.WriteFile(filepath.Join(root, "etc", "hostname"), []byte("guest-1\n"), 0o644))
	must(os.WriteFile(filepath.Join(root, "etc", "ssh", "sshd_config"), []byte("PermitRootLogin no\n"), 0o600))
	must(os.Symlink("/etc/passwd", filepath.Join(root, "etc", "escape")))
	outside := t.TempDir()
	must(os.WriteFile(filepath.Join(outside, "secret"), []byte("host secret"), 0o600))
	must(os.Symlink(outside, filepath.Join(root, "linkdir")))
	return root
}

func dirSession(t *testing.T, root string) *InProcSession {
	t.Helper()
	s, err := InProcessSession(nil, KindFS, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestAgent_ListAndVolumes(t *testing.T) {
	s := dirSession(t, guestTree(t))
	vols, err := s.Volumes()
	if err != nil || len(vols) != 1 || vols[0].Name != "vda1" {
		t.Fatalf("volumes: %v %v", vols, err)
	}
	root, _, _, err := s.List("/")
	if err != nil || len(root) != 1 || root[0].Name != "vda1" || root[0].Type != TypeDir {
		t.Fatalf("list /: %v %v", root, err)
	}
	ents, _, _, err := s.List("/vda1/etc")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Entry{}
	for _, e := range ents {
		got[e.Name] = e
	}
	if got["hostname"].Type != TypeFile || got["hostname"].Size != 8 {
		t.Errorf("hostname: %+v", got["hostname"])
	}
	if got["escape"].Type != TypeSymlink || got["escape"].Target != "/etc/passwd" {
		t.Errorf("escape: %+v", got["escape"])
	}
	if got["ssh"].Type != TypeDir {
		t.Errorf("ssh: %+v", got["ssh"])
	}
}

// A path through a symlink is refused, never followed — in the restore VM a
// guest symlink must not lead the agent anywhere the selection did not name.
func TestAgent_DoesNotFollowSymlinks(t *testing.T) {
	s := dirSession(t, guestTree(t))
	if _, _, _, err := s.List("/vda1/linkdir"); err == nil {
		t.Fatal("listing a symlinked directory followed it")
	}
	var out bytes.Buffer
	if _, err := s.Tar(&out, []string{"/vda1/linkdir/secret"}, TarLimits{}); err == nil {
		t.Fatal("extracting through a symlinked directory was allowed")
	}
	// Extracting the symlink itself yields the link, not its target's bytes.
	s2 := dirSession(t, guestTree(t))
	out.Reset()
	if _, err := s2.Tar(&out, []string{"/vda1/linkdir", "/vda1/etc/escape"}, TarLimits{}); err != nil {
		t.Fatal(err)
	}
	got := readTar(t, out.Bytes())
	if e := got["vda1/linkdir"]; e.h == nil || e.h.Typeflag != tar.TypeSymlink || e.body != "" {
		t.Fatalf("linkdir: %+v", e.h)
	}
	if strings.Contains(out.String(), "host secret") {
		t.Fatal("the symlink target's content was extracted")
	}
}

func TestAgent_TarOfADirectory(t *testing.T) {
	s := dirSession(t, guestTree(t))
	var out bytes.Buffer
	st, err := s.Tar(&out, []string{"/vda1/etc"}, TarLimits{})
	if err != nil {
		t.Fatal(err)
	}
	got := readTar(t, out.Bytes())
	if got["vda1/etc/hostname"].body != "guest-1\n" || got["vda1/etc/ssh/sshd_config"].body != "PermitRootLogin no\n" {
		t.Fatalf("contents: %v", keys(got))
	}
	if _, ok := got["vda1/etc/"]; !ok {
		t.Error("the directory entry itself is missing")
	}
	if st.Entries != 5 { // etc/, hostname, ssh/, sshd_config, escape
		t.Errorf("entries %d, want 5 (%v)", st.Entries, keys(got))
	}
	// The connection stays usable after a complete archive.
	if _, _, _, err := s.List("/vda1"); err != nil {
		t.Fatalf("list after tar: %v", err)
	}
}

func TestAgent_BadRequests(t *testing.T) {
	s := dirSession(t, guestTree(t))
	for _, p := range []string{"/nosuchvol/etc", "/vda1/nope"} {
		if _, _, _, err := s.List(p); err == nil {
			t.Errorf("list %s: no error", p)
		}
	}
	if _, _, _, err := s.List("/vda1/../.."); err == nil {
		t.Error("list with .. accepted")
	}
	var out bytes.Buffer
	if _, err := s.Tar(&out, []string{"/vda1/nope"}, TarLimits{}); err == nil {
		t.Error("tar of a missing path: no error")
	}
	if s.Broken() {
		t.Error("an error response must leave the connection usable")
	}
}

// lxcArchive mimics ExportContainer: "<name>/config" and "<name>/rootfs/…",
// with PAX xattrs, a hard link and a symlink.
func lxcArchive(t *testing.T, big []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	add := func(h *tar.Header, body []byte) {
		h.ModTime = time.Unix(1700000000, 0)
		h.Format = tar.FormatPAX
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(body))
		}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if len(body) > 0 {
			if _, err := tw.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(&tar.Header{Name: "web/", Typeflag: tar.TypeDir, Mode: 0o755}, nil)
	add(&tar.Header{Name: "web/config", Typeflag: tar.TypeReg}, []byte("lxc.rootfs.path = x\n"))
	add(&tar.Header{Name: "web/rootfs/", Typeflag: tar.TypeDir, Mode: 0o755}, nil)
	add(&tar.Header{Name: "web/rootfs/etc/", Typeflag: tar.TypeDir, Mode: 0o755}, nil)
	add(&tar.Header{Name: "web/rootfs/etc/hostname", Typeflag: tar.TypeReg,
		PAXRecords: map[string]string{"SCHILY.xattr.user.k": "v"}}, []byte("web\n"))
	add(&tar.Header{Name: "web/rootfs/var/lib/big.bin", Typeflag: tar.TypeReg}, big)
	add(&tar.Header{Name: "web/rootfs/etc/hostname.bak", Typeflag: tar.TypeLink, Linkname: "web/rootfs/etc/hostname"}, nil)
	add(&tar.Header{Name: "web/rootfs/etc/mtab", Typeflag: tar.TypeSymlink, Linkname: "/proc/self/mounts"}, nil)
	add(&tar.Header{Name: "web/rootfs/dev/null", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3}, nil)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestAgent_ContainerArchive(t *testing.T) {
	big := make([]byte, 3<<20+77)
	_, _ = rand.Read(big)
	dev := &bytesDev{b: lxcArchive(t, big)}
	s, err := InProcessSession(dev, KindArchive, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Indexing reads headers, not file data: it seeks past the 3 MiB file.
	if r := dev.read.Load(); r > 1<<20 {
		t.Errorf("indexing read %d bytes of a %d-byte archive", r, len(dev.b))
	}
	vols, _ := s.Volumes()
	if len(vols) != 1 || vols[0].Name != "rootfs" {
		t.Fatalf("volumes %v, want rootfs", vols)
	}
	ents, _, _, err := s.List("/rootfs/etc")
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]string{}
	for _, e := range ents {
		types[e.Name] = e.Type
	}
	if types["hostname"] != TypeFile || types["hostname.bak"] != TypeFile || types["mtab"] != TypeSymlink {
		t.Fatalf("etc: %v", types)
	}
	var out bytes.Buffer
	st, err := s.Tar(&out, []string{"/rootfs/etc", "/rootfs/var/lib/big.bin", "/rootfs/dev"}, TarLimits{})
	if err != nil {
		t.Fatal(err)
	}
	got := readTar(t, out.Bytes())
	if got["rootfs/etc/hostname"].body != "web\n" || got["rootfs/etc/hostname.bak"].body != "web\n" {
		t.Fatalf("hostname via offsets: %q / %q", got["rootfs/etc/hostname"].body, got["rootfs/etc/hostname.bak"].body)
	}
	if !bytes.Equal([]byte(got["rootfs/var/lib/big.bin"].body), big) {
		t.Fatal("a multi-block file read from its archive offset differs")
	}
	if _, ok := got["rootfs/dev/null"]; ok {
		t.Fatal("a device node was extracted")
	}
	if st.Entries < 5 {
		t.Errorf("entries %d", st.Entries)
	}
}

// The agent's own limits cut the archive short; the host still gets a
// complete, valid tar.
func TestAgent_HonoursRequestLimits(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(root, "f"+itoa(i)), bytes.Repeat([]byte{'x'}, 1000), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := dirSession(t, root)
	var out bytes.Buffer
	st, err := s.Tar(&out, []string{"/vda1"}, TarLimits{MaxBytes: 2500})
	if err == nil || !st.Truncated {
		t.Fatalf("want a truncated extraction, got %+v %v", st, err)
	}
	if n := len(readTar(t, out.Bytes())); n < 2 || n > 4 {
		t.Fatalf("archive holds %d entries", n)
	}
}

// An agent that stops sending mid-archive does not hold the host forever:
// each read must make progress within the client's timeout.
func TestClient_StalledAgentTimesOut(t *testing.T) {
	host, guest := netPipeDeadline()
	defer guest.Close()
	go func() {
		c := newLineConn(guest)
		var req Request
		_ = c.recv(&req)
		_ = c.send(Response{})
		// Half a tar header, then nothing.
		_, _ = guest.Write(make([]byte, 100))
	}()
	cl := NewClient(host)
	cl.opTimeout = 300 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		var out bytes.Buffer
		_, err := cl.Tar(&out, []string{"/vda1/x"}, TarLimits{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a stalled archive returned success")
		}
		if !cl.Broken() {
			t.Error("the client is still usable after a stalled archive")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Tar blocked on a stalled agent")
	}
}

// netPipeDeadline is net.Pipe, whose ends support deadlines.
func netPipeDeadline() (net.Conn, net.Conn) { return net.Pipe() }
