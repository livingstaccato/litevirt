package cloudinit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
)

// goISO is whether seeds are built by writeGoISO where genisoimage is not
// installed (UseGoISOWithoutGenisoimage).
var goISO atomic.Bool

// UseGoISOWithoutGenisoimage has this process build a seed with a small Go
// ISO 9660 writer whenever genisoimage is not on PATH, instead of failing. It
// is for tests on a host without genisoimage (CI): the seed logic they test
// reads the seeds back (ReadSeed). A genisoimage on PATH, a test's stand-in
// included, is used as before. The daemon never calls it.
func UseGoISOWithoutGenisoimage() { goISO.Store(true) }

// buildISO writes the NoCloud ISO image of the files in dir to out, an
// existing file it replaces the content of.
func buildISO(dir, out string) error {
	if goISO.Load() {
		if _, err := exec.LookPath("genisoimage"); err != nil {
			return writeGoISO(dir, out)
		}
	}
	cmd := exec.Command("genisoimage", "-output", out, "-volid", "cidata", "-joliet", "-rock", dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("genisoimage: %s: %w", string(output), err)
	}
	return nil
}

// writeGoISO writes the regular files of dir to out as an ISO 9660 image
// labelled cidata, one root directory, each file under its name as a Rock
// Ridge NM entry (the names ReadSeed and a Linux mount read).
func writeGoISO(dir, out string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type file struct {
		name, id string
		data     []byte
		extent   uint32
	}
	var files []file
	ids := map[string]bool{}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		id := isoIdentifier(e.Name())
		for n := 0; ids[id]; n++ {
			id = isoIdentifier(fmt.Sprintf("%s%d", e.Name()[:min(len(e.Name()), 6)], n))
		}
		ids[id] = true
		files = append(files, file{name: e.Name(), id: id, data: b})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].id < files[j].id })

	const (
		pvdSector  = 16
		lPathTable = 18
		mPathTable = 19
		rootSector = 20
	)
	// The root directory: ".", "..", then one record per file; the extents
	// and sizes are filled in once the layout is known.
	rootSU := append(susp('S', 'P', []byte{0xBE, 0xEF, 0}), susp('E', 'R', append([]byte{10, 0, 0, 1}, "RRIP_1991A"...))...)
	recs := [][]byte{isoDirRecord([]byte{0}, 0, 0, true, rootSU), isoDirRecord([]byte{1}, 0, 0, true, nil)}
	for _, f := range files {
		recs = append(recs, isoDirRecord([]byte(f.id), 0, 0, false,
			append(susp('P', 'X', isoPX()), susp('N', 'M', append([]byte{0}, f.name...))...)))
	}
	// Records do not cross a sector.
	at := make([]int, len(recs))
	off := 0
	for i, r := range recs {
		if off%isoSector+len(r) > isoSector {
			off += isoSector - off%isoSector
		}
		at[i] = off
		off += len(r)
	}
	dirSectors := uint32(off/isoSector + 1)
	next := uint32(rootSector) + dirSectors
	for i := range files {
		files[i].extent = next
		next += uint32((len(files[i].data) + isoSector - 1) / isoSector)
		if len(files[i].data) == 0 {
			next++
		}
	}
	total := next

	img := make([]byte, int(total)*isoSector)
	for i, r := range recs {
		if i < 2 {
			both32(r[2:10], rootSector)
			both32(r[10:18], dirSectors*isoSector)
		} else {
			both32(r[2:10], files[i-2].extent)
			both32(r[10:18], uint32(len(files[i-2].data)))
		}
		copy(img[rootSector*isoSector+at[i]:], r)
	}
	for _, f := range files {
		copy(img[int(f.extent)*isoSector:], f.data)
	}

	pvd := img[pvdSector*isoSector:]
	pvd[0] = 1
	copy(pvd[1:6], "CD001")
	pvd[6] = 1
	copy(pvd[8:40], bytes.Repeat([]byte{' '}, 32))
	copy(pvd[40:72], fmt.Sprintf("%-32s", "cidata"))
	both32(pvd[80:88], total)
	both16(pvd[120:124], 1)
	both16(pvd[124:128], 1)
	both16(pvd[128:132], isoSector)
	both32(pvd[132:140], 10)
	binary.LittleEndian.PutUint32(pvd[140:144], lPathTable)
	binary.BigEndian.PutUint32(pvd[148:152], mPathTable)
	copy(pvd[156:190], isoDirRecord([]byte{0}, rootSector, dirSectors*isoSector, true, nil))
	copy(pvd[190:813], bytes.Repeat([]byte{' '}, 813-190))
	for _, at := range []int{813, 830, 847, 864} {
		copy(pvd[at:at+16], strings.Repeat("0", 16))
	}
	pvd[881] = 1
	term := img[(pvdSector+1)*isoSector:]
	term[0] = 255
	copy(term[1:6], "CD001")
	term[6] = 1
	for _, pt := range []struct {
		sector int
		order  binary.ByteOrder
	}{{lPathTable, binary.LittleEndian}, {mPathTable, binary.BigEndian}} {
		rec := img[pt.sector*isoSector:]
		rec[0] = 1
		pt.order.PutUint32(rec[2:6], rootSector)
		pt.order.PutUint16(rec[6:8], 1)
	}

	f, err := os.OpenFile(out, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write(img); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// isoIdentifier is an ISO 9660 level 1 file identifier for name: at most 8
// d-characters, ".;1".
func isoIdentifier(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		if b.Len() == 8 {
			break
		}
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String() + ".;1"
}

// isoDirRecord is one directory record.
func isoDirRecord(id []byte, extent, size uint32, dir bool, su []byte) []byte {
	n := 33 + len(id)
	if len(id)%2 == 0 {
		n++
	}
	n += len(su)
	if n%2 == 1 {
		n++
	}
	r := make([]byte, n)
	r[0] = byte(n)
	both32(r[2:10], extent)
	both32(r[10:18], size)
	if dir {
		r[25] = 0x02
	}
	both16(r[28:32], 1)
	r[32] = byte(len(id))
	copy(r[33:], id)
	at := 33 + len(id)
	if len(id)%2 == 0 {
		at++
	}
	copy(r[at:], su)
	return r
}

// susp is a System Use Sharing Protocol entry of version 1.
func susp(a, b byte, body []byte) []byte {
	return append([]byte{a, b, byte(4 + len(body)), 1}, body...)
}

// isoPX is a Rock Ridge PX body: a read-only regular file, one link, root.
func isoPX() []byte {
	b := make([]byte, 32)
	both32(b[0:8], 0o100444)
	both32(b[8:16], 1)
	return b
}

func both16(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b[0:2], v)
	binary.BigEndian.PutUint16(b[2:4], v)
}

func both32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b[0:4], v)
	binary.BigEndian.PutUint32(b[4:8], v)
}
