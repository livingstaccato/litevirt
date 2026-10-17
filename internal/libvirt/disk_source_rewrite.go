package libvirt

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// RewriteDiskSourceFile rewrites exactly one disk's <source file=...> in a libvirt
// domain XML from oldFile to newFile and returns the new XML. It is the authoritative
// cutover used by MoveVolume to repoint a domain's persistent config after a disk
// moves between pools — so it is deliberately strict and precise rather than a blunt
// string replace (which can hit the path outside the <source> attribute or mishandle
// XML-escaped attribute values).
//
// Matching:
//   - targetDev != "": the disk with <target dev=targetDev> is the subject. Its current
//     <source file> must equal oldFile (→ rewrite, changed=true) or newFile (→ already
//     cut over, changed=false); anything else, a missing such disk, or a subject disk
//     that has no file-backed <source> (cdrom/block/network) is an error.
//   - targetDev == "" (legacy rows with no recorded dev): exactly one disk whose
//     <source file> equals oldFile → rewrite; else exactly one equal to newFile →
//     idempotent (changed=false); zero or multiple matches → error.
//
// Other disks — including source-less devices (empty cdrom) and block/network disks
// (<source dev=…>/<source protocol=…>, no file attr) — are parsed but never modified.
//
// The result is the input with only that attribute's value replaced: the edit is
// spliced into the original text, so every other byte is kept. Every litevirt
// domain carries namespaced metadata (litevirt-managed, litevirt-owner-epoch),
// and a re-encode through encoding/xml would rewrite those elements, so the text
// is never re-encoded. Namespaces outside <devices> (that metadata, a
// qemu:commandline block) are kept as they are. A namespace on the domain
// element, on <devices>, or on anything inside <devices> is refused: disks are
// matched by element and attribute name there, and a namespaced name could be
// taken for one it is not.
// RewriteDiskSource repoints one disk's source, whichever attribute that disk
// actually uses: <source file=> for a file, <source dev=> for a block device,
// <source name=> for an rbd image.
//
// RewriteDiskSourceFile knows only about `file`, which was enough while every
// generated disk was emitted as type="file" regardless of what backed it. A
// zvol or an LV was therefore rewritable by accident. Now that a block-backed
// disk correctly carries <source dev=>, the file-only rewrite refuses it and
// `lv move-volume` cannot repoint a zfs, lvm-thin or iscsi disk at all.
//
// A move that would change the BACKING KIND is refused: repointing a block
// device at a qcow2 file needs the <disk type> and <driver type> to change too,
// and a source-only rewrite would leave a domain libvirt cannot start. That is
// a different operation, not a path edit.
func RewriteDiskSource(domXML, targetDev, oldSource, newSource string) (out string, changed bool, err error) {
	return rewriteDiskSourceLocator(domXML, targetDev, oldSource, newSource, anySourceAttr)
}

// sourceAttrKind names the <source> attribute a disk uses to locate itself. The
// three are mutually exclusive and are selected by the enclosing <disk type=>.
type sourceAttrKind string

const (
	sourceAttrFile sourceAttrKind = "file" // type="file"
	sourceAttrDev  sourceAttrKind = "dev"  // type="block"
	sourceAttrName sourceAttrKind = "name" // type="network" (rbd et al)
	// anySourceAttr means "whichever one this disk carries".
	anySourceAttr sourceAttrKind = ""
)

// sourceAttrKinds is the search order when a disk's kind is not pinned. A disk
// carries exactly one of these, so the order only decides which is reported
// first for a malformed domain that carries several.
var sourceAttrKinds = []sourceAttrKind{sourceAttrFile, sourceAttrDev, sourceAttrName}

func RewriteDiskSourceFile(domXML, targetDev, oldFile, newFile string) (out string, changed bool, err error) {
	return rewriteDiskSourceLocator(domXML, targetDev, oldFile, newFile, sourceAttrFile)
}

// rewriteDiskSource is the shared body. `want` pins which source attribute is
// eligible; anySourceAttr accepts whichever the disk carries.
func rewriteDiskSourceLocator(domXML, targetDev, oldSource, newSource string, want sourceAttrKind) (string, bool, error) {
	disks, err := parseDiskSourceInfos(domXML)
	if err != nil {
		return "", false, err
	}
	matchIndex, kind, idempotent, err := matchDiskToRewrite(disks, targetDev, oldSource, newSource, want)
	if err != nil {
		return "", false, err
	}
	if idempotent {
		return domXML, false, nil
	}
	// Refuse a move that changes the backing KIND. Repointing a block device at
	// a qcow2 file (or the reverse) needs the <disk type> and the <driver type>
	// to change with it; editing only the locator leaves a domain that claims to
	// be one thing and points at another, and libvirt will not start it. That is
	// a different operation, not a path edit.
	if !sourceSuitsKind(kind, newSource) {
		return "", false, fmt.Errorf(
			"cannot repoint a %s to %q: that is a %s. Changing a disk's backing needs "+
				"the disk type and driver type to change too, which this rewrite does not do",
			sourceAttrDescription(kind), newSource, sourceAttrDescription(kindOfSource(newSource)))
	}
	rewritten, err := spliceDiskSource(domXML, disks[matchIndex], kind, oldSource, newSource)
	if err != nil {
		return "", false, err
	}
	return rewritten, true, nil
}

// diskSourceInfo is one disk's identity for matching: its target dev and its
// source locators, plus where its <source> start tag sits in the text.
type diskSourceInfo struct {
	dev string // <target dev=…>, the disk's stable name
	// Exactly one of these is non-empty for a well-formed disk; all three are
	// empty for a source-less device such as an ejected cdrom.
	src map[sourceAttrKind]string
	// srcStart, srcEnd bound the disk's <source ...> start tag in the domain
	// XML; srcStart is -1 when the disk has no <source>.
	srcStart, srcEnd int64
}

// source returns the disk's locator under `want`, plus which attribute it came
// from. With anySourceAttr it reports whichever one the disk carries.
func (d diskSourceInfo) source(want sourceAttrKind) (string, sourceAttrKind) {
	if want != anySourceAttr {
		return d.src[want], want
	}
	for _, k := range sourceAttrKinds {
		if v := d.src[k]; v != "" {
			return v, k
		}
	}
	return "", anySourceAttr
}

// parseDiskSourceInfos returns every <domain>/<devices>/<disk> in document
// order with its target dev, its <source> locators and the byte span of that
// <source> start tag. It refuses a namespace on the domain element, on
// <devices> or on anything inside <devices> (namespaceInDevicesError);
// namespaces elsewhere are skipped over.
func parseDiskSourceInfos(domXML string) ([]diskSourceInfo, error) {
	dec := xml.NewDecoder(strings.NewReader(domXML))
	var out []diskSourceInfo
	depth := 0 // depth of the element being read; the domain is 1
	inDevices := false
	cur := -1 // index in out of the disk being read, or -1
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse domain xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 && t.Name.Space != "" {
				return nil, namespaceInDevicesError("the domain element is in namespace " + t.Name.Space)
			}
			if depth == 2 && t.Name.Local == "devices" {
				inDevices = true
			}
			if inDevices {
				if t.Name.Space != "" {
					return nil, namespaceInDevicesError("element " + t.Name.Space + ":" + t.Name.Local)
				}
				for _, a := range t.Attr {
					// xmlns="…" is {Space:"", Local:"xmlns"}; xmlns:p="…" is {Space:"xmlns", …}.
					if a.Name.Space != "" || a.Name.Local == "xmlns" {
						return nil, namespaceInDevicesError("attribute " + a.Name.Space + ":" + a.Name.Local + " on <" + t.Name.Local + ">")
					}
				}
			}
			switch {
			case inDevices && depth == 3 && t.Name.Local == "disk":
				out = append(out, diskSourceInfo{src: map[sourceAttrKind]string{}, srcStart: -1, srcEnd: -1})
				cur = len(out) - 1
			case cur >= 0 && depth == 4 && t.Name.Local == "source":
				d := &out[cur]
				if d.srcStart >= 0 {
					return nil, fmt.Errorf("disk %d has more than one <source>", cur)
				}
				d.srcStart, d.srcEnd = start, dec.InputOffset()
				for _, k := range sourceAttrKinds {
					d.src[k] = attrValue(t, string(k))
				}
			case cur >= 0 && depth == 4 && t.Name.Local == "target":
				if out[cur].dev == "" {
					out[cur].dev = attrValue(t, "dev")
				}
			}
		case xml.EndElement:
			if depth == 3 {
				cur = -1
			}
			if depth == 2 {
				inDevices = false
			}
			depth--
		}
	}
	return out, nil
}

// namespaceInDevicesError is the refusal for a namespace where disks are
// matched by name.
func namespaceInDevicesError(what string) error {
	return fmt.Errorf("domain xml uses an XML namespace where disks are matched (%s); refusing automated disk-source rewrite", what)
}

// matchDiskToRewrite resolves which devices/disk (by document-order index) must have
// its source rewritten, enforcing the locked matching rules. idempotent=true means
// the subject disk already points at newFile and no rewrite is needed.
func matchDiskToRewrite(disks []diskSourceInfo, targetDev, oldSource, newSource string, want sourceAttrKind) (matchIndex int, kind sourceAttrKind, idempotent bool, err error) {
	if targetDev != "" {
		idx := -1
		for i, d := range disks {
			if d.dev == targetDev {
				if idx >= 0 {
					return -1, anySourceAttr, false, fmt.Errorf("multiple disks with target dev %q", targetDev)
				}
				idx = i
			}
		}
		if idx < 0 {
			return -1, anySourceAttr, false, fmt.Errorf("no disk with target dev %q", targetDev)
		}
		cur, k := disks[idx].source(want)
		switch {
		case cur == newSource:
			return idx, k, true, nil // already cut over
		case cur == oldSource:
			return idx, k, false, nil
		case cur == "":
			return -1, anySourceAttr, false, fmt.Errorf(
				"disk %q has no %s to rewrite", targetDev, sourceAttrDescription(want))
		default:
			return -1, anySourceAttr, false, fmt.Errorf(
				"disk %q source is %q, expected %q", targetDev, cur, oldSource)
		}
	}
	// targetDev == "": match by source across every disk that has one.
	var oldIdxs, newIdxs []int
	var oldKind sourceAttrKind
	for i, d := range disks {
		cur, k := d.source(want)
		switch cur {
		case "":
			// source-less device (an ejected cdrom) — never a rewrite subject.
		case oldSource:
			oldIdxs = append(oldIdxs, i)
			oldKind = k
		case newSource:
			newIdxs = append(newIdxs, i)
			oldKind = k
		}
	}
	switch {
	case len(oldIdxs) == 1:
		return oldIdxs[0], oldKind, false, nil
	case len(oldIdxs) > 1:
		return -1, anySourceAttr, false, fmt.Errorf("multiple disks with source %q", oldSource)
	case len(newIdxs) == 1:
		return newIdxs[0], oldKind, true, nil // idempotent
	case len(newIdxs) > 1:
		return -1, anySourceAttr, false, fmt.Errorf("multiple disks with source %q", newSource)
	default:
		return -1, anySourceAttr, false, fmt.Errorf("no disk with source %q", oldSource)
	}
}

// kindOfSource infers which <source> attribute a bare locator belongs in.
//
// It reads the locator's SHAPE, not a URI scheme, because inside the domain XML
// the scheme is already gone: an rbd disk stores "pool/image" under
// <source name=>, not "rbd:pool/image". A device node is absolute under /dev,
// a file is any other absolute path, and anything relative is a network name.
func kindOfSource(s string) sourceAttrKind {
	switch {
	case strings.HasPrefix(s, "/dev/"):
		return sourceAttrDev
	case strings.HasPrefix(s, "/"):
		return sourceAttrFile
	default:
		return sourceAttrName
	}
}

// sourceSuitsKind reports whether newSource can live under the attribute the
// disk already uses.
func sourceSuitsKind(kind sourceAttrKind, newSource string) bool {
	return kindOfSource(newSource) == kind
}

// sourceAttrDescription renders a kind for an operator-facing error.
func sourceAttrDescription(k sourceAttrKind) string {
	switch k {
	case sourceAttrFile:
		return "file-backed <source>"
	case sourceAttrDev:
		return "block-backed <source>"
	case sourceAttrName:
		return "network <source>"
	default:
		return "<source> locator"
	}
}

// spliceDiskSource replaces the value of the `kind` attribute of disk d's
// <source> start tag, which must currently read oldSource, with newSource
// escaped. Every byte outside that value is kept.
func spliceDiskSource(domXML string, d diskSourceInfo, kind sourceAttrKind, oldSource, newSource string) (string, error) {
	if d.srcStart < 0 || d.src[kind] != oldSource {
		return "", fmt.Errorf("internal: matched disk %q has no <source %s=%q>", d.dev, kind, oldSource)
	}
	tag := domXML[d.srcStart:d.srcEnd]
	vs, ve, err := attrValueSpan(tag, string(kind))
	if err != nil {
		return "", fmt.Errorf("disk %q: %w", d.dev, err)
	}
	return domXML[:d.srcStart] + tag[:vs] + escapeAttr(newSource) + tag[ve:] + domXML[d.srcEnd:], nil
}

// attrValueSpan finds the attribute named exactly `name` in one raw start tag
// by reading the tag's attributes in turn, so text inside another attribute's
// value is never taken for it. It returns the bounds of the value between its
// quotes.
func attrValueSpan(tag, name string) (start, end int, err error) {
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	i := 1 // past '<'
	for i < len(tag) && !isSpace(tag[i]) && tag[i] != '/' && tag[i] != '>' {
		i++
	}
	found := -1
	for {
		for i < len(tag) && isSpace(tag[i]) {
			i++
		}
		if i >= len(tag) || tag[i] == '/' || tag[i] == '>' {
			break
		}
		ns := i
		for i < len(tag) && !isSpace(tag[i]) && tag[i] != '=' {
			i++
		}
		attr := tag[ns:i]
		for i < len(tag) && isSpace(tag[i]) {
			i++
		}
		if i >= len(tag) || tag[i] != '=' {
			return 0, 0, fmt.Errorf("malformed attribute %q in %q", attr, tag)
		}
		i++
		for i < len(tag) && isSpace(tag[i]) {
			i++
		}
		if i >= len(tag) || (tag[i] != '\'' && tag[i] != '"') {
			return 0, 0, fmt.Errorf("unquoted attribute %q in %q", attr, tag)
		}
		q := tag[i]
		i++
		vs := i
		for i < len(tag) && tag[i] != q {
			i++
		}
		if i >= len(tag) {
			return 0, 0, fmt.Errorf("unterminated attribute %q in %q", attr, tag)
		}
		if attr == name {
			if found >= 0 {
				return 0, 0, fmt.Errorf("attribute %q appears twice in %q", name, tag)
			}
			found, start, end = 1, vs, i
		}
		i++
	}
	if found < 0 {
		return 0, 0, fmt.Errorf("no %s attribute in %q", name, tag)
	}
	return start, end, nil
}
