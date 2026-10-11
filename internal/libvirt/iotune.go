package libvirt

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// Disk discard and zero-detection values (libvirt <driver discard=… detect_zeroes=…>).
const (
	DiscardUnmap  = "unmap"
	DiscardIgnore = "ignore"
)

// DiscardCapableBus reports whether a disk bus carries the guest's TRIM:
// virtio-blk and virtio-scsi/scsi, and sata. IDE and USB are left alone — a
// default must not add a discard feature to a legacy device an old guest driver
// has never seen.
func DiscardCapableBus(bus string) bool {
	switch bus {
	case "", "virtio", "scsi", "sata":
		return true
	}
	return false
}

// ValidateDiscard checks a stored discard value. Empty is unset.
func ValidateDiscard(v string) error {
	switch v {
	case "", DiscardUnmap, DiscardIgnore:
		return nil
	}
	return fmt.Errorf("discard %q: want unmap or ignore", v)
}

// ValidateDetectZeroes checks a detect_zeroes value against the disk's discard
// setting. "unmap" turns a zero write into a discard, which qemu refuses to
// set up unless the disk passes discards down.
func ValidateDetectZeroes(v, discard string) error {
	switch v {
	case "", "off", "on":
		return nil
	case "unmap":
		if discard != DiscardUnmap {
			return fmt.Errorf("detect_zeroes unmap needs discard unmap")
		}
		return nil
	}
	return fmt.Errorf("detect_zeroes %q: want off, on or unmap", v)
}

// IOTune is one disk's I/O throttle (libvirt <iotune>). Zero is "no limit".
type IOTune struct {
	TotalBytesSec, ReadBytesSec, WriteBytesSec int64
	TotalIopsSec, ReadIopsSec, WriteIopsSec    int64

	// The burst ceilings above the sustained rate.
	TotalBytesSecMax, ReadBytesSecMax, WriteBytesSecMax int64
	TotalIopsSecMax, ReadIopsSecMax, WriteIopsSecMax    int64

	// BurstSec is how long a *_Max burst may last (applied to every *_Max that
	// is set). Zero lets libvirt use its default of one second.
	BurstSec int64
}

// maxIOTuneValue is the largest value qemu's throttle accepts (THROTTLE_VALUE_MAX).
const maxIOTuneValue = 1_000_000_000_000_000

// IsZero reports whether no limit is set.
func (t IOTune) IsZero() bool { return t == IOTune{} }

// Validate refuses what libvirt or qemu would refuse at define time, so the
// operator hears it before a stopped VM fails to start.
func (t IOTune) Validate() error {
	type lim struct {
		name     string
		v, burst int64
	}
	all := []lim{
		{"total_bytes_sec", t.TotalBytesSec, t.TotalBytesSecMax},
		{"read_bytes_sec", t.ReadBytesSec, t.ReadBytesSecMax},
		{"write_bytes_sec", t.WriteBytesSec, t.WriteBytesSecMax},
		{"total_iops_sec", t.TotalIopsSec, t.TotalIopsSecMax},
		{"read_iops_sec", t.ReadIopsSec, t.ReadIopsSecMax},
		{"write_iops_sec", t.WriteIopsSec, t.WriteIopsSecMax},
	}
	anyMax := false
	for _, l := range all {
		if l.v < 0 || l.burst < 0 {
			return fmt.Errorf("%s: limits cannot be negative", l.name)
		}
		if l.v > maxIOTuneValue || l.burst > maxIOTuneValue {
			return fmt.Errorf("%s: limit is more than %d", l.name, int64(maxIOTuneValue))
		}
		if l.burst > 0 {
			anyMax = true
			if l.v == 0 {
				return fmt.Errorf("%s_max needs %s: a burst is a ceiling above a sustained rate", l.name, l.name)
			}
			if l.burst < l.v {
				return fmt.Errorf("%s_max (%d) is below %s (%d)", l.name, l.burst, l.name, l.v)
			}
		}
	}
	if t.TotalBytesSec > 0 && (t.ReadBytesSec > 0 || t.WriteBytesSec > 0) {
		return fmt.Errorf("total_bytes_sec cannot be combined with read_bytes_sec or write_bytes_sec")
	}
	if t.TotalIopsSec > 0 && (t.ReadIopsSec > 0 || t.WriteIopsSec > 0) {
		return fmt.Errorf("total_iops_sec cannot be combined with read_iops_sec or write_iops_sec")
	}
	// qemu refuses a burst whose length times its ceiling overflows its limit,
	// which libvirt accepts into the config: a definition that cannot start.
	if t.BurstSec > 0 {
		for _, l := range all {
			if l.burst > 0 && t.BurstSec > maxIOTuneValue/l.burst {
				return fmt.Errorf("%s_max (%d) held for burst_seconds %d is more than qemu allows (%d)", l.name, l.burst, t.BurstSec, int64(maxIOTuneValue))
			}
		}
	}
	if t.BurstSec < 0 || t.BurstSec > maxIOTuneValue {
		return fmt.Errorf("burst_seconds %d out of range", t.BurstSec)
	}
	if t.BurstSec > 0 && !anyMax {
		return fmt.Errorf("burst_seconds needs at least one *_max burst ceiling")
	}
	return nil
}

// diskIOTune is the <iotune> element.
type diskIOTune struct {
	TotalBytesSec    int64 `xml:"total_bytes_sec,omitempty"`
	ReadBytesSec     int64 `xml:"read_bytes_sec,omitempty"`
	WriteBytesSec    int64 `xml:"write_bytes_sec,omitempty"`
	TotalIopsSec     int64 `xml:"total_iops_sec,omitempty"`
	ReadIopsSec      int64 `xml:"read_iops_sec,omitempty"`
	WriteIopsSec     int64 `xml:"write_iops_sec,omitempty"`
	TotalBytesSecMax int64 `xml:"total_bytes_sec_max,omitempty"`
	ReadBytesSecMax  int64 `xml:"read_bytes_sec_max,omitempty"`
	WriteBytesSecMax int64 `xml:"write_bytes_sec_max,omitempty"`
	TotalIopsSecMax  int64 `xml:"total_iops_sec_max,omitempty"`
	ReadIopsSecMax   int64 `xml:"read_iops_sec_max,omitempty"`
	WriteIopsSecMax  int64 `xml:"write_iops_sec_max,omitempty"`

	TotalBytesSecMaxLen int64 `xml:"total_bytes_sec_max_length,omitempty"`
	ReadBytesSecMaxLen  int64 `xml:"read_bytes_sec_max_length,omitempty"`
	WriteBytesSecMaxLen int64 `xml:"write_bytes_sec_max_length,omitempty"`
	TotalIopsSecMaxLen  int64 `xml:"total_iops_sec_max_length,omitempty"`
	ReadIopsSecMaxLen   int64 `xml:"read_iops_sec_max_length,omitempty"`
	WriteIopsSecMaxLen  int64 `xml:"write_iops_sec_max_length,omitempty"`
}

// element renders the throttle as an <iotune> element, or nil when no limit is
// set (an empty <iotune/> would only churn the definition).
func (t IOTune) element() *diskIOTune {
	if t.IsZero() {
		return nil
	}
	lenOf := func(max int64) int64 {
		if max > 0 {
			return t.BurstSec
		}
		return 0
	}
	return &diskIOTune{
		TotalBytesSec: t.TotalBytesSec, ReadBytesSec: t.ReadBytesSec, WriteBytesSec: t.WriteBytesSec,
		TotalIopsSec: t.TotalIopsSec, ReadIopsSec: t.ReadIopsSec, WriteIopsSec: t.WriteIopsSec,
		TotalBytesSecMax: t.TotalBytesSecMax, ReadBytesSecMax: t.ReadBytesSecMax, WriteBytesSecMax: t.WriteBytesSecMax,
		TotalIopsSecMax: t.TotalIopsSecMax, ReadIopsSecMax: t.ReadIopsSecMax, WriteIopsSecMax: t.WriteIopsSecMax,
		TotalBytesSecMaxLen: lenOf(t.TotalBytesSecMax), ReadBytesSecMaxLen: lenOf(t.ReadBytesSecMax),
		WriteBytesSecMaxLen: lenOf(t.WriteBytesSecMax), TotalIopsSecMaxLen: lenOf(t.TotalIopsSecMax),
		ReadIopsSecMaxLen: lenOf(t.ReadIopsSecMax), WriteIopsSecMaxLen: lenOf(t.WriteIopsSecMax),
	}
}

// typedParams renders every field, zeros included: setting a field to 0 is how
// libvirt clears a limit, and a partial list would leave the old one in force.
func (t IOTune) typedParams() []golibvirt.TypedParam {
	lenOf := func(max int64) uint64 {
		if max > 0 && t.BurstSec > 0 {
			return uint64(t.BurstSec)
		}
		return 0
	}
	p := func(field string, v uint64) golibvirt.TypedParam {
		return golibvirt.TypedParam{Field: field, Value: *golibvirt.NewTypedParamValueUllong(v)}
	}
	return []golibvirt.TypedParam{
		p("total_bytes_sec", uint64(t.TotalBytesSec)),
		p("read_bytes_sec", uint64(t.ReadBytesSec)),
		p("write_bytes_sec", uint64(t.WriteBytesSec)),
		p("total_iops_sec", uint64(t.TotalIopsSec)),
		p("read_iops_sec", uint64(t.ReadIopsSec)),
		p("write_iops_sec", uint64(t.WriteIopsSec)),
		p("total_bytes_sec_max", uint64(t.TotalBytesSecMax)),
		p("read_bytes_sec_max", uint64(t.ReadBytesSecMax)),
		p("write_bytes_sec_max", uint64(t.WriteBytesSecMax)),
		p("total_iops_sec_max", uint64(t.TotalIopsSecMax)),
		p("read_iops_sec_max", uint64(t.ReadIopsSecMax)),
		p("write_iops_sec_max", uint64(t.WriteIopsSecMax)),
		p("total_bytes_sec_max_length", lenOf(t.TotalBytesSecMax)),
		p("read_bytes_sec_max_length", lenOf(t.ReadBytesSecMax)),
		p("write_bytes_sec_max_length", lenOf(t.WriteBytesSecMax)),
		p("total_iops_sec_max_length", lenOf(t.TotalIopsSecMax)),
		p("read_iops_sec_max_length", lenOf(t.ReadIopsSecMax)),
		p("write_iops_sec_max_length", lenOf(t.WriteIopsSecMax)),
	}
}

// SetDiskIOTune applies a disk's I/O throttle: the persistent definition first
// (a live change a restart would discard is worse than a refused one), then the
// running domain. dev is the disk's target device ("vda"). A domain that is not
// running gets the persistent change only.
func (c *Client) SetDiskIOTune(domainName, dev string, t IOTune) error {
	if err := t.Validate(); err != nil {
		return err
	}
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	params := t.typedParams()
	if err := c.virt.DomainSetBlockIOTune(dom, dev, params, uint32(domainMemAffectConfig)); err != nil {
		return fmt.Errorf("set I/O limits on %s of %q (config): %w", dev, domainName, err)
	}
	if c.domainRunning(dom) {
		if err := c.virt.DomainSetBlockIOTune(dom, dev, params, uint32(domainMemAffectLive)); err != nil {
			return fmt.Errorf("set I/O limits on %s of %q (live): %w", dev, domainName, err)
		}
	}
	return nil
}

var (
	ioTuneBlockRe = regexp.MustCompile(`(?s)<iotune>.*?</iotune>\s*`)
	diskBlockRe   = regexp.MustCompile(`(?s)<disk\b.*?</disk>`)
)

// PatchDiskIOTune returns domXML with the <iotune> of the disk whose target is
// dev replaced (or removed, for a zero IOTune). It is what the in-memory fake
// applies, and the shape a test reads a rendered definition back with.
func PatchDiskIOTune(domXML, dev string, t IOTune) (string, error) {
	needle1, needle2 := "<target dev='"+dev+"'", `<target dev="`+dev+`"`
	found := false
	out := diskBlockRe.ReplaceAllStringFunc(domXML, func(block string) string {
		if !strings.Contains(block, needle1) && !strings.Contains(block, needle2) {
			return block
		}
		found = true
		block = ioTuneBlockRe.ReplaceAllString(block, "")
		el := t.element()
		if el == nil {
			return block
		}
		return strings.Replace(block, "</disk>", marshalIOTune(el)+"\n    </disk>", 1)
	})
	if !found {
		return "", fmt.Errorf("no disk with target %q", dev)
	}
	return out, nil
}

func marshalIOTune(el *diskIOTune) string {
	var b strings.Builder
	b.WriteString("  <iotune>")
	add := func(name string, v int64) {
		if v != 0 {
			fmt.Fprintf(&b, "<%s>%d</%s>", name, v, name)
		}
	}
	add("total_bytes_sec", el.TotalBytesSec)
	add("read_bytes_sec", el.ReadBytesSec)
	add("write_bytes_sec", el.WriteBytesSec)
	add("total_iops_sec", el.TotalIopsSec)
	add("read_iops_sec", el.ReadIopsSec)
	add("write_iops_sec", el.WriteIopsSec)
	add("total_bytes_sec_max", el.TotalBytesSecMax)
	add("read_bytes_sec_max", el.ReadBytesSecMax)
	add("write_bytes_sec_max", el.WriteBytesSecMax)
	add("total_iops_sec_max", el.TotalIopsSecMax)
	add("read_iops_sec_max", el.ReadIopsSecMax)
	add("write_iops_sec_max", el.WriteIopsSecMax)
	add("total_bytes_sec_max_length", el.TotalBytesSecMaxLen)
	add("read_bytes_sec_max_length", el.ReadBytesSecMaxLen)
	add("write_bytes_sec_max_length", el.WriteBytesSecMaxLen)
	add("total_iops_sec_max_length", el.TotalIopsSecMaxLen)
	add("read_iops_sec_max_length", el.ReadIopsSecMaxLen)
	add("write_iops_sec_max_length", el.WriteIopsSecMaxLen)
	b.WriteString("</iotune>")
	return b.String()
}

// DiskIOTuneFromXML reads back the throttle of the disk whose target is dev.
// ok is false when the domain has no such disk. A disk with no <iotune> is the
// zero IOTune.
func DiskIOTuneFromXML(domXML, dev string) (IOTune, bool) {
	var d struct {
		Disks []struct {
			Target diskTarget  `xml:"target"`
			IOTune *diskIOTune `xml:"iotune"`
		} `xml:"devices>disk"`
	}
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return IOTune{}, false
	}
	for _, disk := range d.Disks {
		if strings.TrimSpace(disk.Target.Dev) != dev {
			continue
		}
		e := disk.IOTune
		if e == nil {
			return IOTune{}, true
		}
		t := IOTune{
			TotalBytesSec: e.TotalBytesSec, ReadBytesSec: e.ReadBytesSec, WriteBytesSec: e.WriteBytesSec,
			TotalIopsSec: e.TotalIopsSec, ReadIopsSec: e.ReadIopsSec, WriteIopsSec: e.WriteIopsSec,
			TotalBytesSecMax: e.TotalBytesSecMax, ReadBytesSecMax: e.ReadBytesSecMax, WriteBytesSecMax: e.WriteBytesSecMax,
			TotalIopsSecMax: e.TotalIopsSecMax, ReadIopsSecMax: e.ReadIopsSecMax, WriteIopsSecMax: e.WriteIopsSecMax,
		}
		for _, l := range []int64{e.TotalBytesSecMaxLen, e.ReadBytesSecMaxLen, e.WriteBytesSecMaxLen,
			e.TotalIopsSecMaxLen, e.ReadIopsSecMaxLen, e.WriteIopsSecMaxLen} {
			if l > t.BurstSec {
				t.BurstSec = l
			}
		}
		return t, true
	}
	return IOTune{}, false
}

var (
	driverTagRe = regexp.MustCompile(`<driver\b[^>]*/?>`)
	attrRe      = func(name string) *regexp.Regexp { return regexp.MustCompile(`\s+` + name + `=(?:'[^']*'|"[^"]*")`) }
	macAttrRe   = regexp.MustCompile(`<mac\s+address=['"]([^'"]*)['"]`)
	ifaceBlock  = regexp.MustCompile(`(?s)<interface\b.*?</interface>`)
)

// setAttr returns a <driver .../> tag with attribute name set to val, or
// removed when val is empty.
func setDriverAttr(tag, name, val string) string {
	tag = attrRe(name).ReplaceAllString(tag, "")
	if val == "" {
		return tag
	}
	end := strings.LastIndex(tag, "/>")
	if end < 0 {
		end = strings.LastIndex(tag, ">")
	}
	return tag[:end] + " " + name + "='" + val + "'" + tag[end:]
}

// PatchInactiveDiskDriver sets (or, for "", removes) the discard and
// detect_zeroes attributes of the <driver> of the disk whose target is dev in
// the persistent definition. Patching rather than regenerating keeps the
// addresses libvirt assigned, which a guest may key licensing or a static NIC
// configuration off.
func PatchInactiveDiskDriver(domXML, dev, discard, detectZeroes string) (string, error) {
	needle1, needle2 := "<target dev='"+dev+"'", `<target dev="`+dev+`"`
	found := false
	out := diskBlockRe.ReplaceAllStringFunc(domXML, func(block string) string {
		if !strings.Contains(block, needle1) && !strings.Contains(block, needle2) {
			return block
		}
		found = true
		return driverTagRe.ReplaceAllStringFunc(block, func(tag string) string {
			tag = setDriverAttr(tag, "discard", discard)
			return setDriverAttr(tag, "detect_zeroes", detectZeroes)
		})
	})
	if !found {
		return "", fmt.Errorf("no disk with target %q", dev)
	}
	return out, nil
}

// PatchInactiveNICQueues sets the queue count of the interface with this MAC in
// the persistent definition (below 2 removes it). The <driver> element is
// created when the NIC has none, and removed again when nothing is left in it.
func PatchInactiveNICQueues(domXML, mac string, queues int) (string, error) {
	want := strings.ToLower(strings.TrimSpace(mac))
	found := false
	out := ifaceBlock.ReplaceAllStringFunc(domXML, func(block string) string {
		m := macAttrRe.FindStringSubmatch(block)
		if m == nil || strings.ToLower(m[1]) != want {
			return block
		}
		found = true
		val := ""
		if queues >= 2 {
			val = fmt.Sprint(queues)
		}
		if driverTagRe.MatchString(block) {
			return driverTagRe.ReplaceAllStringFunc(block, func(tag string) string {
				tag = setDriverAttr(tag, "queues", val)
				// A driver left holding nothing (or only the vhost name an earlier
				// build forced) goes away.
				rest := attrRe("name").ReplaceAllString(tag, "")
				if val == "" && strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rest, "<driver"), "/>")) == "" {
					return ""
				}
				return tag
			})
		}
		if val == "" {
			return block
		}
		return strings.Replace(block, "</interface>", "<driver queues='"+val+"'/>\n    </interface>", 1)
	})
	if !found {
		return "", fmt.Errorf("no interface with MAC %q", mac)
	}
	return out, nil
}
