package rulefield

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServicesFile is the services database nft resolves a port name against: it
// calls getaddrinfo, whose NSS "files" source reads this file. A name is
// matched exactly (nft refuses `dport SSH`), as a service's name or one of its
// aliases, under any protocol (`udp dport http` loads although http is listed
// for tcp only). With no file, nft resolves no name at all.
const ServicesFile = "/etc/services"

// services is this host's services database, re-read when the file changes.
var services = &serviceDB{path: ServicesFile}

type serviceDB struct {
	mu     sync.Mutex
	path   string
	mod    time.Time
	size   int64
	loaded bool
	ports  map[string]uint64 // name or alias → the first port listed for it
	fixed  map[string]uint64 // SetServicesForTest
}

// lookup is the port nft resolves name to, and whether it resolves.
func (d *serviceDB) lookup(name string) (uint64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fixed != nil {
		p, ok := d.fixed[name]
		return p, ok
	}
	fi, err := os.Stat(d.path)
	if err != nil {
		d.loaded, d.ports = false, nil
		return 0, false
	}
	if !d.loaded || !fi.ModTime().Equal(d.mod) || fi.Size() != d.size {
		data, err := os.ReadFile(d.path)
		if err != nil {
			d.loaded, d.ports = false, nil
			return 0, false
		}
		d.ports, d.mod, d.size, d.loaded = parseServices(data), fi.ModTime(), fi.Size(), true
	}
	p, ok := d.ports[name]
	return p, ok
}

// parseServices reads services(5) text: "name port/proto [aliases...]", with
// '#' starting a comment.
func parseServices(data []byte) map[string]uint64 {
	out := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		num, _, ok := strings.Cut(f[1], "/")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(num, 10, 16)
		if err != nil {
			continue
		}
		for _, name := range append([]string{f[0]}, f[2:]...) {
			if _, seen := out[name]; !seen {
				out[name] = port
			}
		}
	}
	return out
}

// SetServicesForTest makes the services database the given name → port map
// until the returned func restores it. Not for a parallel test.
func SetServicesForTest(ports map[string]uint64) (restore func()) {
	services.mu.Lock()
	prev := services.fixed
	services.fixed = ports
	services.mu.Unlock()
	return func() {
		services.mu.Lock()
		services.fixed = prev
		services.mu.Unlock()
	}
}

// KnownService reports whether nft on this host resolves the port name.
func KnownService(name string) bool {
	_, ok := services.lookup(name)
	return ok
}

// nftPortVal is a port word as nft reads it: 0x-hex, octal after a leading
// zero when every digit is octal (`026` is 22, `0000022` is 18), otherwise
// decimal (`08` is 8). ok is false for a word that is not a number.
// overflow reports a value too large to hold.
func nftPortVal(w string) (v uint64, ok, overflow bool) {
	if h, isHex := strings.CutPrefix(strings.ToLower(w), "0x"); isHex {
		if h == "" || strings.Trim(h, "0123456789abcdef") != "" {
			return 0, false, false
		}
		v, err := strconv.ParseUint(h, 16, 64)
		return v, true, err != nil
	}
	if w == "" || strings.Trim(w, "0123456789") != "" {
		return 0, false, false
	}
	base := 10
	if len(w) > 1 && w[0] == '0' && strings.Trim(w, "01234567") == "" {
		base = 8
	}
	v, err := strconv.ParseUint(w, base, 64)
	return v, true, err != nil
}

// portWords are the value words of a port match as nft reads them, lower
// case as the renderer writes them: the bitmask, then each list element, a
// range as its two ends. An unspaced dash after a number makes a range; after
// a letter it is part of a service name (netbios-ns).
func portWords(s string) [][]string {
	v := trimBlank(blanks(strings.ToLower(s)))
	var out [][]string
	mask, v := stripMask(v)
	if mask != "" {
		out = append(out, []string{mask})
	}
	v = stripOp(v)
	var elems []string
	if strings.HasPrefix(v, "{") {
		inner := strings.TrimSuffix(trimBlank(v[1:]), "}")
		for _, e := range strings.Split(inner, ",") {
			if e = trimBlank(e); e != "" {
				elems = append(elems, e)
			}
		}
	} else if v != "" {
		elems = []string{v}
	}
	for _, e := range elems {
		lo, hi, isRange := cutRange(e)
		if !isRange {
			if l, h, found := strings.Cut(e, "-"); found {
				if _, num, _ := nftPortVal(l); num {
					lo, hi, isRange = l, h, true
				}
			}
		}
		if isRange {
			out = append(out, []string{lo, hi})
		} else {
			out = append(out, []string{lo})
		}
	}
	return out
}

// PortUnresolvable is why nft on this host cannot resolve a port the renderer
// writes (tcp and udp), or "": a number outside 0-65535, a name not in the
// services database (ServicesFile), or a range whose end is below its start.
// nft refuses the whole ruleset over any of them.
func PortUnresolvable(proto, s string) string {
	if !RendersPort(proto) || s == "" {
		return ""
	}
	for _, words := range portWords(s) {
		var vals []uint64
		for _, w := range words {
			v, num, overflow := nftPortVal(w)
			if num {
				if overflow || v > 65535 {
					return fmt.Sprintf("port %s is outside 0-65535", w)
				}
			} else {
				p, ok := services.lookup(w)
				if !ok {
					return fmt.Sprintf("service %q is not in this host's services database (%s), so nft cannot resolve it", w, ServicesFile)
				}
				v = p
			}
			vals = append(vals, v)
		}
		if len(vals) == 2 && vals[0] > vals[1] {
			return fmt.Sprintf("range %s-%s runs backwards (%d-%d as nft reads it)", words[0], words[1], vals[0], vals[1])
		}
	}
	return ""
}
