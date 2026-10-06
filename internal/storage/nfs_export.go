package storage

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// NFSExport is an NFS source ("server:/export") in canonical form, so one
// export written two ways is recognised as one: the server lower-cased, or an
// IP address in its canonical form (IPv6 compressed and lower-cased, brackets
// stripped, an IPv4-mapped address as IPv4), and the export path cleaned (no
// trailing slash).
type NFSExport struct {
	Server string
	Path   string
}

// ParseNFSExport parses and canonicalises an NFS source.
func ParseNFSExport(source string) (NFSExport, error) {
	bad := fmt.Errorf("nfs source %q is not server:/export", source)
	var host, rest string
	if strings.HasPrefix(source, "[") {
		end := strings.Index(source, "]:")
		if end < 0 {
			return NFSExport{}, bad
		}
		a, err := netip.ParseAddr(source[1:end])
		if err != nil || a.Zone() != "" {
			return NFSExport{}, bad
		}
		host, rest = a.Unmap().String(), source[end+2:]
	} else {
		var ok bool
		host, rest, ok = strings.Cut(source, ":")
		if !ok || host == "" {
			return NFSExport{}, bad
		}
		if a, err := netip.ParseAddr(host); err == nil {
			host = a.Unmap().String()
		} else {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
		}
	}
	if !strings.HasPrefix(rest, "/") {
		return NFSExport{}, bad
	}
	return NFSExport{Server: host, Path: filepath.Clean(rest)}, nil
}

func (e NFSExport) String() string {
	if strings.Contains(e.Server, ":") {
		return "[" + e.Server + "]:" + e.Path
	}
	return e.Server + ":" + e.Path
}

// PathsOverlap reports whether the two export paths are the same or one is
// inside the other, whatever their servers. "/" (an NFSv4 pseudo-root)
// contains every export of its server.
func (e NFSExport) PathsOverlap(o NFSExport) bool {
	return within(e.Path, o.Path) || within(o.Path, e.Path)
}

// NFSExportKey is an NFS source in canonical form (ParseNFSExport); a source
// that does not parse is returned as it is.
func NFSExportKey(source string) string {
	e, err := ParseNFSExport(source)
	if err != nil {
		return source
	}
	return e.String()
}

// lookupNFSServer resolves an NFS server's name; tests replace it.
var lookupNFSServer = func(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ResolveNFSServer returns the addresses of a canonical server (NFSExport's
// Server): an IP address is itself, a name is looked up. A name that resolves
// to nothing is an error.
func ResolveNFSServer(ctx context.Context, server string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(server); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	addrs, err := lookupNFSServer(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("resolve NFS server %q: %w", server, err)
	}
	var out []netip.Addr
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("resolve NFS server %q: no addresses", server)
	}
	return out, nil
}

// SharesAddress reports whether two servers' address sets meet: servers that
// share any address are one server.
func SharesAddress(a, b []netip.Addr) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// OverrideNFSResolverForTest replaces how NFS server names are resolved, for
// tests in other packages. It returns the restore function.
func OverrideNFSResolverForTest(f func(ctx context.Context, host string) ([]netip.Addr, error)) func() {
	prev := lookupNFSServer
	lookupNFSServer = f
	return func() { lookupNFSServer = prev }
}
