// Package lb manages HAProxy + keepalived for VRRP-based load balancing.
package lb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"text/template"
)

// deriveAuthPass returns a per-LB VRRP authentication password. keepalived
// truncates auth_pass to 8 characters, so we take the first 8 hex chars of a
// salted SHA-256 of the LB name. This is NOT cryptographically secret (VRRP
// PASS auth is plaintext on the wire and sniffable on the L2 segment); its
// purpose is to give each LB a distinct password so two unrelated VRRP
// instances on the same segment can't accidentally pair up. Rely on L2
// segmentation for actual security. (F6: was a single hardcoded "litevirt".)
func deriveAuthPass(name string) string {
	sum := sha256.Sum256([]byte("litevirt-vrrp:" + name))
	return hex.EncodeToString(sum[:])[:8]
}

// Config holds everything needed to render HAProxy + keepalived configs for one LB instance.
type Config struct {
	Name      string // e.g. "app-server"
	VIP       string // e.g. "10.0.100.100"
	VIPPrefix int    // CIDR prefix length
	Interface string // the device the VIP goes on (and, unless VRRPUnicast, VRRP's)
	VRID      int    // VRRP virtual router ID (1–255, unique per VIP)
	Priority  int    // 100 = master, 50 = backup
	Backends  []Backend
	Ports     []Port
	Algorithm string        // roundrobin | leastconn | source
	Health    *HealthConfig // backend health check (nil = default tcp-check)
	Sticky    bool          // keep a client on one backend by its source address

	// VRRPUnicast sends this LB's VRRP adverts as unicast from UnicastSrc to
	// UnicastPeers over VRRPInterface, the device holding this host's own
	// address, and accepts adverts only from those peers. The VIP still goes
	// on Interface, named on its line, and Interface is tracked, so nothing
	// VRRP is sent on, or taken from, the segment the VIP's guests are on.
	// Off: adverts are multicast on Interface with a PASS password, as every
	// LB was before vrrp_unicast_v1, which guests on that segment can read and
	// answer.
	VRRPUnicast   bool
	VRRPInterface string
	UnicastSrc    string
	// UnicastPeers are the other LB hosts' addresses. None: a sole host,
	// which names itself (see the template).
	UnicastPeers []string

	// SNAT fields — set when LB provides outbound NAT for host-isolated VMs.
	SNATEnabled bool   // enable SNAT + conntrackd
	LocalIP     string // this host's IP for conntrackd sync
	PeerIP      string // VRRP peer IP for conntrackd sync
	Subnet      string // VM subnet CIDR for SNAT rule (e.g. "10.100.0.0/24")
	// SyncInterface is the device holding LocalIP, which conntrackd syncs
	// over. Empty: Interface.
	SyncInterface string
	// KeepSNAT leaves this LB's SNAT side as the last apply that set it left
	// it: conntrackd and its files untouched, and keepalived's notify hooks
	// rendered exactly when the notify script is there. For an apply that
	// does not know the LB's snat (a peer on an earlier build).
	KeepSNAT bool

	// ConfigDir is the directory the manager writes this LB's files to, which
	// the rendered configs name (TLS PEMs, the notify script, conntrackd's
	// config). Empty: DefaultConfigDir.
	ConfigDir string
}

// DefaultConfigDir is where the manager writes LB configs in production.
const DefaultConfigDir = "/etc/litevirt/lb"

// withDefaults returns cfg ready to render, or an error when it may not be
// rendered at all (checkRender).
func withDefaults(cfg Config) (Config, error) {
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = DefaultConfigDir
	}
	if err := checkRender(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// HealthConfig configures HAProxy backend health checking.
type HealthConfig struct {
	Type       string // "tcp" | "http" (default: tcp)
	Path       string // HTTP health check path (only for type "http")
	IntervalMS int    // check interval in milliseconds (0 = default 2000)
}

// Backend is a single VM instance behind the LB.
type Backend struct {
	Name string
	IP   string
	Port int
}

// Port is a listener on the VIP.
type Port struct {
	Listen   int
	Target   int    // backend port
	Protocol string // tcp | http
	TLS      *TLSConfig
	// RedirectHTTPS answers every request on this listener with a redirect
	// to https. Ignored on a TLS listener.
	RedirectHTTPS bool
}

// TLSConfig holds cert/key paths for TLS termination.
type TLSConfig struct {
	Cert string
	Key  string
}

const haproxyTmplStr = `
global
    log /dev/log local0
    maxconn 4096
    user haproxy
    group haproxy
    daemon
    stats socket /run/litevirt/lb/{{.Name}}-haproxy.sock mode 660 level admin
    stats timeout 30s

defaults
    log     global
    mode    tcp
    option  tcplog
    retries 3
    timeout connect 5s
    timeout client  30s
    timeout server  30s

{{- range .Ports}}
frontend {{$.Name}}-{{.Listen}}
    {{- if .TLS}}
    bind {{$.VIP}}:{{.Listen}} ssl crt {{$.ConfigDir}}/{{$.Name}}-{{.Listen}}.pem
    {{- else}}
    bind {{$.VIP}}:{{.Listen}}
    {{- end}}
    {{- if and .RedirectHTTPS (not .TLS)}}
    mode http
    http-request redirect scheme https code 301
    {{- else}}
    default_backend {{$.Name}}-{{.Listen}}-be
    {{- end}}

backend {{$.Name}}-{{.Listen}}-be
    balance {{$.Algorithm}}
    {{- if $.Sticky}}
    stick-table type ip size 100k expire 30m
    stick on src
    {{- end}}
    {{- if and $.Health (eq $.Health.Type "http")}}
    option httpchk GET {{or $.Health.Path "/"}}
    http-check expect status 200
    {{- else}}
    option tcp-check
    {{- end}}
    {{- range $.Backends}}
    server {{.Name}} {{.IP}}:{{.Port}} check inter {{checkInterval $}} rise 2 fall 3
    {{- end}}
{{- end}}
`

// keepalivedTmpl renders one vrrp_instance. With VRRPUnicast, the source check
// is rendered twice: check_unicast_src in the instance (keepalived 2.1 on) and
// vrrp_check_unicast_src in global_defs, which 2.0 also honours (it has no
// instance keyword). With VRRPUnicast and no peers (a
// sole LB host) it names the host itself as its peer, with a TTL range no
// packet is in: keepalived cannot run unicast with no peers (it falls back to
// multicast on the interface), and this way its adverts go only to itself over
// loopback and are discarded, nothing is accepted from anyone, and it becomes
// master on its own.
var keepalivedTmpl = template.Must(template.New("keepalived").Parse(`
global_defs {
    enable_script_security
    script_user root
{{- if .VRRPUnicast}}
    vrrp_check_unicast_src
{{- end}}
}

vrrp_script chk_haproxy {
    script "/usr/bin/pgrep -f {{.Name}}-haproxy.cfg"
    interval 2
    weight 2
    rise 2
    fall 3
}

vrrp_instance {{.Name}} {
    state {{if eq .Priority 100}}MASTER{{else}}BACKUP{{end}}
{{- if .VRRPUnicast}}
    interface {{.VRRPInterface}}
    virtual_router_id {{.VRID}}
    priority {{.Priority}}
    advert_int 1

    unicast_src_ip {{.UnicastSrc}}
    unicast_peer {
{{- range .UnicastPeers}}
        {{.}}
{{- else}}
        {{.UnicastSrc}} min_ttl 0 max_ttl 0
{{- end}}
    }
    check_unicast_src
{{- if ne .Interface .VRRPInterface}}

    track_interface {
        {{.Interface}}
    }
{{- end}}

    virtual_ipaddress {
        {{.VIP}}/{{.VIPPrefix}} dev {{.Interface}}
    }
{{- else}}
    interface {{.Interface}}
    virtual_router_id {{.VRID}}
    priority {{.Priority}}
    advert_int 1

    authentication {
        auth_type PASS
        auth_pass {{.AuthPass}}
    }

    virtual_ipaddress {
        {{.VIP}}/{{.VIPPrefix}}
    }
{{- end}}

    track_script {
        chk_haproxy
    }
{{- if .SNATEnabled}}

    notify_master "{{.ConfigDir}}/{{.Name}}-notify.sh MASTER"
    notify_backup "{{.ConfigDir}}/{{.Name}}-notify.sh BACKUP"
    notify_fault  "{{.ConfigDir}}/{{.Name}}-notify.sh FAULT"
{{- end}}
}
`))

// RenderHAProxy produces an haproxy.cfg content string.
func RenderHAProxy(cfg Config) (string, error) {
	cfg, err := withDefaults(cfg)
	if err != nil {
		return "", err
	}
	if cfg.Algorithm == "" {
		cfg.Algorithm = "roundrobin"
	}

	funcs := template.FuncMap{
		"checkInterval": func(cfg Config) string {
			if cfg.Health != nil && cfg.Health.IntervalMS > 0 {
				return fmt.Sprintf("%dms", cfg.Health.IntervalMS)
			}
			return "2s"
		},
	}
	tmpl, err := template.New("haproxy").Funcs(funcs).Parse(haproxyTmplStr)
	if err != nil {
		return "", fmt.Errorf("parse haproxy template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		return "", fmt.Errorf("render haproxy config: %w", err)
	}
	return buf.String(), nil
}

// RenderKeepalived produces a keepalived.conf content string.
//
// INVARIANT: the template emits EXACTLY ONE address in the virtual_ipaddress block
// (a single {{.VIP}}/{{.VIPPrefix}} per LB). parseKeepalivedVIP relies on this — it
// returns the sole address in that block — so if this template is ever changed to render
// multiple VIPs per instance, parseKeepalivedVIP + DemoteAll must be revisited to
// enumerate all of them (today "one LB ⇒ one VIP" makes single-address parsing exact).
func RenderKeepalived(cfg Config) (string, error) {
	cfg, err := withDefaults(cfg)
	if err != nil {
		return "", err
	}
	// One order whatever order the hosts came in, so the same peers render the
	// same config (and keepalived is not restarted over a reorder).
	cfg.UnicastPeers = append([]string(nil), cfg.UnicastPeers...)
	sort.Strings(cfg.UnicastPeers)
	var buf bytes.Buffer
	// Augment cfg with a derived, per-LB VRRP auth password (F6).
	data := struct {
		Config
		AuthPass string
	}{Config: cfg, AuthPass: deriveAuthPass(cfg.Name)}
	if err := keepalivedTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render keepalived config: %w", err)
	}
	return buf.String(), nil
}

// RenderConntrackd produces a conntrackd.conf for SNAT conntrack sync between VRRP peers.
func RenderConntrackd(cfg Config) (string, error) {
	cfg, err := withDefaults(cfg)
	if err != nil {
		return "", err
	}
	if cfg.LocalIP == "" || cfg.PeerIP == "" {
		return "", fmt.Errorf("conntrackd requires LocalIP and PeerIP")
	}
	var buf bytes.Buffer
	if err := conntrackdTmpl.Execute(&buf, cfg); err != nil {
		return "", fmt.Errorf("render conntrackd config: %w", err)
	}
	return buf.String(), nil
}

// RenderNotifyScript produces the keepalived notify script for conntrackd state transitions.
func RenderNotifyScript(cfg Config) (string, error) {
	cfg, err := withDefaults(cfg)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := notifyTmpl.Execute(&buf, cfg); err != nil {
		return "", fmt.Errorf("render notify script: %w", err)
	}
	return buf.String(), nil
}

var conntrackdTmpl = template.Must(template.New("conntrackd").Parse(`Sync {
    Mode FTFW {}
    UDP {
        IPv4_address {{.LocalIP}}
        IPv4_Destination_Address {{.PeerIP}}
        Port 3780
        Interface {{or .SyncInterface .Interface}}
    }
}

General {
    Nice -20
    HashSize 32768
    HashLimit 131072
    Syslog on
    LockFile /var/lock/conntrack-{{.Name}}.lock
    UNIX { Path /var/run/conntrackd-{{.Name}}.ctl }
    NetlinkBufferSize 2097152
    NetlinkBufferSizeMaxGrowth 8388608
    Filter From Userspace {
        Protocol Accept { TCP UDP }
        Address Accept { IPv4_address {{.Subnet}} }
    }
}
`))

// notifyTmpl drives this LB's conntrackd on a VRRP transition. conntrackd's
// -C names its CONFIG file, which says where its control socket is.
var notifyTmpl = template.Must(template.New("notify").Parse(`#!/bin/bash
CONF="{{.ConfigDir}}/{{.Name}}-conntrackd.conf"
case "$1" in
    MASTER)
        conntrackd -C "$CONF" -c
        conntrackd -C "$CONF" -f
        conntrackd -C "$CONF" -R
        conntrackd -C "$CONF" -B
        ;;
    BACKUP)
        conntrackd -C "$CONF" -t
        conntrackd -C "$CONF" -n
        ;;
    FAULT)
        conntrackd -C "$CONF" -t
        ;;
esac
`))

// ParseVIP splits "10.0.100.100/24" into IP and prefix length.
func ParseVIP(vip string) (ip string, prefix int, err error) {
	// net.ParseIP, not a bare split. Without it anything lacking a "/" came back
	// verbatim as an address, so `--vip '*'` was accepted — and that string is
	// rendered into keepalived's virtual_ipaddress (where the failure is only
	// logged, so the VIP silently never comes up) and, on an isolated bridge,
	// into an nftables rule, where `nft -f` rejects the WHOLE ruleset and every
	// later firewall reconcile on that host fails with it.
	ip, cidr, hasPrefix := strings.Cut(vip, "/")

	addr := net.ParseIP(ip)
	if addr == nil {
		return "", 0, fmt.Errorf("invalid VIP address %q", vip)
	}
	// IPv4 only, and not as a style preference. internal/firewall refuses any
	// exception VIP containing ":" and fails the ENTIRE plan when it sees one,
	// so an IPv6 VIP does not degrade — it breaks every later firewall
	// reconcile on that host, which is the same blast radius this validator
	// exists to prevent. keepalived's rendering here is IPv4-shaped too, and
	// the rest of the tree already refuses IPv6 at its entry points
	// (advertise_address, resolveHost).
	// strings.Contains(ip, ":"), not just To4() == nil. A v4-mapped literal like
	// "::ffff:10.0.0.1" HAS a To4() form, so a family check alone lets it
	// through — and it is the textual value that gets stored and handed to
	// internal/firewall, whose refusal is literally
	// `strings.Contains(exc.VIP, ":")`. Match that test exactly.
	if addr.To4() == nil || strings.Contains(ip, ":") {
		return "", 0, fmt.Errorf("invalid VIP %q: must be IPv4 (the firewall and keepalived paths cannot carry IPv6)", vip)
	}

	// Width of the address family, which is both the default and the ceiling.
	const width = 32
	if !hasPrefix {
		return ip, width, nil
	}

	// strconv, not Sscanf("%d"): Sscanf stops at the first non-digit and reports
	// success, so "/3.5" and "/24junk" were read as 3 and 24.
	prefix, err = strconv.Atoi(cidr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid VIP CIDR %q", vip)
	}
	if prefix < 0 || prefix > width {
		return "", 0, fmt.Errorf("invalid VIP CIDR %q: prefix must be between 0 and %d", vip, width)
	}
	return ip, prefix, nil
}
