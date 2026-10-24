// Package compose parses litevirt compose YAML files and generates execution plans.
package compose

import (
	"fmt"
	"net/netip"
	"strings"
)

// File is the top-level compose document.
type File struct {
	Version  string                `yaml:"version"`
	Name     string                `yaml:"name"`
	Images   map[string]ImageDef   `yaml:"images"`
	Networks map[string]NetworkDef `yaml:"networks"`
	Volumes  map[string]VolumeDef  `yaml:"volumes"`
	VMs      map[string]VMDef      `yaml:"vms"`
	// Workloads is the unified container/VM map; entries with
	// `kind: lxc | oci` route to the Containers runtime. Entries
	// without `kind:` (or `kind: vm`) behave identically to a `vms:`
	// entry. The parser folds `workloads:` into `VMs` after load so
	// existing compose code only needs to look at `VMs`.
	Workloads     map[string]VMDef  `yaml:"workloads,omitempty"`
	DNS           *DNSDef           `yaml:"dns"`
	Notifications *NotificationsDef `yaml:"notifications"`

	// BackupRepos registers logical backup-repo name → path mappings for the
	// cluster, so a VM's `backup: { repo: <name> }` resolves without editing
	// daemon config. CRDT-replicated; removed when the stack is deleted.
	BackupRepos map[string]BackupRepoDef `yaml:"backup-repos,omitempty"`

	// SecurityGroups defines reusable rule sets that NICs reference by
	// name (NetworkAttachment.SecurityGroups). distributed
	// firewall.
	SecurityGroups map[string]SecurityGroupDef `yaml:"security-groups,omitempty"`

	// IPSets defines named address lists. Rules can reference one with
	// `cidr: "@<ipset-name>"`. Same scoping as SecurityGroups.
	IPSets map[string]IPSetDef `yaml:"ipsets,omitempty"`

	// FirewallDefaults sets cluster-wide policy + cluster-tier rules
	// that apply to every NIC under this stack. Per-host overrides
	// live in the host config rather than compose.
	FirewallDefaults *FirewallDefaultsDef `yaml:"firewall,omitempty"`
}

// SecurityGroupDef is a named bundle of firewall rules.
type SecurityGroupDef struct {
	Description string            `yaml:"description,omitempty"`
	Rules       []FirewallRuleDef `yaml:"rules"`
}

// IPSetDef is a named CIDR list, rendered as an nftables set object.
type IPSetDef struct {
	Description string   `yaml:"description,omitempty"`
	CIDRs       []string `yaml:"cidrs"`
}

// BackupRepoDef registers a logical backup-repo name → on-disk path.
type BackupRepoDef struct {
	Path string `yaml:"path"`
}

// FirewallRuleDef is one rule inside a security group or the firewall
// defaults block. Mirrors internal/firewall.Rule but lives in the
// compose package so YAML stays free of internal types.
type FirewallRuleDef struct {
	Direction string `yaml:"direction"`        // "ingress" | "egress"
	Proto     string `yaml:"proto,omitempty"`  // "tcp" | "udp" | "icmp" | "all"
	Port      string `yaml:"port,omitempty"`   // "80" | "8000-9000"
	CIDR      string `yaml:"cidr,omitempty"`   // CIDR or "@ipset"
	Action    string `yaml:"action,omitempty"` // "accept" | "drop" | "reject"
	Comment   string `yaml:"comment,omitempty"`
	// Log logs each packet the rule matches (docs/firewall.md, "Logging").
	Log bool `yaml:"log,omitempty"`
	// Macro names a rule macro (internal/firewall.Macros) in place of proto
	// and port. The parser expands it into one ordinary row per macro row,
	// so no later stage sees a macro.
	Macro string `yaml:"macro,omitempty"`
	// Priority is set by macro expansion, never read from YAML: every row of
	// the rule at index i has (i+1)*10. Zero means the deployer numbers the
	// row by its position.
	Priority int `yaml:"-"`
}

// FirewallDefaultsDef sets cluster-tier rules and the default policy.
type FirewallDefaultsDef struct {
	// DefaultDeny, when true, makes the forward chain's default policy
	// drop. Anything not explicitly accepted is dropped. Reply traffic
	// is always allowed (conntrack established/related).
	DefaultDeny bool `yaml:"default-deny,omitempty"`
	// ClusterRules apply before per-NIC rules. Use them for blanket
	// allow/deny that should never be overridden.
	ClusterRules []FirewallRuleDef `yaml:"cluster-rules,omitempty"`
}

// ImageDef describes a base image reference.
type ImageDef struct {
	Source   string `yaml:"source"`
	Format   string `yaml:"format"` // qcow2 | iso
	Checksum string `yaml:"checksum"`
}

// NetworkDef describes a logical network.
type NetworkDef struct {
	Type          string   `yaml:"type"`      // bridge | vxlan | isolated | sriov | direct
	Interface     string   `yaml:"interface"` // bridge name on host
	VLAN          int      `yaml:"vlan"`
	VNI           int      `yaml:"vni"`
	Underlay      string   `yaml:"underlay"`
	Learning      bool     `yaml:"learning"`
	Port          int      `yaml:"port"`
	Subnet        string   `yaml:"subnet"`
	DHCP          bool     `yaml:"dhcp"`
	NAT           *bool    `yaml:"nat"` // enable NAT/masquerade (default true)
	PF            string   `yaml:"pf"`  // SR-IOV physical function
	SpoofCheck    bool     `yaml:"spoof-check"`
	External      bool     `yaml:"external"`       // use pre-existing network, don't create/destroy
	HostIsolation bool     `yaml:"host-isolation"` // block VM→host management traffic
	DNS           []string `yaml:"dns"`            // DNS resolvers for isolated VMs (default: 1.1.1.1, 8.8.8.8)

	// Gateway is the network's router when it is not litevirt's own: the
	// address of the upstream router on an external or VLAN bridge. Setting it
	// also says the subnet's first host is NOT the router (LitevirtGateway).
	// ReservedAddresses are further infrastructure addresses on the network (a
	// second router, a VRRP address, the IPv6 router). No guest NIC may claim
	// either, and a NIC guard confined to the subnet excludes them.
	Gateway           string   `yaml:"gateway"`
	ReservedAddresses []string `yaml:"reserved-addresses"`

	// AllowedVLANs are the VLANs a NIC on the `trunk:` feature may carry on
	// this network: a trunk NIC created on this release carries only those of
	// its trunk VLANs listed here (docs/firewall.md, "VLAN tags"). Setting it
	// needs network.update on the network.
	AllowedVLANs []int `yaml:"allowed-vlans"`
	// KeptVLANs are the VLANs litevirt itself put on AllowedVLANs, never set
	// from a compose file: the trunk VLANs in use when the cluster upgraded,
	// and those a network row took over from the flat bridge of its name
	// (re-review R4-I2). A VLAN here and not on AllowedVLANs is one an
	// operator removed, and stays removed; a re-deploy of the network, which
	// writes its definition verbatim, keeps the others (re-review m6).
	KeptVLANs []int `yaml:"-"`
	// AllowUnfilteredAccessVLANMoves lets `lv migrate` and `lv host drain`
	// move a VM with an access-VLAN NIC (trunk: with one VLAN) on this
	// network onto a host whose bridge does not filter VLANs — onto that
	// bridge's untagged segment. Off by default. Never set from a compose
	// file: only `lv network set --allow-unfiltered-access-vlan-moves`
	// (admin, audited) sets it, and a re-deploy of the network keeps it.
	// Omitted from the stored JSON while off, and an older node, which does
	// not know the key, ignores it (it does not refuse such moves anyway).
	AllowUnfilteredAccessVLANMoves bool `yaml:"-" json:",omitempty"`

	// NetBoxPrefixID binds this network to a NetBox prefix. Zero means unbound,
	// which is every network today.
	//
	// This field needs NO migration: network defs are persisted as
	// json.Marshal(def) into networks.config, and nothing in the tree decodes
	// strictly, so an older node ignores the unknown key. What actually makes a
	// mixed-version cluster safe is the netbox_ipam_v1 latch, because an older
	// node would otherwise allocate from the builtin allocator across the prefix.
	NetBoxPrefixID int `yaml:"netbox-prefix-id"`
}

// HostIsolatedAddressable reports whether litevirt itself gives the
// addresses of the network's guests that name none: a host-isolated network
// runs no DHCP server on any host, so its guests are addressed through
// cloud-init from the network's subnet. IPv4 subnets on the types litevirt
// addresses; sriov and direct attach guests to hardware litevirt does not
// address, and a NetBox-bound network's addresses are NetBox's.
func (n NetworkDef) HostIsolatedAddressable() bool {
	if !n.HostIsolation || n.Subnet == "" || n.NetBoxPrefixID != 0 {
		return false
	}
	switch n.Type {
	case "", "bridge", "vxlan", "isolated":
	default:
		return false
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(n.Subnet))
	return err == nil && p.Addr().Is4()
}

// LitevirtGateway is the address litevirt itself puts on the network's bridge
// — the subnet's first host — on a network whose dnsmasq or router litevirt
// runs: one it serves DHCP for (where guests send DHCP and DNS), or routes (a
// vxlan network's anycast gateway, an isolated network, a bridge litevirt
// manages). It is protected whatever Gateway names: a network's configured
// gateway is its upstream router, and dnsmasq still answers on the first host
// (re-review R2-I5). "" where litevirt runs neither: a VLAN or external bridge
// with no DHCP, a host-isolated network. A superset of where
// network.DHCPWouldServe starts dnsmasq (TestLitevirtGatewayCoversDHCP).
func (n NetworkDef) LitevirtGateway() string {
	if n.Subnet == "" || n.HostIsolation {
		return ""
	}
	switch n.Type {
	case "", "bridge":
		if n.VLAN != 0 || (n.External && !n.DHCP) {
			return ""
		}
	case "vxlan", "isolated":
	default:
		return ""
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(n.Subnet))
	if err != nil || p.Addr().Zone() != "" {
		return ""
	}
	p = p.Masked()
	gw := p.Addr().Next()
	if !p.Contains(gw) {
		return ""
	}
	return gw.String()
}

// NATEnabled returns true unless NAT is explicitly disabled.
func (n NetworkDef) NATEnabled() bool {
	if n.NAT == nil {
		return true
	}
	return *n.NAT
}

// Workloads is the unified container/VM map. Each entry has a Kind
// discriminator: "vm" (default) for a libvirt-managed VM, or "lxc" /
// "oci" for a container. Existing stacks that use the legacy `vms:`
// map keep working because the parser folds it into Workloads with
// Kind="vm".
type WorkloadKind string

const (
	WorkloadKindVM  WorkloadKind = "vm"
	WorkloadKindLXC WorkloadKind = "lxc"
	WorkloadKindOCI WorkloadKind = "oci"
)

// VolumeDef describes a named volume / disk pool.
//
// Supported drivers:
//
//	local     — qcow2 files under <dataDir>/disks (or Target).
//	dir       — qcow2 files under an operator-specified Target directory.
//	nfs       — Source is "host:/export"; mounted lazily under Target.
//	iscsi     — Source is the IQN; LUNs are pre-provisioned on the SAN.
//	ceph      — Source is the pool name; rbd CLI shell-out.
//	zfs       — Source is the parent dataset (e.g. "tank/litevirt").
//	btrfs     — Source is an absolute path on a btrfs filesystem.
//	lvm-thin  — Source is the VG; options.thinpool is required.
type VolumeDef struct {
	Driver  string            `yaml:"driver"`
	Source  string            `yaml:"source"`
	Target  string            `yaml:"target"`
	Options map[string]string `yaml:"options"`
}

// VMDef is a full VM specification inside a compose file. Despite the
// name it covers containers too — the Kind field discriminates. New
// stacks should use the unified `workloads:` map; `vms:` is preserved
// as a legacy alias that defaults Kind to vm.
type VMDef struct {
	// Service inheritance — resolved before validation.
	Extends string `yaml:"extends"`

	// Kind selects the runtime: "vm" (default), "lxc", or "oci".
	// "oci" pulls an OCI image and runs it as an LXC container.
	Kind WorkloadKind `yaml:"kind,omitempty"`

	// Container security opt-outs (kind lxc/oci only; docs/containers.md,
	// "Security"): privileged creates the container without a user namespace,
	// confinement "legacy" allows AppArmor nesting with the template's seccomp
	// and capabilities ("default" or unset: the default confinement). Deploying
	// either needs the Admin role.
	Privileged  bool   `yaml:"privileged,omitempty"`
	Confinement string `yaml:"confinement,omitempty"`

	// Image & Boot
	Image    string `yaml:"image"`
	ISO      string `yaml:"iso"`
	Firmware string `yaml:"firmware"` // uefi | bios
	Machine  string `yaml:"machine"`  // q35 | pc

	// UEFI Secure Boot (uefi + q35) and a vTPM, as lv run --secure-boot
	// --tpm. Toggling either on an existing VM is a restart-class update.
	SecureBoot bool `yaml:"secure-boot"`
	TPM        bool `yaml:"tpm"`

	// Compute
	CPU      int    `yaml:"cpu"`
	MaxCPU   int    `yaml:"max-cpu"`   // vCPU hotplug ceiling (> cpu) for live CPU hot-add; requires live_resize
	CPUMode  string `yaml:"cpu-mode"`  // host-passthrough | host-model | custom (unset → host-model)
	CPUModel string `yaml:"cpu-model"` // CPU model for cpu-mode: custom (e.g. x86-64-v3)
	// Noisy-neighbour controls, both changeable on a running VM with no restart.
	// cpu-limit caps the VM's total CPU in host cores (Proxmox cpulimit; fractions
	// allowed, 0/unset = unlimited, at most cpu). cpu-shares is its relative CPU
	// weight under contention (libvirt shares, default 1024; range 2-262144).
	CPULimit  float64 `yaml:"cpu-limit"`
	CPUShares int     `yaml:"cpu-shares"`
	Memory    Memory  `yaml:"memory"` // int MiB or string "8G"
	// Memory ballooning (#4). max-memory (> memory) raises the balloon ceiling
	// so the guest can be inflated up to it; min-memory is the floor the host may
	// reclaim to. Both accept int MiB or "8G" strings. 0/unset = fixed memory.
	MinMemory Memory `yaml:"min-memory"`
	MaxMemory Memory `yaml:"max-memory"`

	// Boot ordering (#10). onboot autostarts the VM when its host boots;
	// startup-order sequences onboot VMs (lower first); start-delay/stop-delay
	// pace the ordered start/stop.
	Onboot       bool `yaml:"onboot"`
	StartupOrder int  `yaml:"startup-order"`
	StartDelay   int  `yaml:"start-delay"`
	StopDelay    int  `yaml:"stop-delay"`

	// Replicas — pointer so we can distinguish "omitted" (nil → default 1)
	// from explicit "replicas: 0" (scale-to-zero).
	Replicas *int `yaml:"replicas"`

	// Guest agent
	GuestAgent *bool `yaml:"guest-agent"`

	// Graphics console preferences. Empty = VNC only (default).
	// `vnc: false` → headless. `spice: true` → add a SPICE device alongside VNC.
	Graphics *GraphicsDef `yaml:"graphics"`

	// Disks — supports both shorthand ("root: 20G") and full form
	Disks map[string]DiskDef `yaml:"disks"`

	// Network interfaces
	Network []NetworkAttachment `yaml:"network"`

	// Cloud-init
	CloudInit *CloudInitDef `yaml:"cloud-init"`

	// Placement
	Placement *PlacementDef `yaml:"placement"`

	// Migration policy
	Migrate *MigrateDef `yaml:"migrate"`

	// Update strategy
	Update *UpdateDef `yaml:"update"`

	// Load balancer
	LoadBalancer *LBDef `yaml:"loadbalancer"`

	// Health check
	HealthCheck *HealthCheckDef `yaml:"healthcheck"`

	// Lifecycle hooks
	Hooks *HooksDef `yaml:"hooks"`

	// Shutdown timeout
	StopGracePeriod string `yaml:"stop-grace-period"` // "30s", "2m" — ACPI shutdown timeout

	// Restart policy
	Restart *RestartDef `yaml:"restart"`

	// PCI device passthrough
	Devices []DeviceDef `yaml:"devices"`

	// Resource tuning
	Resources *ResourcesDef `yaml:"resources"`

	// Boot ordering
	DependsOn DependsOn `yaml:"depends-on"`

	// Labels
	Labels map[string]string `yaml:"labels"`

	// IP hint for non-cloud-init VMs
	IPHint string `yaml:"ip-hint"`

	// Backup configuration.
	// When unset the VM is not backed up by the scheduler — operators
	// can still take ad-hoc snapshots via `lv backup`.
	Backup *BackupDef `yaml:"backup"`
}

// BackupDef configures the PBS-equivalent backup pipeline for one VM.
// repo names a backup repository configured in the cluster ("backup-repos:"
// stanza). schedule is a cron expression evaluated by internal/scheduler;
// retention runs after each successful push.
type BackupDef struct {
	Repo       string        `yaml:"repo"`
	Schedule   string        `yaml:"schedule"` // cron (e.g. "0 2 * * *")
	Retention  *RetentionDef `yaml:"retention,omitempty"`
	Encryption string        `yaml:"encryption,omitempty"` // "" | "aes256gcm" | "tenant-key"
}

// RetentionDef expresses the same N daily / N weekly / N monthly /
// N yearly buckets as Proxmox PBS.
type RetentionDef struct {
	KeepLast    int `yaml:"keep-last"`
	KeepDaily   int `yaml:"keep-daily"`
	KeepWeekly  int `yaml:"keep-weekly"`
	KeepMonthly int `yaml:"keep-monthly"`
	KeepYearly  int `yaml:"keep-yearly"`
}

// Memory accepts both int (MiB) and string ("8G") YAML values.
type Memory int

func (m *Memory) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try int first
	var i int
	if err := unmarshal(&i); err == nil {
		*m = Memory(i)
		return nil
	}
	// Try string like "8G", "512M"
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	v, err := parseMemoryString(s)
	if err != nil {
		return fmt.Errorf("invalid memory value %q: %w", s, err)
	}
	*m = Memory(v)
	return nil
}

// DiskDef supports shorthand "20G" and full form.
type DiskDef struct {
	Size         string `yaml:"size"`
	Bus          string `yaml:"bus"`
	Cache        string `yaml:"cache"`
	Storage      string `yaml:"storage"`       // references volumes section
	ClusterSize  string `yaml:"cluster_size"`  // qcow2 cluster size (e.g. "64K", "2M")
	RefcountBits int    `yaml:"refcount_bits"` // qcow2 refcount width (1–64, default 16)
	// Overwrite lets a root disk from an image on an iscsi pool write the image
	// over a LUN that is not blank (docs/storage.md).
	Overwrite bool `yaml:"overwrite"`

	// Discard passes the guest's TRIM down to the storage: unmap (or on) frees
	// the space on thin storage, ignore (or off) drops it. Unset: a new VM gets
	// the storage type's default (docs/storage.md), an existing one keeps what
	// it has.
	Discard string `yaml:"discard,omitempty"`
	// DetectZeroes turns a guest write of zeroes into a discard (unmap, which
	// needs discard unmap), or only skips the zero blocks (on); off disables it.
	DetectZeroes string `yaml:"detect_zeroes,omitempty"`
	// IOTune throttles this disk's I/O (libvirt <iotune>). Changeable on a
	// running VM; an empty `iotune: {}` clears every limit.
	IOTune *IOTuneDef `yaml:"iotune,omitempty"`
}

func (d *DiskDef) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try shorthand string "20G"
	var s string
	if err := unmarshal(&s); err == nil {
		d.Size = s
		return nil
	}
	// Full form
	type diskDefAlias DiskDef
	return unmarshal((*diskDefAlias)(d))
}

// NetworkAttachment is a VM's connection to a network.
type NetworkAttachment struct {
	Name    string `yaml:"name"`
	Model   string `yaml:"model"`
	IP      string `yaml:"ip"`
	Gateway string `yaml:"gateway"`
	MAC     string `yaml:"mac"`
	Trunk   []int  `yaml:"trunk"`

	// Rate caps this NIC's bandwidth in MB/s in both directions (Proxmox rate=,
	// fractions allowed). 0/unset = unlimited. Changeable on a running VM.
	Rate float64 `yaml:"rate,omitempty"`

	// IPv6 / IPv6Gateway are the v6 counterparts. Empty = use SLAAC
	// (router advertisement) or DHCPv6 if the network is configured
	// for it. Networks themselves carry both an IPv4 subnet and an
	// optional IPv6 subnet — these per-NIC fields override defaults.
	IPv6        string `yaml:"ipv6,omitempty"`
	IPv6Gateway string `yaml:"ipv6-gateway,omitempty"`

	// SecurityGroups are names that resolve to top-level
	// security-groups: definitions. Empty = inherit cluster + host
	// rules only (no per-NIC SG layer).
	SecurityGroups []string `yaml:"security-groups,omitempty"`

	// Queues is the virtio-net multiqueue count (<driver
	// queues='N'/>): 1 to 64, or "auto" for one per vCPU up to 8. Unset or 1
	// is a single queue. Virtio model only; applies on the next define.
	Queues NICQueues `yaml:"queues,omitempty"`

	// MTU is the guest NIC's MTU (<mtu size='N'/>): 576 to 65520, which must
	// equal the bridge's MTU on the defining host, or "bridge" for the bridge's
	// own MTU. Unset or 0 renders none. Virtio model only; applies on the next
	// define.
	MTU NICMTU `yaml:"mtu,omitempty"`

	// NIC guard (anti-spoofing; docs/firewall.md "NIC guards"). SpoofGuard is
	// "" (on, the default for a new NIC), "on" or "off". AllowedAddresses are
	// extra source addresses or prefixes the guest may use beyond the ones
	// litevirt assigns. Anything but the default needs cluster-root network
	// authority at deploy.
	SpoofGuard               string   `yaml:"spoof-guard,omitempty"`
	AllowedAddresses         []string `yaml:"allowed-addresses,omitempty"`
	AllowDHCPServer          bool     `yaml:"allow-dhcp-server,omitempty"`
	AllowRouterAdvertisement bool     `yaml:"allow-router-advertisement,omitempty"`
	AllowVLANTags            bool     `yaml:"allow-vlan-tags,omitempty"`
}

// CloudInitDef holds cloud-init configuration.
type CloudInitDef struct {
	UserData      string            `yaml:"userdata"`
	NetworkConfig string            `yaml:"networkconfig"`
	MetaData      map[string]string `yaml:"metadata"`
}

// GraphicsDef controls which console graphics devices are attached to the
// VM. `vnc` defaults to true (most VMs need a display); `spice` opt-in.
type GraphicsDef struct {
	VNC   *bool `yaml:"vnc"`   // pointer so "vnc: false" disables; nil = default true
	SPICE bool  `yaml:"spice"` // explicit opt-in
}

// PlacementDef controls VM scheduling.
type PlacementDef struct {
	Host         string            `yaml:"host"`
	AntiAffinity []string          `yaml:"anti-affinity"`
	Affinity     []string          `yaml:"affinity"`
	Require      map[string]string `yaml:"require"`
	Prefer       map[string]string `yaml:"prefer"`
	Spread       bool              `yaml:"spread"`       // legacy; use Policy=spread-strict
	MaxPerNode   int               `yaml:"max-per-node"` // 0 = unlimited

	// Policy: balance | bin-pack | spread-strict | cost-aware. Empty defaults
	// to balance. See docs/placement.md and
	Policy string `yaml:"policy"`

	// Mode is a named-bundle alias (`performance`, `savings`, `ha-critical`,
	// `spot-cheap`). Expanded at parse time into Policy + Rebalance fields.
	// If both Mode and explicit Policy/Rebalance are set, explicit wins.
	Mode string `yaml:"mode"`

	// Rebalance: day-2 reconciliation behavior for this VM. nil = inherit
	// from cluster default.
	Rebalance *RebalanceDef `yaml:"rebalance"`

	// NoMigrate: this VM opts out of all live migration (rebalancer ignores
	// it; storage motion not allowed). Set automatically by admission for
	// VMs with non-migratable PCI passthrough.
	NoMigrate bool `yaml:"no-migrate"`

	// Failback: after a host drain moves this VM away, live-migrate it back
	// once that host is undrained (docs/migration-failover.md#failback). It
	// moves back only a VM the drain moved and nothing has moved since.
	Failback bool `yaml:"failback"`
}

// RebalanceDef controls per-VM (or per-stack / per-cluster) rebalancer
// behavior. See for the mode matrix.
type RebalanceDef struct {
	Mode      string           `yaml:"mode"`      // off | dry-run | auto (on-demand: an alias of dry-run)
	Threshold int              `yaml:"threshold"` // min imbalance % (default 15)
	Cooldown  string           `yaml:"cooldown"`  // "5m" — min interval per VM
	Budget    *RebalanceBudget `yaml:"budget"`
}

// RebalanceBudget caps how aggressive the rebalancer may be.
type RebalanceBudget struct {
	MaxConcurrent int    `yaml:"max-concurrent"` // simultaneous live migrations cluster-wide
	MaxPerHour    int    `yaml:"max-per-hour"`
	Window        string `yaml:"window"` // named cluster time window (e.g. "off-hours")
}

// RestartDef controls auto-restart behaviour for stopped/crashed VMs.
type RestartDef struct {
	Condition   string `yaml:"condition"`    // "none" | "on-failure" | "always"
	Delay       string `yaml:"delay"`        // "5s", "1m"
	MaxAttempts int    `yaml:"max-attempts"` // 0 = unlimited
	Window      string `yaml:"window"`       // "1h" — reset attempt counter after this duration
}

// MigrateDef controls migration behaviour.
type MigrateDef struct {
	Strategy      string `yaml:"strategy"` // live | cold | none
	MaxDowntime   string `yaml:"max-downtime"`
	AutoConverge  bool   `yaml:"auto-converge"`
	WithStorage   bool   `yaml:"with-storage"`
	OnHostFailure string `yaml:"on-host-failure"` // restart-any | restart-same | none
	Priority      int    `yaml:"priority"`
	FenceStrategy string `yaml:"fence-strategy"` // best-effort | ipmi | manual | watchdog
	BandwidthMiB  int    `yaml:"bandwidth-mib-sec"`
	TimeoutSec    int    `yaml:"timeout-sec"`
}

// UpdateDef controls rolling update behaviour.
type UpdateDef struct {
	Strategy          string `yaml:"strategy"` // in-place | recreate | snapshot-and-replace | rolling | all-at-once | blue-green
	MaxUnavailable    int    `yaml:"max-unavailable"`
	MaxSurge          int    `yaml:"max-surge"`
	Order             string `yaml:"order"` // start-first | stop-first
	HealthWait        string `yaml:"health-wait"`
	RollbackOnFailure bool   `yaml:"rollback-on-failure"`
	PauseBetween      string `yaml:"pause-between"`
}

// LBDef defines load balancer configuration.
type LBDef struct {
	Enabled   bool      `yaml:"enabled"`
	VIP       string    `yaml:"vip"`
	Ports     []LBPort  `yaml:"ports"`
	Algorithm string    `yaml:"algorithm"` // roundrobin | leastconn | source
	Health    *LBHealth `yaml:"health"`
	Hosts     []string  `yaml:"hosts"`
	Sticky    bool      `yaml:"sticky-sessions"`
	SNAT      bool      `yaml:"snat"` // SNAT outbound VM traffic to VIP
}

// LBPort defines a single LB listener.
type LBPort struct {
	Listen        int       `yaml:"listen"`
	Target        int       `yaml:"target"`
	Protocol      string    `yaml:"protocol"` // tcp | http
	RedirectHTTPS bool      `yaml:"redirect-https"`
	TLS           *LBTLSDef `yaml:"tls"`
}

// LBTLSDef holds TLS termination config.
type LBTLSDef struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// LBHealth defines LB backend health checking.
type LBHealth struct {
	UseVMHealthcheck bool   `yaml:"use-vm-healthcheck"`
	Type             string `yaml:"type"`
	Path             string `yaml:"path"`
	IntervalMS       int    `yaml:"interval-ms"`
}

// HealthCheckDef defines VM-level health checking.
type HealthCheckDef struct {
	// Type is tcp | http | https | ping | exec. When omitted, the parser
	// infers it from a target that settles it (see inferHealthType).
	Type string `yaml:"type"`
	// Target is resolved relative to the VM, because the probe runs on the
	// VM's owning host: a bare port, an empty host, localhost or any loopback
	// address means the VM's own address; another host is probed as given.
	// tcp: "22" or host:port. http/https: a URL, "8080", ":8080/path" or
	// "/path". ping: empty (the VM) or a host. exec: a command run in the
	// guest by its agent. See ParseHealthTarget.
	Target   string `yaml:"target"`
	Interval string `yaml:"interval"`
	Timeout  string `yaml:"timeout"`
	Retries  int    `yaml:"retries"`
	Action   string `yaml:"action"` // restart | migrate | alert

	typeInferred bool // Type was inferred from Target, not written
}

// HooksDef contains lifecycle hook scripts.
type HooksDef struct {
	PreStart    string `yaml:"pre-start"`
	PostStart   string `yaml:"post-start"`
	PreStop     string `yaml:"pre-stop"`
	PostStop    string `yaml:"post-stop"`
	PreMigrate  string `yaml:"pre-migrate"`
	PostMigrate string `yaml:"post-migrate"`
}

// DeviceDef describes a PCI device passthrough request.
type DeviceDef struct {
	Type    string `yaml:"type"`    // gpu | network | nvme | infiniband | pci
	Vendor  string `yaml:"vendor"`  // PCI vendor ID e.g. "10de"
	Model   string `yaml:"model"`   // optional model string match
	Count   int    `yaml:"count"`   // number of devices (default 1)
	Address string `yaml:"address"` // exact PCI address e.g. "0000:41:00.0"
	SRIOV   bool   `yaml:"sriov"`   // request an SR-IOV VF
	Parent  string `yaml:"parent"`  // SR-IOV: allocate from this PF
	Mapping string `yaml:"mapping"` // cluster-wide resource-mapping name (#14)
}

// ResourcesDef holds advanced resource tuning.
type ResourcesDef struct {
	HugePages    bool   `yaml:"hugepages"`
	CPUPinning   []int  `yaml:"cpu-pinning"`
	NUMATopology string `yaml:"numa-topology"`
	IOThreads    int    `yaml:"io-threads"`
}

// DependsOn maps dependency VM names to their conditions.
// Supports both list form (all vm_started) and map form (per-dependency condition).
type DependsOn map[string]DependencyDef

// DependencyDef specifies the condition for a dependency.
type DependencyDef struct {
	Condition string `yaml:"condition"` // "vm_started" | "vm_healthy"
}

// UnmarshalYAML allows DependsOn to accept both list and map forms:
//
//	depends-on: [db, redis]                        → all vm_started
//	depends-on:
//	  db: { condition: vm_healthy }
//	  redis: { condition: vm_started }
func (d *DependsOn) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try list form first.
	var list []string
	if err := unmarshal(&list); err == nil {
		*d = make(DependsOn, len(list))
		for _, name := range list {
			(*d)[name] = DependencyDef{Condition: "vm_started"}
		}
		return nil
	}
	// Map form.
	type alias DependsOn
	var m alias
	if err := unmarshal(&m); err != nil {
		return err
	}
	// Default condition to vm_started.
	for k, v := range m {
		if v.Condition == "" {
			v.Condition = "vm_started"
			m[k] = v
		}
	}
	*d = DependsOn(m)
	return nil
}

// DNSDef holds cluster DNS configuration.
type DNSDef struct {
	Domain string `yaml:"domain"`
}

// NotificationsDef holds webhook configuration.
type NotificationsDef struct {
	Webhook string `yaml:"webhook"`
}

// ScopedNetworkName returns the stack-scoped name for a network.
// Stack-owned networks are stored as "{stack}_{name}" to prevent
// cross-stack collisions. Standalone networks (empty stack) keep their
// raw name.
func ScopedNetworkName(stackName, netName string) string {
	if stackName == "" {
		return netName
	}
	return stackName + "_" + netName
}

// DefaultNetworkInterfaces gives every network f declares (and does not mark
// external) with no interface a device: kept[name] when the caller keeps one
// (the device a deployed network is recorded on, so a default never moves it,
// or a host bridge the network is named after). Otherwise a bridge network
// (no type, or "bridge") gets its stack-scoped flat bridge name,
// FlatBridgeName(ScopedNetworkName(f.Name, name)), and any other type its own
// name as written in the file (for "direct" that is the host NIC macvtap
// attaches to). A deploy calls it once, before anything provisions or
// persists a network, so the entry node, every peer and the network row name
// the same device, and two stacks that each declare a bridge network of the
// same name are never on one bridge by default.
func (f *File) DefaultNetworkInterfaces(kept map[string]string) {
	for name, nd := range f.Networks {
		if nd.External || nd.Interface != "" {
			continue
		}
		switch {
		case kept[name] != "":
			nd.Interface = kept[name]
		case nd.Type == "" || nd.Type == "bridge":
			nd.Interface = FlatBridgeName(ScopedNetworkName(f.Name, name))
		default:
			nd.Interface = name
		}
		f.Networks[name] = nd
	}
}

// ResolveNetworkName returns the cluster network record a workload NIC
// naming raw refers to. A network this file declares (and does not mark
// external) belongs to the stack and is stored as "<stack>_<raw>". Any other
// name — declared `external: true`, or not declared at all — is a cluster
// network made outside the stack (`lv network create`), stored under its own
// name. Every site that turns a NIC's network into a record name must use
// this, so the VM, the container and the planner agree.
func (f *File) ResolveNetworkName(raw string) string {
	if nd, ok := f.Networks[raw]; ok && !nd.External {
		return ScopedNetworkName(f.Name, raw)
	}
	return raw
}
