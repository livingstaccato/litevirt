package compose

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Resource defaults for a CREATE whose caller left cpu/memory unset. On create,
// 0 means "use the default" — NOT "keep current", which is the separate
// resize/reconfigure semantic.
const (
	DefaultVMCPU       = 2
	DefaultVMMemoryMiB = 4096
)

// NormalizeVMSpecResources fills in the create-time cpu/memory defaults.
//
// This MUST run before anything reads spec.Cpu/spec.MemoryMib for ADMISSION —
// project quota, placement, host capacity. Every one of those checks is a no-op
// at zero (the admission helpers early-return on non-positive deltas, placement
// skips its fit filter behind `if req.CPUNeeded > 0`, and a quota check cannot be
// violated by adding 0), so defaulting afterwards admitted a free VM and then ran
// a 2 vCPU / 4096 MiB one — repeatable, bypassing both quota and host capacity.
//
// It lives here rather than in grpcapi because BOTH the CreateVM handler and the
// compose planner's placement request need it, and compose is the package they
// share. Idempotent, so calling it again on a forwarded or replanned spec is free.
//
// Deliberately narrow: it touches ONLY the two admission inputs. Other create
// defaults (machine, firmware, the server-owned UUID mint) stay with the handler
// that owns them.
func NormalizeVMSpecResources(spec *pb.VMSpec) {
	if spec == nil {
		return
	}
	if spec.Cpu == 0 {
		spec.Cpu = DefaultVMCPU
	}
	if spec.MemoryMib == 0 {
		spec.MemoryMib = DefaultVMMemoryMiB
	}
}

// BuildVMSpec converts a compose VMDef into a gRPC VMSpec.
// Used by both the CLI (lv compose up) and the server-side DeployStack handler.
func BuildVMSpec(instanceName, baseName string, vm *VMDef, f *File) (*pb.VMSpec, error) {
	spec := &pb.VMSpec{
		Name:          instanceName,
		StackName:     f.Name,
		Image:         vm.Image,
		Cpu:           int32(vm.CPU),
		MaxCpu:        int32(vm.MaxCPU),
		CpuMode:       vm.CPUMode,
		CpuModel:      vm.CPUModel,
		CpuLimit:      vm.CPULimit,
		CpuShares:     int32(vm.CPUShares),
		MemoryMib:     int32(vm.Memory),
		MinMemoryMib:  int32(vm.MinMemory),
		MaxMemoryMib:  int32(vm.MaxMemory),
		Machine:       vm.Machine,
		Firmware:      vm.Firmware,
		SecureBoot:    vm.SecureBoot,
		Tpm:           vm.TPM,
		GuestAgent:    vm.EffectiveGuestAgent(),
		Boot:          "disk",
		Labels:        vm.Labels,
		Onboot:        vm.Onboot,
		StartupOrder:  int32(vm.StartupOrder),
		StartDelaySec: int32(vm.StartDelay),
		StopDelaySec:  int32(vm.StopDelay),
	}

	// Graphics defaults: VNC on, SPICE off. Compose can opt out of VNC
	// (`graphics.vnc: false`) or opt into SPICE (`graphics.spice: true`).
	if g := vm.Graphics; g != nil {
		if g.VNC != nil && !*g.VNC {
			spec.DisableVnc = true
		}
		if g.SPICE {
			spec.EnableSpice = true
		}
	}

	// iso: names the VM's installer ISO — a library reference
	// (<pool>/<file>.iso) or a host path, both with a '/' — which is
	// VMSpec.iso: attached as a CD-ROM beside the image's root disk, and
	// confined as every create confines an ISO (the library's project rules;
	// a host path is an Admin's only). It is never an image name, which every
	// create would refuse for the '/'. A bare name keeps its earlier meaning,
	// an image-store name used as the boot image.
	if vm.ISO != "" {
		if strings.Contains(vm.ISO, "/") {
			spec.Iso = vm.ISO
		} else {
			spec.Image = vm.ISO
		}
		spec.Boot = "cdrom"
	}

	// Deterministic disk ordering: "root" first, then alphabetical.
	// The first disk becomes vda and gets boot order 1, so root must be first.
	diskNames := make([]string, 0, len(vm.Disks))
	for name := range vm.Disks {
		if name != "root" {
			diskNames = append(diskNames, name)
		}
	}
	sort.Strings(diskNames)
	if _, ok := vm.Disks["root"]; ok {
		diskNames = append([]string{"root"}, diskNames...)
	}

	for _, diskName := range diskNames {
		disk := vm.Disks[diskName]
		ds := diskTuningSpec(disk)
		ds.Name, ds.Size, ds.Bus, ds.Cache, ds.Storage, ds.Overwrite = diskName, disk.Size, disk.Bus, disk.Cache, disk.Storage, disk.Overwrite
		spec.Disks = append(spec.Disks, ds)
	}

	for _, n := range vm.Network {
		netDef := f.Networks[n.Name]
		trunk := make([]int32, len(n.Trunk))
		for i, v := range n.Trunk {
			trunk[i] = int32(v)
		}
		if netDef.VLAN > 0 && len(trunk) == 0 {
			trunk = []int32{int32(netDef.VLAN)}
		}
		// The record name, so that DB lookups in CreateVM (provisioning,
		// lookupNetworkDef) find the network: scoped for a stack-owned
		// network, raw for an external or undeclared one.
		networkName := f.ResolveNetworkName(n.Name)
		spec.Network = append(spec.Network, &pb.NetworkAttachment{
			Name:           networkName,
			Model:          n.Model,
			Ip:             n.IP,
			Gateway:        n.Gateway,
			Mac:            n.MAC,
			Trunk:          trunk,
			Ipv6:           n.IPv6,
			Ipv6Gateway:    n.IPv6Gateway,
			SecurityGroups: n.SecurityGroups,
			Queues:         nicQueues(n.Queues, vm.CPU),
			Mtu:            n.MTU.N,
			RateMbSec:      n.Rate,

			SpoofGuard:               n.SpoofGuard,
			AllowedAddresses:         n.AllowedAddresses,
			AllowDhcpServer:          n.AllowDHCPServer,
			AllowRouterAdvertisement: n.AllowRouterAdvertisement,
			AllowVlanTags:            n.AllowVLANTags,
		})
	}

	if vm.CloudInit != nil {
		spec.CloudInit = &pb.CloudInitSpec{
			Userdata:      vm.CloudInit.UserData,
			Networkconfig: vm.CloudInit.NetworkConfig,
		}
	}

	if vm.Placement != nil {
		// Expand named-mode aliases into concrete Policy + Rebalance fields
		// before the spec leaves compose. Higher scopes (project, cluster
		// default) merge later via MergePlacement.
		eff := copyPlacement(vm.Placement)
		ExpandPlacementMode(eff)

		spec.Placement = &pb.PlacementSpec{
			Host:         eff.Host,
			AntiAffinity: eff.AntiAffinity,
			Affinity:     eff.Affinity,
			Require:      eff.Require,
			Prefer:       eff.Prefer,
			Spread:       eff.Spread,
			MaxPerNode:   int32(eff.MaxPerNode),
			Policy:       eff.Policy,
			NoMigrate:    eff.NoMigrate,
			Failback:     eff.Failback,
		}
		if eff.Rebalance != nil {
			rb := &pb.RebalanceSpec{
				Mode:      eff.Rebalance.Mode,
				Threshold: int32(eff.Rebalance.Threshold),
				Cooldown:  eff.Rebalance.Cooldown,
			}
			if eff.Rebalance.Budget != nil {
				rb.Budget = &pb.RebalanceBudget{
					MaxConcurrent: int32(eff.Rebalance.Budget.MaxConcurrent),
					MaxPerHour:    int32(eff.Rebalance.Budget.MaxPerHour),
					Window:        eff.Rebalance.Budget.Window,
				}
			}
			spec.Placement.Rebalance = rb
		}
	}

	spec.Loadbalancer = BuildLBSpec(vm.LoadBalancer)

	if vm.HealthCheck != nil {
		spec.Healthcheck = &pb.HealthCheckSpec{
			Type:     vm.HealthCheck.Type,
			Target:   vm.HealthCheck.Target,
			Interval: vm.HealthCheck.Interval,
			Timeout:  vm.HealthCheck.Timeout,
			Retries:  int32(vm.HealthCheck.Retries),
			Action:   vm.HealthCheck.Action,
		}
	}

	if vm.Hooks != nil {
		spec.Hooks = &pb.HooksSpec{
			PreStart:    vm.Hooks.PreStart,
			PostStart:   vm.Hooks.PostStart,
			PreStop:     vm.Hooks.PreStop,
			PostStop:    vm.Hooks.PostStop,
			PreMigrate:  vm.Hooks.PreMigrate,
			PostMigrate: vm.Hooks.PostMigrate,
		}
	}

	if vm.Resources != nil {
		cpuPins := make([]int32, len(vm.Resources.CPUPinning))
		for i, p := range vm.Resources.CPUPinning {
			cpuPins[i] = int32(p)
		}
		spec.Resources = &pb.ResourceTuning{
			Hugepages:  vm.Resources.HugePages,
			CpuPinning: cpuPins,
			IoThreads:  int32(vm.Resources.IOThreads),
		}
	}

	for _, dev := range vm.Devices {
		count := int32(dev.Count)
		if count == 0 {
			count = 1
		}
		spec.Devices = append(spec.Devices, &pb.DeviceSpec{
			Type:    dev.Type,
			Vendor:  dev.Vendor,
			Model:   dev.Model,
			Count:   count,
			Address: dev.Address,
			Sriov:   dev.SRIOV,
			Parent:  dev.Parent,
			Mapping: dev.Mapping,
		})
	}

	// Stop grace period → stop_timeout_sec
	if vm.StopGracePeriod != "" {
		secs, err := parseDurationSeconds(vm.StopGracePeriod)
		if err != nil {
			return nil, fmt.Errorf("vm %q stop-grace-period: %w", instanceName, err)
		}
		spec.StopTimeoutSec = int32(secs)
	}

	// Placement max-per-node
	if spec.Placement != nil && vm.Placement != nil && vm.Placement.MaxPerNode > 0 {
		spec.Placement.MaxPerNode = int32(vm.Placement.MaxPerNode)
	}

	// Restart policy
	if vm.Restart != nil {
		spec.Restart = &pb.RestartPolicy{
			Condition:   vm.Restart.Condition,
			Delay:       vm.Restart.Delay,
			MaxAttempts: int32(vm.Restart.MaxAttempts),
			Window:      vm.Restart.Window,
		}
	}

	// Migration policy
	if vm.Migrate != nil {
		strategy := pb.MigrateStrategy_MIGRATE_LIVE
		switch vm.Migrate.Strategy {
		case "cold":
			strategy = pb.MigrateStrategy_MIGRATE_COLD
		case "none":
			strategy = pb.MigrateStrategy_MIGRATE_NONE
		}
		onFailure := pb.HostFailurePolicy_RESTART_ANY
		switch vm.Migrate.OnHostFailure {
		case "restart-same":
			onFailure = pb.HostFailurePolicy_RESTART_SAME
		case "none":
			onFailure = pb.HostFailurePolicy_FAILURE_NONE
		}
		// Mirror the policy into the top-level string field: the failover
		// coordinator resolves it from the persisted spec JSON, where the enum
		// is unusable (RESTART_ANY = 0 is omitempty-dropped on store).
		switch onFailure {
		case pb.HostFailurePolicy_RESTART_SAME:
			spec.OnHostFailure = "restart-same"
		case pb.HostFailurePolicy_FAILURE_NONE:
			spec.OnHostFailure = "none"
		default:
			spec.OnHostFailure = "restart-any"
		}
		spec.Migrate = &pb.MigrationPolicy{
			Strategy:        strategy,
			MaxDowntime:     vm.Migrate.MaxDowntime,
			AutoConverge:    vm.Migrate.AutoConverge,
			WithStorage:     vm.Migrate.WithStorage,
			OnHostFailure:   onFailure,
			Priority:        int32(vm.Migrate.Priority),
			FenceStrategy:   vm.Migrate.FenceStrategy,
			BandwidthMibSec: int32(vm.Migrate.BandwidthMiB),
			TimeoutSec:      int32(vm.Migrate.TimeoutSec),
		}
	}

	// Update policy
	if vm.Update != nil {
		spec.Update = &pb.UpdatePolicy{
			Strategy:          vm.Update.Strategy,
			MaxUnavailable:    int32(vm.Update.MaxUnavailable),
			MaxSurge:          int32(vm.Update.MaxSurge),
			Order:             vm.Update.Order,
			HealthWait:        vm.Update.HealthWait,
			RollbackOnFailure: vm.Update.RollbackOnFailure,
			PauseBetween:      vm.Update.PauseBetween,
		}
	}

	_ = baseName
	return spec, nil
}

// BuildLBSpec converts a compose load balancer definition into its wire form,
// or nil when the definition is absent or not enabled. It is the one
// conversion: a VM's spec and a stack deploy's LB step both take their LB
// from here, so neither applies an LB missing something the file asked for.
func BuildLBSpec(def *LBDef) *pb.LBSpec {
	if def == nil || !def.Enabled {
		return nil
	}
	lbSpec := &pb.LBSpec{
		Enabled:        true,
		Vip:            def.VIP,
		Algorithm:      def.Algorithm,
		StickySessions: def.Sticky,
		Hosts:          def.Hosts,
		Snat:           def.SNAT,
	}
	for _, p := range def.Ports {
		pbPort := &pb.LBPort{
			Listen:        int32(p.Listen),
			Target:        int32(p.Target),
			Protocol:      p.Protocol,
			RedirectHttps: p.RedirectHTTPS,
		}
		if p.TLS != nil {
			pbPort.Tls = &pb.LBTlsSpec{
				Cert: p.TLS.Cert,
				Key:  p.TLS.Key,
			}
		}
		lbSpec.Ports = append(lbSpec.Ports, pbPort)
	}
	if def.Health != nil {
		lbSpec.Health = &pb.LBHealthSpec{
			UseVmHealthcheck: def.Health.UseVMHealthcheck,
			Type:             def.Health.Type,
			Path:             def.Health.Path,
			Interval:         fmt.Sprintf("%dms", def.Health.IntervalMS),
		}
	}
	return lbSpec
}

// parseDurationSeconds converts a human-friendly duration string like "30s", "2m", "1h"
// to seconds. Returns an error for malformed values.
func parseDurationSeconds(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, nil
	}
	// Try suffixed formats
	if strings.HasSuffix(s, "s") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "s"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return n, nil
	}
	if strings.HasSuffix(s, "m") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "m"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return n * 60, nil
	}
	if strings.HasSuffix(s, "h") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "h"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return n * 3600, nil
	}
	// Bare number = seconds
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return n, nil
}

// FindVMDef locates the VMDef for an instance name (handles replica suffixes).
func FindVMDef(f *File, instanceName string) (*VMDef, string) {
	// Exact match first.
	if def, ok := f.VMs[instanceName]; ok {
		return &def, instanceName
	}
	// Strip replica suffix "-N".
	for baseName, def := range f.VMs {
		for r := 0; r < def.EffectiveReplicas(); r++ {
			if def.InstanceName(baseName, r) == instanceName {
				return &def, baseName
			}
		}
	}
	return nil, ""
}

// diskTuningSpec carries a compose disk's discard, detect_zeroes and throttle
// into a DiskSpec (the caller fills in the identity fields). An unset key stays
// unset; an `iotune: {}` becomes an empty message, which clears the limits.
func diskTuningSpec(d DiskDef) *pb.DiskSpec {
	ds := &pb.DiskSpec{
		Discard:      NormalizeDiscard(d.Discard),
		DetectZeroes: strings.ToLower(strings.TrimSpace(d.DetectZeroes)),
	}
	if t := d.IOTune; t != nil {
		ds.Io = &pb.DiskIOLimits{
			TotalBytesSec: int64(t.TotalBytesSec), ReadBytesSec: int64(t.ReadBytesSec), WriteBytesSec: int64(t.WriteBytesSec),
			TotalIopsSec: t.TotalIopsSec, ReadIopsSec: t.ReadIopsSec, WriteIopsSec: t.WriteIopsSec,
			TotalBytesSecMax: int64(t.TotalBytesSecMax), ReadBytesSecMax: int64(t.ReadBytesSecMax), WriteBytesSecMax: int64(t.WriteBytesSecMax),
			TotalIopsSecMax: t.TotalIopsSecMax, ReadIopsSecMax: t.ReadIopsSecMax, WriteIopsSecMax: t.WriteIopsSecMax,
			BurstSeconds: t.BurstSeconds,
		}
	}
	return ds
}

// nicQueues resolves a NIC's queue setting: "auto" is one per vCPU up to 8
// (the create default for cpu is the one CreateVM applies).
func nicQueues(q NICQueues, cpu int) int32 {
	if !q.Auto {
		return q.N
	}
	if cpu == 0 {
		cpu = DefaultVMCPU
	}
	return ResolveAutoQueues(cpu)
}

// SpecEntryIndexForNIC is the index of the spec entry that describes the NIC
// with this MAC and ordinal: the entry that records its MAC (case folded),
// else — only for an entry that records no MAC — the entry at its ordinal.
// -1 when none does. A NIC's ordinal is not its entry's index once a NIC was
// detached: an ordinal is never reused, so a NIC attached again takes a new
// one while its MAC's entry keeps its place.
func SpecEntryIndexForNIC(spec *pb.VMSpec, mac string, ordinal int) int {
	if mac != "" {
		for i, e := range spec.GetNetwork() {
			if e != nil && e.Mac != "" && strings.EqualFold(e.Mac, mac) {
				return i
			}
		}
	}
	if ordinal >= 0 && ordinal < len(spec.GetNetwork()) {
		if e := spec.Network[ordinal]; e != nil && e.Mac == "" {
			return ordinal
		}
	}
	return -1
}

// NICRate is the bandwidth cap (MB/s, 0 = unlimited) a VM spec declares for
// the NIC with this MAC and ordinal: its own entry's (SpecEntryIndexForNIC),
// trusted only when that entry names the same network — a hot-plugged NIC,
// or one a retarget moved, carries no cap rather than another NIC's.
func NICRate(spec *pb.VMSpec, mac string, ordinal int, network string) float64 {
	i := SpecEntryIndexForNIC(spec, mac, ordinal)
	if i < 0 {
		return 0
	}
	n := spec.Network[i]
	if network != "" && n.Name != network {
		return 0
	}
	return n.RateMbSec
}
