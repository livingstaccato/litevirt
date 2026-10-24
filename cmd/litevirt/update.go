package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

func newUpdateCmd() *cobra.Command {
	var (
		cpu        int32
		memory     int32
		cpuMode    string
		cpuModel   string
		disableVNC bool
		// live metadata (applied while running, no restart)
		restart      string
		restartMax   int32
		restartDelay string
		restartWin   string
		onboot       bool
		startupOrder int32
		startDelay   int32
		stopDelay    int32
		// redefine-class (require the VM stopped)
		machine         string
		firmware        string
		guestAgent      bool
		minMem          int32
		maxMem          int32
		maxCPU          int32
		secureBoot      bool
		tpm             bool
		force           bool
		restartIfNeeded bool
		allowOvercommit bool
		memHotplugMax   int32
		clearUSB        bool
		usb             usbFlags
		// noisy-neighbour limits (applied live, no restart)
		cpuLimit  float64
		cpuShares int32
		nicRates  []string
		// per-NIC MTU (a redefine)
		nicMTUs []string
	)
	cmd := &cobra.Command{
		Use:   "update <vm>",
		Short: "Reconfigure a VM (restart policy, autostart, resources, ...)",
		Long: `Reconfigure an existing VM.

Restart policy, autostart (onboot), startup ordering and the noisy-neighbour
limits (--cpu-limit, --cpu-shares, --nic-rate) apply LIVE — the VM does
not need to be stopped. CPU, memory, CPU mode, VNC, machine type, firmware,
guest-agent, the balloon min/max bounds and --nic-mtu change the domain
definition, so the VM must be stopped for those.

With live_resize enabled cluster-wide, --cpu GROWS a running VM's vCPUs LIVE up to
its --max-cpu hotplug ceiling (a CPU shrink or exceeding the ceiling still needs a
stop), and 'lv set-memory' balloons memory live within the min/max bounds.

A VM with memory hot-add (--memory-hotplug-max) takes --memory LIVE: memory above
its boot size is a virtio-mem region, plugged or unplugged in the running guest.

--usb, --usb-port and --usb-mapping REPLACE the VM's USB passthrough list
(--clear-usb empties it). Like the other definition changes, they need the VM
stopped or --restart-if-needed; USB devices are not hot-plugged.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			any := false
			for _, n := range []string{"cpu", "memory", "cpu-mode", "cpu-model", "disable-vnc",
				"restart", "restart-max-attempts", "restart-delay", "restart-window",
				"onboot", "startup-order", "start-delay", "stop-delay",
				"machine", "firmware", "guest-agent", "min-mem", "max-mem", "max-cpu",
				"secure-boot", "tpm", "memory-hotplug-max", "clear-usb", "usb", "usb-port", "usb-mapping",
				"cpu-limit", "cpu-shares", "nic-rate", "nic-mtu"} {
				if f.Changed(n) {
					any = true
					break
				}
			}
			if !any {
				return fmt.Errorf("specify at least one field to change (see --help)")
			}

			req := &pb.UpdateVMRequest{Name: args[0]}
			// Redefine-class: 0/"" already means "unchanged" server-side.
			if f.Changed("cpu") {
				req.Cpu = cpu
			}
			if f.Changed("memory") {
				req.MemoryMib = memory
			}
			if f.Changed("cpu-mode") {
				req.CpuMode = cpuMode
			}
			if f.Changed("cpu-model") {
				req.CpuModel = cpuModel
			}
			req.DisableVnc = disableVNC
			if f.Changed("machine") {
				req.Machine = machine
			}
			if f.Changed("firmware") {
				req.Firmware = firmware
			}
			if f.Changed("guest-agent") {
				req.GuestAgent = &guestAgent
			}
			if f.Changed("min-mem") {
				req.MinMemoryMib = &minMem
			}
			if f.Changed("max-mem") {
				req.MaxMemoryMib = &maxMem
			}
			if f.Changed("max-cpu") {
				req.MaxCpu = &maxCPU
			}
			if f.Changed("restart-if-needed") {
				req.AllowRestart = &restartIfNeeded
				req.AllowOvercommit = allowOvercommit
			}
			if f.Changed("secure-boot") {
				req.SecureBoot = &secureBoot
			}
			if f.Changed("tpm") {
				req.Tpm = &tpm
			}
			if f.Changed("memory-hotplug-max") {
				req.MemoryHotplugMaxMib = &memHotplugMax
			}
			if usb.changed(cmd) || clearUSB {
				if clearUSB && usb.changed(cmd) {
					return fmt.Errorf("--clear-usb and --usb/--usb-port/--usb-mapping are exclusive: the USB flags already replace the whole list")
				}
				devs, err := usb.devices()
				if err != nil {
					return err
				}
				req.SetUsbDevices, req.UsbDevices = true, devs
			}
			req.Force = force
			// Noisy-neighbour limits: presence-detected, so 0 can clear one.
			if f.Changed("cpu-limit") {
				req.CpuLimit = &cpuLimit
			}
			if f.Changed("cpu-shares") {
				req.CpuShares = &cpuShares
			}
			for _, spec := range nicRates {
				nr, err := parseNICRate(spec)
				if err != nil {
					return err
				}
				req.NicRate = append(req.NicRate, nr)
			}
			for _, spec := range nicMTUs {
				nm, err := parseNICMTU(spec)
				if err != nil {
					return err
				}
				req.NicMtu = append(req.NicMtu, nm)
			}
			// The NIC numbers are positions in the VM's NIC list, as lv
			// inspect shows them, not spec entries.
			req.NicByListPosition = len(req.NicRate) > 0 || len(req.NicMtu) > 0
			// Live metadata: only send what changed (presence-detected).
			if f.Changed("restart") || f.Changed("restart-max-attempts") ||
				f.Changed("restart-delay") || f.Changed("restart-window") {
				// condition "none"/"" clears the policy server-side.
				req.Restart = &pb.RestartPolicy{
					Condition:   restart,
					MaxAttempts: restartMax,
					Delay:       restartDelay,
					Window:      restartWin,
				}
			}
			if f.Changed("onboot") {
				req.Onboot = &onboot
			}
			if f.Changed("startup-order") {
				req.StartupOrder = &startupOrder
			}
			if f.Changed("start-delay") {
				req.StartDelaySec = &startDelay
			}
			if f.Changed("stop-delay") {
				req.StopDelaySec = &stopDelay
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if err := nicNumbersForNode(ctx, c, req); err != nil {
					return err
				}
				vm, err := c.UpdateVM(ctx, req)
				if err != nil {
					return fmt.Errorf("update VM: %w", err)
				}
				fmt.Printf("VM %s updated (cpu: %d, memory: %d MiB, state: %s)\n",
					vm.Name, vm.CpuActual, vm.MemActualMib, vm.State)
				return nil
			})
		},
	}
	cmd.Flags().Float64Var(&cpuLimit, "cpu-limit", 0, "Cap the VM's total CPU at this many host cores, fractions allowed, at most --cpu (live; 0 removes the cap)")
	cmd.Flags().Int32Var(&cpuShares, "cpu-shares", 0, "CPU weight under contention, 1-10000: the cgroup v2 weight, Proxmox cpuunits, default 100 (live; 0 restores the default)")
	cmd.Flags().StringArrayVar(&nicRates, "nic-rate", nil, "Cap one NIC's bandwidth, <nic>=<MB/s>, the NIC numbered from 0 in the order lv inspect lists them under spec.network, e.g. 0=12.5 (live; 0=0 removes it; repeatable). A node on an older build is refused")
	cmd.Flags().StringArrayVar(&nicMTUs, "nic-mtu", nil, "Set one NIC's MTU, <nic>=<MTU|bridge>, the NIC numbered from 0 in the order lv inspect lists them under spec.network, e.g. 0=9000; it must equal the bridge's MTU (VM must be stopped; 0=0 removes it; repeatable). A node on an older build is refused")
	cmd.Flags().Int32Var(&cpu, "cpu", 0, "Number of vCPUs (VM must be stopped)")
	cmd.Flags().Int32Var(&memory, "memory", 0, "Memory in MiB (VM must be stopped)")
	cmd.Flags().StringVar(&cpuMode, "cpu-mode", "", "CPU mode: host-passthrough|host-model|custom (VM must be stopped)")
	cmd.Flags().StringVar(&cpuModel, "cpu-model", "", "CPU model for --cpu-mode custom, e.g. x86-64-v3 (VM must be stopped)")
	cmd.Flags().BoolVar(&disableVNC, "disable-vnc", false, "Disable VNC access (VM must be stopped)")
	cmd.Flags().StringVar(&restart, "restart", "", "Auto-restart policy: none|on-failure|always (live; none clears it)")
	cmd.Flags().Int32Var(&restartMax, "restart-max-attempts", 0, "Max restart attempts within the window (0 = unlimited)")
	cmd.Flags().StringVar(&restartDelay, "restart-delay", "", "Delay between restart attempts (e.g. 5s)")
	cmd.Flags().StringVar(&restartWin, "restart-window", "", "Attempt-count window (e.g. 1h)")
	cmd.Flags().BoolVar(&onboot, "onboot", false, "Start this VM automatically when its host boots (live)")
	cmd.Flags().Int32Var(&startupOrder, "startup-order", 0, "Autostart order, lower starts first (live)")
	cmd.Flags().Int32Var(&startDelay, "start-delay", 0, "Seconds to wait after starting before the next VM (live)")
	cmd.Flags().Int32Var(&stopDelay, "stop-delay", 0, "Seconds to wait after stopping during ordered shutdown (live)")
	cmd.Flags().StringVar(&machine, "machine", "", "Machine type, e.g. q35 (VM must be stopped)")
	cmd.Flags().StringVar(&firmware, "firmware", "", "Firmware: uefi|bios (VM must be stopped)")
	cmd.Flags().BoolVar(&guestAgent, "guest-agent", false, "Enable the QEMU guest agent (VM must be stopped)")
	cmd.Flags().Int32Var(&minMem, "min-mem", 0, "Minimum balloon memory in MiB (VM must be stopped)")
	cmd.Flags().Int32Var(&maxMem, "max-mem", 0, "Maximum balloon memory in MiB (VM must be stopped)")
	cmd.Flags().Int32Var(&maxCPU, "max-cpu", 0, "vCPU hotplug ceiling for live CPU hot-add (requires live_resize; set once stopped, then --cpu grows live up to it)")
	cmd.Flags().BoolVar(&secureBoot, "secure-boot", false, "Enable/disable UEFI Secure Boot (VM must be stopped; --force if firmware state exists)")
	cmd.Flags().BoolVar(&tpm, "tpm", false, "Enable/disable the emulated TPM 2.0 (VM must be stopped; --force if TPM state exists)")
	cmd.Flags().BoolVar(&force, "force", false, "Allow toggling secure-boot/tpm even when firmware state exists")
	cmd.Flags().BoolVar(&restartIfNeeded, "restart-if-needed", false, "Permit a stop→redefine→start for a change that can't apply live (cpu shrink, machine/firmware, beyond the vCPU ceiling)")
	cmd.Flags().BoolVar(&allowOvercommit, "allow-overcommit", false,
		"Skip the host capacity check when --restart-if-needed grows the VM (project quota still applies). The bypass is audited.")
	cmd.Flags().Int32Var(&memHotplugMax, "memory-hotplug-max", 0,
		"Memory hot-add ceiling in MiB (virtio-mem; 0 turns it off). Set while stopped; then --memory or lv set-memory changes memory live up to it")
	cmd.Flags().BoolVar(&clearUSB, "clear-usb", false, "Remove every USB passthrough device (VM must be stopped)")
	usb.register(cmd)
	return cmd
}

// nicNumbersForNode makes sure the node lv update talks to reads the NIC
// numbers as list positions. A node whose Ping lacks nic_list_position reads
// each number as a spec index, which can name another NIC: refused.
func nicNumbersForNode(ctx context.Context, c pb.LiteVirtClient, req *pb.UpdateVMRequest) error {
	if !req.GetNicByListPosition() {
		return nil
	}
	p, err := c.Ping(ctx, &pb.PingRequest{})
	if err == nil && p.GetNicListPosition() {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ask the node whether it reads --nic-mtu and --nic-rate numbers as NIC positions: %w", err)
	}
	return fmt.Errorf("the node this command talks to runs an older build, which reads --nic-mtu and --nic-rate " +
		"numbers as spec entries; run lv update against an upgraded node, or upgrade this one first")
}

// parseNICRate parses one --nic-rate value, "<nic>=<MB/s>".
func parseNICRate(v string) (*pb.NICRateUpdate, error) {
	n, rate, ok := strings.Cut(v, "=")
	if !ok {
		return nil, fmt.Errorf("--nic-rate %q: want <nic>=<MB/s>, e.g. 0=12.5", v)
	}
	ord, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil || ord < 0 {
		return nil, fmt.Errorf("--nic-rate %q: the NIC must be a 0-based number", v)
	}
	r, err := strconv.ParseFloat(strings.TrimSpace(rate), 64)
	if err != nil || r < 0 {
		return nil, fmt.Errorf("--nic-rate %q: the rate must be a number of MB/s, 0 or more", v)
	}
	return &pb.NICRateUpdate{Ordinal: int32(ord), RateMbSec: r}, nil
}

// parseNICMTU parses one --nic-mtu value, "<nic>=<MTU|bridge>".
func parseNICMTU(v string) (*pb.NICMTUUpdate, error) {
	n, m, ok := strings.Cut(v, "=")
	if !ok {
		return nil, fmt.Errorf("--nic-mtu %q: want <nic>=<MTU|bridge>, e.g. 0=9000", v)
	}
	ord, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil || ord < 0 {
		return nil, fmt.Errorf("--nic-mtu %q: the NIC must be a 0-based number", v)
	}
	m = strings.TrimSpace(m)
	if strings.EqualFold(m, "bridge") {
		return &pb.NICMTUUpdate{Ordinal: int32(ord), Mtu: compose.NICMTUBridge}, nil
	}
	mtu, err := strconv.Atoi(m)
	if err != nil || (mtu != 0 && (mtu < int(compose.MinNICMTU) || mtu > int(compose.MaxNICMTU))) {
		return nil, fmt.Errorf("--nic-mtu %q: the MTU must be %d to %d, bridge, or 0 to remove it", v, compose.MinNICMTU, compose.MaxNICMTU)
	}
	return &pb.NICMTUUpdate{Ordinal: int32(ord), Mtu: int32(mtu)}, nil
}
