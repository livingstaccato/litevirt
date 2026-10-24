package pci

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// nvidiaSMI is the nvidia-smi binary the MIG functions run. Tests point it at
// a fake script; there is no NVIDIA GPU to run the real one against.
var nvidiaSMI = "nvidia-smi"

// MIGGPU is one GPU as nvidia-smi reports it, with its MIG mode. A GPU that
// cannot do MIG reports its modes as "[N/A]".
type MIGGPU struct {
	Index   int
	BusID   string // "00000000:36:00.0", as nvidia-smi prints it
	Name    string
	Current string // mig.mode.current: "Enabled" | "Disabled" | "[N/A]"
	Pending string // mig.mode.pending: differs from Current until a GPU reset
}

// MIGCapable reports whether the GPU supports MIG at all.
func (g MIGGPU) MIGCapable() bool {
	return g.Current == "Enabled" || g.Current == "Disabled"
}

// MIGInstance is one MIG GPU instance (GI).
type MIGInstance struct {
	GPUIndex   int
	InstanceID int    // the GI ID, which -dgi -gi takes
	Profile    string // e.g. "1g.5gb", "3g.20gb" (without the "MIG " prefix)
	ProfileID  int
	Placement  string // "start:size"
}

func runNvidiaSMI(args ...string) (string, error) {
	out, err := exec.Command(nvidiaSMI, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("nvidia-smi %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// validGPU accepts what nvidia-smi -i takes (an index, a PCI bus ID or a
// GPU UUID) and refuses anything nvidia-smi could read as a flag.
var validGPU = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z:.\-]*$`)

func checkGPU(gpu string) error {
	if !validGPU.MatchString(gpu) {
		return fmt.Errorf("invalid GPU %q: give its nvidia-smi index, PCI bus ID or UUID", gpu)
	}
	return nil
}

// validProfile accepts a MIG profile name ("3g.20gb", "1g.10gb+me") or ID ("9").
var validProfile = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+]*$`)

// ListMIGGPUs lists every GPU nvidia-smi sees and its MIG mode. A GPU bound to
// vfio-pci (passed through to a VM) is not visible to nvidia-smi and is not
// listed.
func ListMIGGPUs() ([]MIGGPU, error) {
	out, err := runNvidiaSMI("--query-gpu=index,pci.bus_id,mig.mode.current,mig.mode.pending,name",
		"--format=csv,noheader")
	if err != nil {
		return nil, err
	}
	var gpus []MIGGPU
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.SplitN(line, ",", 5)
		if len(f) != 5 {
			return nil, fmt.Errorf("parse nvidia-smi --query-gpu line %q", line)
		}
		idx, err := strconv.Atoi(strings.TrimSpace(f[0]))
		if err != nil {
			return nil, fmt.Errorf("parse nvidia-smi --query-gpu line %q: %w", line, err)
		}
		gpus = append(gpus, MIGGPU{
			Index:   idx,
			BusID:   strings.TrimSpace(f[1]),
			Current: strings.TrimSpace(f[2]),
			Pending: strings.TrimSpace(f[3]),
			Name:    strings.TrimSpace(f[4]),
		})
	}
	return gpus, nil
}

// lgiRow matches one GPU-instance row of `nvidia-smi mig -lgi`:
//
//	|   0  MIG 3g.20gb       9        1          4:4     |
var lgiRow = regexp.MustCompile(`^\|\s*(\d+)\s+MIG\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+:\d+)\s*\|$`)

// ListMIGInstances lists the MIG GPU instances on every GPU. `nvidia-smi mig`
// has no CSV output, so this parses the table -lgi prints.
func ListMIGInstances() ([]MIGInstance, error) {
	out, err := runNvidiaSMI("mig", "-lgi")
	if err != nil {
		// No instance anywhere is an answer, not a failure: nvidia-smi
		// prints "No GPU instances found" and exits non-zero.
		if strings.Contains(out, "No GPU instances found") {
			return nil, nil
		}
		return nil, err
	}
	return parseLGI(out), nil
}

func parseLGI(out string) []MIGInstance {
	var instances []MIGInstance
	for _, line := range strings.Split(out, "\n") {
		m := lgiRow.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		gpu, _ := strconv.Atoi(m[1])
		pid, _ := strconv.Atoi(m[3])
		gi, _ := strconv.Atoi(m[4])
		instances = append(instances, MIGInstance{
			GPUIndex: gpu, Profile: m[2], ProfileID: pid, InstanceID: gi, Placement: m[5],
		})
	}
	return instances
}

// createdGI matches the line -cgi prints for the GPU instance it made:
//
//	Successfully created GPU instance ID  2 on GPU  0 using profile MIG 3g.20gb (ID  9)
var createdGI = regexp.MustCompile(`Successfully created GPU instance ID\s+(\d+) on GPU\s+(\d+) using profile MIG (\S+) \(ID\s+(\d+)\)`)

// CreateMIGInstance creates one GPU instance of profile on gpu, with its
// default compute instance in the same call (-C), so a failure cannot leave a
// GI without a CI behind.
func CreateMIGInstance(gpu, profile string) (*MIGInstance, error) {
	if err := checkGPU(gpu); err != nil {
		return nil, err
	}
	if !validProfile.MatchString(profile) {
		return nil, fmt.Errorf("invalid MIG profile %q", profile)
	}
	out, err := runNvidiaSMI("mig", "-i", gpu, "-cgi", profile, "-C")
	if err != nil {
		return nil, err
	}
	m := createdGI.FindStringSubmatch(out)
	if m == nil {
		return nil, fmt.Errorf("nvidia-smi created no GPU instance it reported: %s", strings.TrimSpace(out))
	}
	gi, _ := strconv.Atoi(m[1])
	idx, _ := strconv.Atoi(m[2])
	pid, _ := strconv.Atoi(m[4])
	return &MIGInstance{GPUIndex: idx, InstanceID: gi, Profile: m[3], ProfileID: pid}, nil
}

// DestroyMIGInstance destroys GPU instance instanceID on gpu, its compute
// instances first: -dgi refuses a GI that still has one.
func DestroyMIGInstance(gpu string, instanceID int) error {
	if err := checkGPU(gpu); err != nil {
		return err
	}
	if instanceID < 0 {
		return fmt.Errorf("invalid GPU instance ID %d", instanceID)
	}
	gi := strconv.Itoa(instanceID)
	ciOut, ciErr := runNvidiaSMI("mig", "-i", gpu, "-gi", gi, "-dci")
	if _, err := runNvidiaSMI("mig", "-i", gpu, "-gi", gi, "-dgi"); err != nil {
		// A GI with no compute instance makes -dci fail harmlessly, so its
		// error only matters when -dgi fails too; then it is the likely cause.
		if ciErr != nil {
			return fmt.Errorf("%w (destroying its compute instances first: %s)", err, strings.TrimSpace(ciOut))
		}
		return err
	}
	return nil
}

// EnableMIG enables MIG mode on gpu. Requires no process on the GPU; on some
// systems the mode stays pending until a GPU reset or reboot, which the
// returned nvidia-smi output says.
func EnableMIG(gpu string) (string, error) {
	if err := checkGPU(gpu); err != nil {
		return "", err
	}
	return runNvidiaSMI("-i", gpu, "-mig", "1")
}

// DisableMIG disables MIG mode on gpu. Requires every MIG instance on it to
// be destroyed first.
func DisableMIG(gpu string) (string, error) {
	if err := checkGPU(gpu); err != nil {
		return "", err
	}
	return runNvidiaSMI("-i", gpu, "-mig", "0")
}
