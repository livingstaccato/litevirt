package pci

import (
	"errors"
	"fmt"
	"io/fs"
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
		// prints "No GPU instances found" and exits non-zero, and "No
		// MIG-enabled devices found" when no GPU is in MIG mode at all.
		if strings.Contains(out, "No GPU instances found") || strings.Contains(out, "No MIG-enabled devices found") {
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

// SetNvidiaSMI points the MIG functions at another nvidia-smi binary and
// returns a restore func. Test seam: production never calls it.
func SetNvidiaSMI(path string) func() {
	old := nvidiaSMI
	nvidiaSMI = path
	return func() { nvidiaSMI = old }
}

// nvidiaVendorID is NVIDIA's PCI vendor ID, as the scan records it.
const nvidiaVendorID = "10de"

// MIGBusyError is the refusal to pass through a GPU that MIG holds: its MIG
// mode is enabled, now or pending a reset, or it has MIG GPU instances.
// Rebinding it to vfio-pci would pull it from under every MIG workload on it.
type MIGBusyError struct {
	Address   string // the GPU's PCI address
	Index     int    // its nvidia-smi index, which `lv host mig` takes
	Current   string
	Pending   string
	Instances int
}

func (e *MIGBusyError) Error() string {
	var why []string
	if e.Current == "Enabled" || e.Pending == "Enabled" {
		why = append(why, fmt.Sprintf("its MIG mode is on (current %s, pending %s)", e.Current, e.Pending))
	}
	if e.Instances > 0 {
		why = append(why, fmt.Sprintf("it holds %d MIG GPU instance(s)", e.Instances))
	}
	return fmt.Sprintf("GPU %s (nvidia-smi index %d) is not available for passthrough: %s; "+
		"binding it to vfio-pci would take it from its MIG workloads. To reclaim it, on that host "+
		"destroy each instance (`lv host mig destroy %d <instance-id>`, see `lv host mig ls`) "+
		"and then run `lv host mig disable %d`",
		e.Address, e.Index, strings.Join(why, " and "), e.Index, e.Index)
}

// MIGState is one reading of every GPU's MIG mode and MIG instances on this
// host, taken once and asked about each device a passthrough would rebind.
type MIGState struct {
	read      bool
	noDriver  bool // nvidia-smi is not installed: no GPU can be in MIG mode
	gpus      []MIGGPU
	gpuErr    error
	instances []MIGInstance
	instErr   error
}

// ReadMIGState returns a reading of this host's MIG state, taken from
// nvidia-smi the first time Hold checks an NVIDIA GPU, so a request with no
// NVIDIA GPU never runs it. A failure is kept, not returned: it only matters
// to an NVIDIA GPU, which Hold then refuses. Not safe for concurrent use.
func ReadMIGState() *MIGState { return &MIGState{} }

func (st *MIGState) load() {
	if st.read {
		return
	}
	st.read = true
	gpus, err := ListMIGGPUs()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			st.noDriver = true
			return
		}
		st.gpuErr = err
		return
	}
	st.gpus = gpus
	for _, g := range gpus {
		if g.MIGCapable() || g.Pending == "Enabled" {
			st.instances, st.instErr = ListMIGInstances()
			break
		}
	}
}

// Hold returns why the device at address (vendor as the PCI scan records
// it, driver the one it is bound to now) must not be rebound to vfio-pci for
// passthrough, or nil when it may be. Only an NVIDIA GPU on a driver other
// than vfio-pci is checked: one already on vfio-pci is not rebound, and
// nvidia-smi does not see it. A *MIGBusyError means MIG holds it; any other
// error means its MIG state could not be read, and the caller refuses too.
func (st *MIGState) Hold(address, vendor, driver string) error {
	if strings.TrimPrefix(strings.ToLower(vendor), "0x") != nvidiaVendorID || driver == "vfio-pci" {
		return nil
	}
	st.load()
	if st.noDriver {
		return nil
	}
	if st.gpuErr != nil {
		return fmt.Errorf("cannot read the MIG state of GPU %s: %w", address, st.gpuErr)
	}
	want := normalizeBusID(address)
	for _, g := range st.gpus {
		if normalizeBusID(g.BusID) != want {
			continue
		}
		busy := &MIGBusyError{Address: address, Index: g.Index, Current: g.Current, Pending: g.Pending}
		if g.MIGCapable() || g.Pending == "Enabled" {
			if st.instErr != nil {
				return fmt.Errorf("cannot list the MIG instances of GPU %s: %w", address, st.instErr)
			}
			for _, in := range st.instances {
				if in.GPUIndex == g.Index {
					busy.Instances++
				}
			}
		}
		if g.Current == "Enabled" || g.Pending == "Enabled" || busy.Instances > 0 {
			return busy
		}
		return nil
	}
	// nvidia-smi lists every GPU the NVIDIA driver holds. One it holds that
	// nvidia-smi does not list has an unknown MIG state; one on any other
	// driver (or none) cannot be in MIG mode.
	if driver == "nvidia" {
		return fmt.Errorf("cannot read the MIG state of GPU %s: it is on the nvidia driver but nvidia-smi does not list it", address)
	}
	return nil
}

// normalizeBusID maps nvidia-smi's "00000000:36:00.0" and sysfs's
// "0000:36:00.0" to one form: a four-digit domain, lower case.
func normalizeBusID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	dom, rest, ok := strings.Cut(id, ":")
	if !ok {
		return id
	}
	if len(dom) > 4 {
		dom = dom[len(dom)-4:]
	}
	return dom + ":" + rest
}
