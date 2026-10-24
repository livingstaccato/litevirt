package grpcapi

import (
	"os"

	"golang.org/x/sys/unix"
)

// keptScanPseudo is each pseudo-filesystem keptCollisionScan neither lists
// nor reads, by its statfs f_type, so a link to /proc or /sys below a root
// is not walked whatever path names it. devtmpfs reports tmpfs's type and is
// not told apart: what it holds is device nodes, which the scan never opens.
var keptScanPseudo = map[int64]string{
	unix.PROC_SUPER_MAGIC:     "proc",
	unix.SYSFS_MAGIC:          "sysfs",
	unix.CGROUP_SUPER_MAGIC:   "cgroup",
	unix.CGROUP2_SUPER_MAGIC:  "cgroup2",
	unix.DEBUGFS_MAGIC:        "debugfs",
	unix.TRACEFS_MAGIC:        "tracefs",
	unix.SECURITYFS_MAGIC:     "securityfs",
	0x62656570:                "configfs",
	unix.DEVPTS_SUPER_MAGIC:   "devpts",
	0x19800202:                "mqueue",
	unix.BPF_FS_MAGIC:         "bpf",
	unix.PSTOREFS_MAGIC:       "pstore",
	unix.SELINUX_MAGIC:        "selinuxfs",
	unix.SMACK_MAGIC:          "smackfs",
	unix.EFIVARFS_MAGIC:       "efivarfs",
	0x65735543:                "fusectl",
	unix.BINFMTFS_MAGIC:       "binfmt_misc",
	unix.NSFS_MAGIC:           "nsfs",
	unix.RDTGROUP_SUPER_MAGIC: "resctrl",
}

// keptScanPseudoFS reports whether path is on a pseudo-filesystem, and its
// name.
func keptScanPseudoFS(path string) (string, bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return "", false, err
	}
	name, ok := keptScanPseudo[int64(st.Type)]
	return name, ok, nil
}

// keptScanPseudoFSOf is keptScanPseudoFS of an open file.
func keptScanPseudoFSOf(f *os.File) (string, bool, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return "", false, err
	}
	name, ok := keptScanPseudo[int64(st.Type)]
	return name, ok, nil
}
