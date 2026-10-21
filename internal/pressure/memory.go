package pressure

import (
	"bufio"
	"os"
	"runtime/metrics"
	"strconv"
	"strings"
)

// daemonMemory is the Go runtime's mapped memory less what it has already
// returned to the kernel: the daemon's own footprint as the runtime sees it.
func daemonMemory() (uint64, bool) {
	s := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 || s[1].Value.Kind() != metrics.KindUint64 {
		return 0, false
	}
	total, released := s[0].Value.Uint64(), s[1].Value.Uint64()
	if released > total {
		return 0, true
	}
	return total - released, true
}

// hostRAM is MemTotal from /proc/meminfo; 0 where there is none.
func hostRAM() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0
			}
			return kb << 10
		}
	}
	return 0
}
