package compose

import (
	"fmt"
	"strconv"
	"strings"
)

// ByteRate is a bytes-per-second value: a plain number of bytes, or one with a
// binary suffix ("50M", "1G", "512K", "100MiB").
type ByteRate int64

// UnmarshalYAML accepts an int or a suffixed string.
func (b *ByteRate) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var i int64
	if err := unmarshal(&i); err == nil {
		*b = ByteRate(i)
		return nil
	}
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	v, err := ParseByteRate(s)
	if err != nil {
		return err
	}
	*b = ByteRate(v)
	return nil
}

// ParseByteRate reads a byte rate: a number of bytes, or one with a K, M, G or T suffix.
func ParseByteRate(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	t = strings.TrimSuffix(strings.TrimSuffix(t, "B"), "I")
	mult := int64(1)
	switch {
	case strings.HasSuffix(t, "K"):
		mult, t = 1<<10, strings.TrimSuffix(t, "K")
	case strings.HasSuffix(t, "M"):
		mult, t = 1<<20, strings.TrimSuffix(t, "M")
	case strings.HasSuffix(t, "G"):
		mult, t = 1<<30, strings.TrimSuffix(t, "G")
	case strings.HasSuffix(t, "T"):
		mult, t = 1<<40, strings.TrimSuffix(t, "T")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid byte rate %q: want a number of bytes or one with a K, M, G or T suffix", s)
	}
	if n > (1<<62)/mult {
		return 0, fmt.Errorf("byte rate %q is too large", s)
	}
	return n * mult, nil
}

// IOTuneDef is a disk's I/O throttle. 0 or unset is unlimited. A total_* limit
// cannot be combined with the read_*/write_* limit of the same kind; *_max is
// the burst ceiling above the sustained rate and needs it.
type IOTuneDef struct {
	TotalBytesSec ByteRate `yaml:"total_bytes_sec,omitempty"`
	ReadBytesSec  ByteRate `yaml:"read_bytes_sec,omitempty"`
	WriteBytesSec ByteRate `yaml:"write_bytes_sec,omitempty"`
	TotalIopsSec  int64    `yaml:"total_iops_sec,omitempty"`
	ReadIopsSec   int64    `yaml:"read_iops_sec,omitempty"`
	WriteIopsSec  int64    `yaml:"write_iops_sec,omitempty"`

	TotalBytesSecMax ByteRate `yaml:"total_bytes_sec_max,omitempty"`
	ReadBytesSecMax  ByteRate `yaml:"read_bytes_sec_max,omitempty"`
	WriteBytesSecMax ByteRate `yaml:"write_bytes_sec_max,omitempty"`
	TotalIopsSecMax  int64    `yaml:"total_iops_sec_max,omitempty"`
	ReadIopsSecMax   int64    `yaml:"read_iops_sec_max,omitempty"`
	WriteIopsSecMax  int64    `yaml:"write_iops_sec_max,omitempty"`

	// BurstSeconds is how long a *_max burst lasts (default 1s).
	BurstSeconds int64 `yaml:"burst_seconds,omitempty"`
}

// NICQueues is a NIC's multiqueue count: a number, or "auto".
type NICQueues struct {
	N    int32
	Auto bool
}

// UnmarshalYAML accepts an int or "auto".
func (q *NICQueues) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var i int32
	if err := unmarshal(&i); err == nil {
		*q = NICQueues{N: i}
		return nil
	}
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(s), "auto") {
		*q = NICQueues{Auto: true}
		return nil
	}
	return fmt.Errorf("invalid queues %q: want a number or auto", s)
}

// IsZero lets yaml omit an unset value.
func (q NICQueues) IsZero() bool { return q.N == 0 && !q.Auto }

// MarshalYAML writes the form the file takes: a number, or auto.
func (q NICQueues) MarshalYAML() (interface{}, error) {
	if q.Auto {
		return "auto", nil
	}
	return q.N, nil
}
