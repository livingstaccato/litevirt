// Package pressure watches this host's own resources (the data directory's
// filesystem, each storage pool's, the daemon's file descriptors and memory)
// and grades each one ok, warn, degrade or critical, with hysteresis, so the
// host can say it is running out of room before it does
// (docs/configuration.md, "Resource pressure").
//
// It only observes. A level is reported on the readiness probe, in a health
// condition, in metrics and in `lv host inspect`; nothing is refused, paused or
// shed because of it. In particular pressure never makes a host unready: an
// unready host loses its voting weight, and a fill common to every host (a log
// storm) would then take the whole fleet below majority.
package pressure

import (
	"fmt"
)

// Config is the `pressure:` block of config.yaml. It is per host: each host
// reads its own. Every threshold of 0 is off (that level is never entered by
// it).
type Config struct {
	// Enabled false samples nothing and reports nothing: peers see the
	// host's pressure as unknown.
	Enabled bool `yaml:"enabled"`
	// SampleIntervalSec is the time between samples.
	SampleIntervalSec int `yaml:"sample_interval_sec"`
	// EnterSamples is how many consecutive samples past a threshold enter
	// its level.
	EnterSamples int `yaml:"enter_samples"`
	// ClearMarginPct is how many percentage points better than a level's
	// threshold a sample must be to count toward leaving it. A MiB floor
	// needs 25 % of the floor beyond it instead.
	ClearMarginPct float64 `yaml:"clear_margin_pct"`
	// ClearAfterSec is how long every sample must stay past the margin
	// before a level is left.
	ClearAfterSec int `yaml:"clear_after_sec"`
	// TrendWindowSec is the window the time-to-full projection fits its
	// slope over.
	TrendWindowSec int `yaml:"trend_window_sec"`
	// DataDir grades the data directory's filesystem.
	DataDir FSThresholds `yaml:"data_dir"`
	// Pools grades every storage pool's filesystem, unless PoolOverrides
	// names the pool.
	Pools FSThresholds `yaml:"pools"`
	// PoolOverrides replaces, per pool name, the thresholds it sets.
	PoolOverrides map[string]FSOverride `yaml:"pool_overrides"`
	// Memory grades the daemon's own memory.
	Memory MemoryThresholds `yaml:"memory"`
	// FDs grades the daemon's open file descriptors against its limit.
	FDs UsageThresholds `yaml:"fds"`
}

// FSThresholds grade one filesystem by what is FREE to the daemon
// (f_bavail): a level is entered when free space is under its percentage OR
// under its MiB floor, whichever is crossed first, so a large filesystem is
// not left to a percentage alone.
type FSThresholds struct {
	WarnFreePct     float64 `yaml:"warn_free_pct"`
	DegradeFreePct  float64 `yaml:"degrade_free_pct"`
	CriticalFreePct float64 `yaml:"critical_free_pct"`

	WarnFreeMiB     int64 `yaml:"warn_free_mib"`
	DegradeFreeMiB  int64 `yaml:"degrade_free_mib"`
	CriticalFreeMiB int64 `yaml:"critical_free_mib"`

	WarnFreeInodesPct     float64 `yaml:"warn_free_inodes_pct"`
	DegradeFreeInodesPct  float64 `yaml:"degrade_free_inodes_pct"`
	CriticalFreeInodesPct float64 `yaml:"critical_free_inodes_pct"`
}

// FSOverride is FSThresholds with every field optional: a field left out
// keeps the `pools:` value.
type FSOverride struct {
	WarnFreePct     *float64 `yaml:"warn_free_pct"`
	DegradeFreePct  *float64 `yaml:"degrade_free_pct"`
	CriticalFreePct *float64 `yaml:"critical_free_pct"`

	WarnFreeMiB     *int64 `yaml:"warn_free_mib"`
	DegradeFreeMiB  *int64 `yaml:"degrade_free_mib"`
	CriticalFreeMiB *int64 `yaml:"critical_free_mib"`

	WarnFreeInodesPct     *float64 `yaml:"warn_free_inodes_pct"`
	DegradeFreeInodesPct  *float64 `yaml:"degrade_free_inodes_pct"`
	CriticalFreeInodesPct *float64 `yaml:"critical_free_inodes_pct"`
}

// UsageThresholds grade a resource by the percentage of its limit in USE.
type UsageThresholds struct {
	WarnPct     float64 `yaml:"warn_pct"`
	DegradePct  float64 `yaml:"degrade_pct"`
	CriticalPct float64 `yaml:"critical_pct"`
}

// MemoryThresholds grade the daemon's memory (the Go runtime's mapped
// memory, less what it has returned to the kernel) against a limit.
type MemoryThresholds struct {
	// DaemonLimitMiB is the limit; 0 is auto: 10 % of the host's RAM, at
	// least 1 GiB and at most 4 GiB.
	DaemonLimitMiB  int64 `yaml:"daemon_limit_mib"`
	UsageThresholds `yaml:",inline"`
}

// DefaultConfig is the owner's defaults (2026-10-21): warn 15 %, degrade
// 8 %, critical 3 % free, with 4 GiB / 2 GiB / 512 MiB floors, for the data
// directory and for every pool alike.
func DefaultConfig() Config {
	fs := FSThresholds{
		WarnFreePct: 15, DegradeFreePct: 8, CriticalFreePct: 3,
		WarnFreeMiB: 4096, DegradeFreeMiB: 2048, CriticalFreeMiB: 512,
		WarnFreeInodesPct: 10, DegradeFreeInodesPct: 5, CriticalFreeInodesPct: 1,
	}
	return Config{
		Enabled:           true,
		SampleIntervalSec: 5,
		EnterSamples:      2,
		ClearMarginPct:    2,
		ClearAfterSec:     120,
		TrendWindowSec:    900,
		DataDir:           fs,
		Pools:             fs,
		Memory:            MemoryThresholds{UsageThresholds: UsageThresholds{WarnPct: 60, DegradePct: 75, CriticalPct: 90}},
		FDs:               UsageThresholds{WarnPct: 70, DegradePct: 85, CriticalPct: 95},
	}
}

// PoolThresholds is the thresholds pool name is graded by.
func (c Config) PoolThresholds(name string) FSThresholds {
	t := c.Pools
	o, ok := c.PoolOverrides[name]
	if !ok {
		return t
	}
	setF := func(dst *float64, v *float64) {
		if v != nil {
			*dst = *v
		}
	}
	setI := func(dst *int64, v *int64) {
		if v != nil {
			*dst = *v
		}
	}
	setF(&t.WarnFreePct, o.WarnFreePct)
	setF(&t.DegradeFreePct, o.DegradeFreePct)
	setF(&t.CriticalFreePct, o.CriticalFreePct)
	setI(&t.WarnFreeMiB, o.WarnFreeMiB)
	setI(&t.DegradeFreeMiB, o.DegradeFreeMiB)
	setI(&t.CriticalFreeMiB, o.CriticalFreeMiB)
	setF(&t.WarnFreeInodesPct, o.WarnFreeInodesPct)
	setF(&t.DegradeFreeInodesPct, o.DegradeFreeInodesPct)
	setF(&t.CriticalFreeInodesPct, o.CriticalFreeInodesPct)
	return t
}

// Validate refuses a config that cannot grade sensibly: an interval, a run
// or a window that is not positive, a percentage outside 0-100, or levels out
// of order (a degrade threshold looser than warn's). A level that is off (0)
// takes no part in the ordering.
func (c Config) Validate() error {
	switch {
	case c.SampleIntervalSec < 1:
		return fmt.Errorf("pressure.sample_interval_sec %d: must be at least 1", c.SampleIntervalSec)
	case c.EnterSamples < 1:
		return fmt.Errorf("pressure.enter_samples %d: must be at least 1", c.EnterSamples)
	case c.ClearMarginPct < 0 || c.ClearMarginPct > 100:
		return fmt.Errorf("pressure.clear_margin_pct %v: must be between 0 and 100", c.ClearMarginPct)
	case c.ClearAfterSec < 0:
		return fmt.Errorf("pressure.clear_after_sec %d: must not be negative", c.ClearAfterSec)
	case c.TrendWindowSec < 60:
		return fmt.Errorf("pressure.trend_window_sec %d: must be at least 60", c.TrendWindowSec)
	case c.Memory.DaemonLimitMiB < 0:
		return fmt.Errorf("pressure.memory.daemon_limit_mib %d: must not be negative (0 is auto)", c.Memory.DaemonLimitMiB)
	}
	if err := c.DataDir.validate("pressure.data_dir"); err != nil {
		return err
	}
	if err := c.Pools.validate("pressure.pools"); err != nil {
		return err
	}
	for name := range c.PoolOverrides {
		if err := c.PoolThresholds(name).validate("pressure.pool_overrides." + name); err != nil {
			return err
		}
	}
	if err := c.Memory.validate("pressure.memory"); err != nil {
		return err
	}
	return c.FDs.validate("pressure.fds")
}

func (t FSThresholds) validate(where string) error {
	if err := freeOrder(where, "free_pct", t.WarnFreePct, t.DegradeFreePct, t.CriticalFreePct, 100); err != nil {
		return err
	}
	if err := freeOrder(where, "free_mib", float64(t.WarnFreeMiB), float64(t.DegradeFreeMiB), float64(t.CriticalFreeMiB), -1); err != nil {
		return err
	}
	return freeOrder(where, "free_inodes_pct", t.WarnFreeInodesPct, t.DegradeFreeInodesPct, t.CriticalFreeInodesPct, 100)
}

func (t UsageThresholds) validate(where string) error {
	vals := []float64{t.WarnPct, t.DegradePct, t.CriticalPct}
	names := []string{"warn_pct", "degrade_pct", "critical_pct"}
	prev, prevName := 0.0, ""
	for i, v := range vals {
		if v < 0 || v > 100 {
			return fmt.Errorf("%s.%s %v: must be between 0 and 100", where, names[i], v)
		}
		if v == 0 {
			continue
		}
		if prevName != "" && v < prev {
			return fmt.Errorf("%s.%s %v is below %s %v: a worse level needs more in use", where, names[i], v, prevName, prev)
		}
		prev, prevName = v, names[i]
	}
	return nil
}

// freeOrder checks one free-space triple: each in [0, max] (max < 0: no
// upper bound), and a worse level's threshold no higher than a milder one's.
func freeOrder(where, suffix string, warn, degrade, critical, max float64) error {
	vals := []float64{warn, degrade, critical}
	names := []string{"warn_", "degrade_", "critical_"}
	prev, prevName := 0.0, ""
	for i, v := range vals {
		if v < 0 || (max >= 0 && v > max) {
			return fmt.Errorf("%s.%s%s %v: out of range", where, names[i], suffix, v)
		}
		if v == 0 {
			continue
		}
		if prevName != "" && v > prev {
			return fmt.Errorf("%s.%s%s %v is above %s%s %v: a worse level needs less free", where, names[i], suffix, v, prevName, suffix, prev)
		}
		prev, prevName = v, names[i]
	}
	return nil
}
