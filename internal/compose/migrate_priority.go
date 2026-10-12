package compose

import (
	"log/slog"
	"math"
)

// clampMigratePriority bounds a compose migrate.priority to the int32 it is
// stored as (MigrationPolicy.priority), logging a WARN naming field when it
// had to. Out of range is clamped, never refused: such a file deployed before
// priorities were read, and the clamp keeps the order the operator meant
// (3000000000 is "highest") where the old int32 conversion wrapped it.
func clampMigratePriority(field string, v int) int {
	clamped := min(max(v, math.MinInt32), math.MaxInt32)
	if clamped != v {
		slog.Warn("compose: migrate.priority is outside the stored range and was clamped; higher still goes first",
			"field", field, "value", v, "clamped", clamped)
	}
	return clamped
}
