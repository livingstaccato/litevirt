package grpcapi

import "github.com/litevirt/litevirt/internal/health"

// Review m-4: the production release gate must answer the release token's own
// latch, or ReleaseTokenLatched silently falls back to reading a feature.
var _ releaseTokenLatcher = (*health.Checker)(nil)
