package litevirt

import (
	"context"
	av "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
)

// EnsureOwner calls the corresponding public Automation RPC.
func (c *Client) EnsureOwner(ctx context.Context, request *av.EnsureOwnerRequest) (*av.EnsureOwnerResponse, error) {
	return rpc(c, ctx, request, true, func(s av.AutomationClient, ctx context.Context, r *av.EnsureOwnerRequest) (*av.EnsureOwnerResponse, error) {
		return s.EnsureOwner(ctx, r)
	})
}

// AcquireOwnerSession calls the corresponding public Automation RPC.
func (c *Client) AcquireOwnerSession(ctx context.Context, request *av.AcquireOwnerSessionRequest) (*av.AcquireOwnerSessionResponse, error) {
	return rpc(c, ctx, request, true, func(s av.AutomationClient, ctx context.Context, r *av.AcquireOwnerSessionRequest) (*av.AcquireOwnerSessionResponse, error) {
		return s.AcquireOwnerSession(ctx, r)
	})
}

// HandoffOwnerSession calls the corresponding public Automation RPC.
func (c *Client) HandoffOwnerSession(ctx context.Context, request *av.HandoffOwnerSessionRequest) (*av.HandoffOwnerSessionResponse, error) {
	return rpc(c, ctx, request, true, func(s av.AutomationClient, ctx context.Context, r *av.HandoffOwnerSessionRequest) (*av.HandoffOwnerSessionResponse, error) {
		return s.HandoffOwnerSession(ctx, r)
	})
}

// ListByOwner calls the corresponding public Automation RPC.
func (c *Client) ListByOwner(ctx context.Context, request *av.ListByOwnerRequest) (*av.ListByOwnerResponse, error) {
	return rpc(c, ctx, request, false, func(s av.AutomationClient, ctx context.Context, r *av.ListByOwnerRequest) (*av.ListByOwnerResponse, error) {
		return s.ListByOwner(ctx, r)
	})
}

// TransferOwner calls the corresponding public Automation RPC.
func (c *Client) TransferOwner(ctx context.Context, request *av.TransferOwnerRequest) (*av.TransferOwnerResponse, error) {
	return rpc(c, ctx, request, true, func(s av.AutomationClient, ctx context.Context, r *av.TransferOwnerRequest) (*av.TransferOwnerResponse, error) {
		return s.TransferOwner(ctx, r)
	})
}
