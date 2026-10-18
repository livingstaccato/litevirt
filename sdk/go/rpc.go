package litevirt

import (
	"context"
	av "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
)

// GetAutomationCapabilities calls the corresponding public Automation RPC.
func (c *Client) GetAutomationCapabilities(ctx context.Context, request *av.GetAutomationCapabilitiesRequest) (*av.GetAutomationCapabilitiesResponse, error) {
	return rpc(c, ctx, request, false, func(s av.AutomationClient, ctx context.Context, r *av.GetAutomationCapabilitiesRequest) (*av.GetAutomationCapabilitiesResponse, error) {
		return s.GetAutomationCapabilities(ctx, r)
	})
}

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

// ResolveBinding calls the corresponding public Automation RPC.
func (c *Client) ResolveBinding(ctx context.Context, request *av.ResolveBindingRequest) (*av.ResolveBindingResponse, error) {
	return rpc(c, ctx, request, false, func(s av.AutomationClient, ctx context.Context, r *av.ResolveBindingRequest) (*av.ResolveBindingResponse, error) {
		return s.ResolveBinding(ctx, r)
	})
}

// ObserveResource calls the corresponding public Automation RPC.
func (c *Client) ObserveResource(ctx context.Context, request *av.ObserveResourceRequest) (*av.ObserveResourceResponse, error) {
	return rpc(c, ctx, request, false, func(s av.AutomationClient, ctx context.Context, r *av.ObserveResourceRequest) (*av.ObserveResourceResponse, error) {
		return s.ObserveResource(ctx, r)
	})
}

// SubmitCreateVM calls the corresponding public Automation RPC.
func (c *Client) SubmitCreateVM(ctx context.Context, request *av.SubmitCreateVMRequest) (*av.SubmitCreateVMResponse, error) {
	return rpc(c, ctx, request, true, func(s av.AutomationClient, ctx context.Context, r *av.SubmitCreateVMRequest) (*av.SubmitCreateVMResponse, error) {
		return s.SubmitCreateVM(ctx, r)
	})
}

// SubmitUpdateVM calls the corresponding public Automation RPC.
func (c *Client) SubmitUpdateVM(ctx context.Context, request *av.SubmitUpdateVMRequest) (*av.SubmitUpdateVMResponse, error) {
	return rpc(c, ctx, request, true, func(s av.AutomationClient, ctx context.Context, r *av.SubmitUpdateVMRequest) (*av.SubmitUpdateVMResponse, error) {
		return s.SubmitUpdateVM(ctx, r)
	})
}

// SubmitDeleteVM calls the corresponding public Automation RPC.
func (c *Client) SubmitDeleteVM(ctx context.Context, request *av.SubmitDeleteVMRequest) (*av.SubmitDeleteVMResponse, error) {
	return rpc(c, ctx, request, true, func(s av.AutomationClient, ctx context.Context, r *av.SubmitDeleteVMRequest) (*av.SubmitDeleteVMResponse, error) {
		return s.SubmitDeleteVM(ctx, r)
	})
}

// GetOperation calls the corresponding public Automation RPC.
func (c *Client) GetOperation(ctx context.Context, request *av.GetOperationRequest) (*av.GetOperationResponse, error) {
	return rpc(c, ctx, request, false, func(s av.AutomationClient, ctx context.Context, r *av.GetOperationRequest) (*av.GetOperationResponse, error) {
		return s.GetOperation(ctx, r)
	})
}

// ListByOwner calls the corresponding public Automation RPC.
func (c *Client) ListByOwner(ctx context.Context, request *av.ListByOwnerRequest) (*av.ListByOwnerResponse, error) {
	return rpc(c, ctx, request, false, func(s av.AutomationClient, ctx context.Context, r *av.ListByOwnerRequest) (*av.ListByOwnerResponse, error) {
		return s.ListByOwner(ctx, r)
	})
}

// AdoptResource calls the corresponding public Automation RPC.
func (c *Client) AdoptResource(ctx context.Context, request *av.AdoptResourceRequest) (*av.AdoptResourceResponse, error) {
	return rpc(c, ctx, request, true, func(s av.AutomationClient, ctx context.Context, r *av.AdoptResourceRequest) (*av.AdoptResourceResponse, error) {
		return s.AdoptResource(ctx, r)
	})
}

// TransferOwner calls the corresponding public Automation RPC.
func (c *Client) TransferOwner(ctx context.Context, request *av.TransferOwnerRequest) (*av.TransferOwnerResponse, error) {
	return rpc(c, ctx, request, true, func(s av.AutomationClient, ctx context.Context, r *av.TransferOwnerRequest) (*av.TransferOwnerResponse, error) {
		return s.TransferOwner(ctx, r)
	})
}
