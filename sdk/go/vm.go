package litevirt

import (
	"context"
	av "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
)

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

// AdoptResource calls the corresponding public Automation RPC.
func (c *Client) AdoptResource(ctx context.Context, request *av.AdoptResourceRequest) (*av.AdoptResourceResponse, error) {
	return rpc(c, ctx, request, true, func(s av.AutomationClient, ctx context.Context, r *av.AdoptResourceRequest) (*av.AdoptResourceResponse, error) {
		return s.AdoptResource(ctx, r)
	})
}
