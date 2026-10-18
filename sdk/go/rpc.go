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

// GetOperation calls the corresponding public Automation RPC.
func (c *Client) GetOperation(ctx context.Context, request *av.GetOperationRequest) (*av.GetOperationResponse, error) {
	return rpc(c, ctx, request, false, func(s av.AutomationClient, ctx context.Context, r *av.GetOperationRequest) (*av.GetOperationResponse, error) {
		return s.GetOperation(ctx, r)
	})
}
