// Copyright (c) The OpenTofu Authors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package disco

import (
	"context"

	svchost "github.com/opentofu/svchost"
)

// DiscoTrace allows a caller of [Disco.Discover] to be notified about
// potentially-interesting events during the discovery process, in case
// they want to generate log messages, telemetry traces, or similar.
//
// Use [ContextWithDiscoTrace] to derive a [context.Context] containing
// an instance of this type, and use that context when calling
// [Disco.Discover] or one of its shortcut variants.
//
// All of the function-typed fields may either be left as nil or set to
// a function with the specified signature, unless otherwise stated. If
// nil then the call for the corresponding event will be skipped.
//
// "Start" functions return their own [context.Context] that should be
// either exactly the context given or a child of that context. This can
// be used to track per-request values such as distributed tracing spans.
type DiscoTrace struct {
	// DiscoveryStart is called when a discovery request is about to begin
	// for a specific hostname.
	//
	// This should return a [context.Context] to be used for the discovery
	// HTTP requests, and it will then be passed as the context to either
	// DiscoverySuccess or DiscoveryFailure once the request is complete
	// to allow terminating distributed tracing spans, etc.
	DiscoveryStart func(ctx context.Context, host svchost.Hostname) context.Context

	// DiscoverySuccess is called after a discovery request is complete if
	// the result was successful.
	//
	// The given context has the same values as the one returned by the earlier
	// call to DiscoveryStart.
	DiscoverySuccess func(ctx context.Context, host svchost.Hostname)

	// DiscoveryFailure is called after a discovery request is complete if
	// the request encountered an error.
	//
	// The given context has the same values as the one returned by the earlier
	// call to DiscoveryStart.
	DiscoveryFailure func(ctx context.Context, host svchost.Hostname, err error)

	// DiscoveryHostCached is called instead of DiscoveryStart and its
	// completion callbacks if a service discovery request is served from the
	// cache of previous results rather than by making a discovery request.
	DiscoveryHostCached func(ctx context.Context, host svchost.Hostname)
}

func ContextWithDiscoTrace(parent context.Context, trace *DiscoTrace) context.Context {
	return context.WithValue(parent, discoTraceKey, trace)
}

func (t *DiscoTrace) discoveryStart(ctx context.Context, host svchost.Hostname) context.Context {
	if t.DiscoveryStart == nil {
		return ctx
	}
	return t.DiscoveryStart(ctx, host)
}

func (t *DiscoTrace) discoverySuccess(ctx context.Context, host svchost.Hostname) {
	if t.DiscoverySuccess == nil {
		return
	}
	t.DiscoverySuccess(ctx, host)
}

func (t *DiscoTrace) discoveryFailure(ctx context.Context, host svchost.Hostname, err error) {
	if t.DiscoveryFailure == nil {
		return
	}
	t.DiscoveryFailure(ctx, host, err)
}

func (t *DiscoTrace) discoveryHostCached(ctx context.Context, host svchost.Hostname) {
	if t.DiscoveryHostCached == nil {
		return
	}
	t.DiscoveryHostCached(ctx, host)
}

func discoTraceFromContext(ctx context.Context) *DiscoTrace {
	trace, ok := ctx.Value(discoTraceKey).(*DiscoTrace)
	if !ok {
		trace = noTrace
	}
	return trace
}

type discoTraceKeyType string

const discoTraceKey = discoTraceKeyType("")

var noTrace = &DiscoTrace{}
