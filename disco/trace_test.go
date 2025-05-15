// Copyright (c) The OpenTofu Authors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package disco

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/opentofu/svchost"
)

func TestDiscoTrace(t *testing.T) {
	type TraceEvent struct {
		Event      string
		Arg        string
		Err        string
		CorrectCtx bool
	}
	type ctxKey string
	var gotEvents []TraceEvent

	isDerivedCtx := func(ctx context.Context) bool {
		return ctx.Value(ctxKey("derivedInDiscoveryStart")) != nil
	}

	ctx := ContextWithDiscoTrace(t.Context(), &DiscoTrace{
		DiscoveryStart: func(ctx context.Context, host svchost.Hostname) context.Context {
			gotEvents = append(gotEvents, TraceEvent{
				Event:      "DiscoveryStart",
				Arg:        host.ForDisplay(),
				CorrectCtx: true,
			})
			return context.WithValue(ctx, ctxKey("derivedInDiscoveryStart"), true)
		},
		DiscoverySuccess: func(ctx context.Context, host svchost.Hostname) {
			gotEvents = append(gotEvents, TraceEvent{
				Event:      "DiscoverySuccess",
				Arg:        host.ForDisplay(),
				CorrectCtx: isDerivedCtx(ctx),
			})
		},
		DiscoveryFailure: func(ctx context.Context, host svchost.Hostname, err error) {
			gotEvents = append(gotEvents, TraceEvent{
				Event:      "DiscoveryFailure",
				Arg:        host.ForDisplay(),
				Err:        err.Error(),
				CorrectCtx: isDerivedCtx(ctx),
			})
		},
		DiscoveryHostCached: func(ctx context.Context, host svchost.Hostname) {
			gotEvents = append(gotEvents, TraceEvent{
				Event:      "DiscoveryHostCached",
				Arg:        host.ForDisplay(),
				CorrectCtx: true,
			})
		},
	})

	serverFails := true
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serverFails {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.Header().Set("content-length", "2")
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	hostname := strings.TrimPrefix(server.URL, "https://")

	disco := New(WithHTTPClient(server.Client()))

	// The following don't use t.Run subtests because the steps are interdependent.

	// 1. Discovery fails
	{
		_, err := disco.Discover(ctx, svchost.Hostname(hostname))
		if err == nil {
			t.Fatal("unexpected success; want error")
		}

		wantEvents := []TraceEvent{
			{
				Event:      "DiscoveryStart",
				Arg:        hostname,
				CorrectCtx: true,
			},
			{
				Event:      "DiscoveryFailure",
				Arg:        hostname,
				Err:        `failed to request discovery document: 500 Internal Server Error`,
				CorrectCtx: true,
			},
		}
		if diff := cmp.Diff(wantEvents, gotEvents); diff != "" {
			t.Error("wrong trace events\n" + diff)
		}
	}

	// 2. Discovery succeeds
	{
		disco.Forget(svchost.Hostname(hostname))
		serverFails = false
		gotEvents = nil

		_, err := disco.Discover(ctx, svchost.Hostname(hostname))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		wantEvents := []TraceEvent{
			{
				Event:      "DiscoveryStart",
				Arg:        hostname,
				CorrectCtx: true,
			},
			{
				Event:      "DiscoverySuccess",
				Arg:        hostname,
				CorrectCtx: true,
			},
		}
		if diff := cmp.Diff(wantEvents, gotEvents); diff != "" {
			t.Error("wrong trace events\n" + diff)
		}
	}

	// 2. Discovery from cache of previous result
	{
		// NOTE: No disco.Forget this time, so the cache entry stands
		gotEvents = nil

		_, err := disco.Discover(ctx, svchost.Hostname(hostname))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		wantEvents := []TraceEvent{
			{
				Event:      "DiscoveryHostCached",
				Arg:        hostname,
				CorrectCtx: true,
			},
		}
		if diff := cmp.Diff(wantEvents, gotEvents); diff != "" {
			t.Error("wrong trace events\n" + diff)
		}
	}
}
