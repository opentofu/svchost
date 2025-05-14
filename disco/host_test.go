// Copyright (c) The OpenTofu Authors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package disco

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestHostServiceURL(t *testing.T) {
	baseURL, _ := url.Parse("https://example.com/disco/foo.json")
	host := Host{
		discoURL: baseURL,
		hostname: "test-server",
		services: map[string]any{
			"absolute.v1":         "http://example.net/foo/bar",
			"absolutewithport.v1": "http://example.net:8080/foo/bar",
			"relative.v1":         "./stu/",
			"rootrelative.v1":     "/baz",
			"protorelative.v1":    "//example.net/",
			"withfragment.v1":     "http://example.org/#foo",
			"querystring.v1":      "https://example.net/baz?foo=bar",
			"nothttp.v1":          "ftp://127.0.0.1/pub/",
			"invalid.v1":          "***not A URL at all!:/<@@@@>***",
		},
	}

	tests := []struct {
		ID   string
		want string
		err  string
	}{
		{"absolute.v1", "http://example.net/foo/bar", ""},
		{"absolutewithport.v1", "http://example.net:8080/foo/bar", ""},
		{"relative.v1", "https://example.com/disco/stu/", ""},
		{"rootrelative.v1", "https://example.com/baz", ""},
		{"protorelative.v1", "https://example.net/", ""},
		{"withfragment.v1", "http://example.org/", ""},
		{"querystring.v1", "https://example.net/baz?foo=bar", ""},
		{"nothttp.v1", "<nil>", "unsupported scheme"},
		{"invalid.v1", "<nil>", "failed to parse service URL"},
	}

	for _, test := range tests {
		t.Run(test.ID, func(t *testing.T) {
			serviceURL, err := host.ServiceURL(test.ID)
			if (err != nil || test.err != "") &&
				(err == nil || !strings.Contains(err.Error(), test.err)) {
				t.Fatalf("unexpected service URL error: %s", err)
			}

			var got string
			if serviceURL != nil {
				got = serviceURL.String()
			} else {
				got = "<nil>"
			}

			if got != test.want {
				t.Errorf("wrong result\ngot:  %s\nwant: %s", got, test.want)
			}
		})
	}
}

func TestHostServiceOAuthClient(t *testing.T) {
	baseURL, _ := url.Parse("https://example.com/disco/foo.json")
	host := Host{
		discoURL: baseURL,
		hostname: "test-server",
		services: map[string]any{
			"explicitgranttype.v1": map[string]any{
				"client":      "explicitgranttype",
				"authz":       "./authz",
				"token":       "./token",
				"grant_types": []any{"authz_code", "password", "tbd"},
			},
			"customports.v1": map[string]any{
				"client": "customports",
				"authz":  "./authz",
				"token":  "./token",
				"ports":  []any{1025, 1026},
			},
			"invalidports.v1": map[string]any{
				"client": "invalidports",
				"authz":  "./authz",
				"token":  "./token",
				"ports":  []any{1, 65535},
			},
			"missingauthz.v1": map[string]any{
				"client": "missingauthz",
				"token":  "./token",
			},
			"missingtoken.v1": map[string]any{
				"client": "missingtoken",
				"authz":  "./authz",
			},
			"passwordmissingauthz.v1": map[string]any{
				"client":      "passwordmissingauthz",
				"token":       "./token",
				"grant_types": []any{"password"},
			},
			"absolute.v1": map[string]any{
				"client": "absolute",
				"authz":  "http://example.net/foo/authz",
				"token":  "http://example.net/foo/token",
			},
			"absolutewithport.v1": map[string]any{
				"client": "absolutewithport",
				"authz":  "http://example.net:8000/foo/authz",
				"token":  "http://example.net:8000/foo/token",
			},
			"relative.v1": map[string]any{
				"client": "relative",
				"authz":  "./authz",
				"token":  "./token",
			},
			"rootrelative.v1": map[string]any{
				"client": "rootrelative",
				"authz":  "/authz",
				"token":  "/token",
			},
			"protorelative.v1": map[string]any{
				"client": "protorelative",
				"authz":  "//example.net/authz",
				"token":  "//example.net/token",
			},
			"nothttp.v1": map[string]any{
				"client": "nothttp",
				"authz":  "ftp://127.0.0.1/pub/authz",
				"token":  "ftp://127.0.0.1/pub/token",
			},
			"invalidauthz.v1": map[string]any{
				"client": "invalidauthz",
				"authz":  "***not A URL at all!:/<@@@@>***",
				"token":  "/foo",
			},
			"invalidtoken.v1": map[string]any{
				"client": "invalidauthz",
				"authz":  "/foo",
				"token":  "***not A URL at all!:/<@@@@>***",
			},
			"scopesincluded.v1": map[string]any{
				"client": "scopesincluded",
				"authz":  "/auth",
				"token":  "/token",
				"scopes": []any{"app1.full_access", "app2.read_only"},
			},
			"scopesempty.v1": map[string]any{
				"client": "scopesempty",
				"authz":  "/auth",
				"token":  "/token",
				"scopes": []any{},
			},
			"scopesbad.v1": map[string]any{
				"client": "scopesbad",
				"authz":  "/auth",
				"token":  "/token",
				"scopes": []any{"app1.full_access", 42},
			},
		},
	}

	mustURL := func(t *testing.T, s string) *url.URL {
		t.Helper()
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("invalid wanted URL %s in test case: %s", s, err)
		}
		return u
	}

	tests := []struct {
		ID   string
		want *OAuthClient
		err  string
	}{
		{
			"explicitgranttype.v1",
			&OAuthClient{
				ID:                  "explicitgranttype",
				AuthorizationURL:    mustURL(t, "https://example.com/disco/authz"),
				TokenURL:            mustURL(t, "https://example.com/disco/token"),
				MinPort:             1024,
				MaxPort:             65535,
				SupportedGrantTypes: NewOAuthGrantTypeSet("authz_code", "password", "tbd"),
			},
			"",
		},
		{
			"customports.v1",
			&OAuthClient{
				ID:                  "customports",
				AuthorizationURL:    mustURL(t, "https://example.com/disco/authz"),
				TokenURL:            mustURL(t, "https://example.com/disco/token"),
				MinPort:             1025,
				MaxPort:             1026,
				SupportedGrantTypes: NewOAuthGrantTypeSet("authz_code"),
			},
			"",
		},
		{
			"invalidports.v1",
			nil,
			`invalid "ports" definition for service invalidports.v1: both ports must be whole numbers between 1024 and 65535`,
		},
		{
			"missingauthz.v1",
			nil,
			`service missingauthz.v1 definition is missing required property "authz"`,
		},
		{
			"missingtoken.v1",
			nil,
			`service missingtoken.v1 definition is missing required property "token"`,
		},
		{
			"passwordmissingauthz.v1",
			&OAuthClient{
				ID:                  "passwordmissingauthz",
				TokenURL:            mustURL(t, "https://example.com/disco/token"),
				MinPort:             1024,
				MaxPort:             65535,
				SupportedGrantTypes: NewOAuthGrantTypeSet("password"),
			},
			"",
		},
		{
			"absolute.v1",
			&OAuthClient{
				ID:                  "absolute",
				AuthorizationURL:    mustURL(t, "http://example.net/foo/authz"),
				TokenURL:            mustURL(t, "http://example.net/foo/token"),
				MinPort:             1024,
				MaxPort:             65535,
				SupportedGrantTypes: NewOAuthGrantTypeSet("authz_code"),
			},
			"",
		},
		{
			"absolutewithport.v1",
			&OAuthClient{
				ID:                  "absolutewithport",
				AuthorizationURL:    mustURL(t, "http://example.net:8000/foo/authz"),
				TokenURL:            mustURL(t, "http://example.net:8000/foo/token"),
				MinPort:             1024,
				MaxPort:             65535,
				SupportedGrantTypes: NewOAuthGrantTypeSet("authz_code"),
			},
			"",
		},
		{
			"relative.v1",
			&OAuthClient{
				ID:                  "relative",
				AuthorizationURL:    mustURL(t, "https://example.com/disco/authz"),
				TokenURL:            mustURL(t, "https://example.com/disco/token"),
				MinPort:             1024,
				MaxPort:             65535,
				SupportedGrantTypes: NewOAuthGrantTypeSet("authz_code"),
			},
			"",
		},
		{
			"rootrelative.v1",
			&OAuthClient{
				ID:                  "rootrelative",
				AuthorizationURL:    mustURL(t, "https://example.com/authz"),
				TokenURL:            mustURL(t, "https://example.com/token"),
				MinPort:             1024,
				MaxPort:             65535,
				SupportedGrantTypes: NewOAuthGrantTypeSet("authz_code"),
			},
			"",
		},
		{
			"protorelative.v1",
			&OAuthClient{
				ID:                  "protorelative",
				AuthorizationURL:    mustURL(t, "https://example.net/authz"),
				TokenURL:            mustURL(t, "https://example.net/token"),
				MinPort:             1024,
				MaxPort:             65535,
				SupportedGrantTypes: NewOAuthGrantTypeSet("authz_code"),
			},
			"",
		},
		{
			"nothttp.v1",
			nil,
			"failed to parse authorization URL: unsupported scheme ftp",
		},
		{
			"invalidauthz.v1",
			nil,
			"failed to parse authorization URL: parse \"***not A URL at all!:/<@@@@>***\": first path segment in URL cannot contain colon",
		},
		{
			"invalidtoken.v1",
			nil,
			"failed to parse token URL: parse \"***not A URL at all!:/<@@@@>***\": first path segment in URL cannot contain colon",
		},
		{
			"scopesincluded.v1",
			&OAuthClient{
				ID:                  "scopesincluded",
				AuthorizationURL:    mustURL(t, "https://example.com/auth"),
				TokenURL:            mustURL(t, "https://example.com/token"),
				MinPort:             1024,
				MaxPort:             65535,
				SupportedGrantTypes: NewOAuthGrantTypeSet("authz_code"),
				Scopes:              []string{"app1.full_access", "app2.read_only"},
			},
			"",
		},
		{
			"scopesempty.v1",
			&OAuthClient{
				ID:                  "scopesempty",
				AuthorizationURL:    mustURL(t, "https://example.com/auth"),
				TokenURL:            mustURL(t, "https://example.com/token"),
				MinPort:             1024,
				MaxPort:             65535,
				SupportedGrantTypes: NewOAuthGrantTypeSet("authz_code"),
			},
			"",
		},
		{
			"scopesbad.v1",
			nil,
			`invalid "scopes" for service scopesbad.v1: all scopes must be strings`,
		},
	}

	for _, test := range tests {
		t.Run(test.ID, func(t *testing.T) {
			got, err := host.ServiceOAuthClient(test.ID)
			if (err != nil || test.err != "") &&
				(err == nil || !strings.Contains(err.Error(), test.err)) {
				t.Fatalf("unexpected service URL error: %s", err)
			}

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("wrong result\n%s", diff)
			}
		})
	}
}

func testVersionsServer(h func(w http.ResponseWriter, r *http.Request)) (portStr string, cleanup func()) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Test server always returns 404 if the URL isn't what we expect
			if !strings.HasPrefix(r.URL.Path, "/v1/versions/") {
				w.WriteHeader(404)
				w.Write([]byte("not found"))
				return
			}

			// If the URL is correct then the given hander decides the response
			h(w, r)
		},
	))

	serverURL, _ := url.Parse(server.URL)

	portStr = serverURL.Port()
	if portStr != "" {
		portStr = ":" + portStr
	}

	cleanup = func() {
		server.Close()
	}

	return portStr, cleanup
}
