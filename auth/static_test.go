// Copyright (c) The OpenTofu Authors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"testing"

	svchost "github.com/opentofu/svchost"
)

func TestStaticCredentialsSource(t *testing.T) {
	src := StaticCredentialsSource(map[svchost.Hostname]map[string]interface{}{
		svchost.Hostname("example.com"): {
			"token": "abc123",
		},
	})

	t.Run("exists", func(t *testing.T) {
		creds, err := src.ForHost(svchost.Hostname("example.com"))
		if err != nil {
			t.Fatal(err)
		}
		if tokCreds, isToken := creds.(HostCredentialsToken); isToken {
			if got, want := string(tokCreds), "abc123"; got != want {
				t.Errorf("wrong token %q; want %q", got, want)
			}
		} else {
			t.Errorf("creds is %#v; want HostCredentialsToken", creds)
		}
	})
	t.Run("does not exist", func(t *testing.T) {
		creds, err := src.ForHost(svchost.Hostname("example.net"))
		if err != nil {
			t.Fatal(err)
		}
		if creds != nil {
			t.Errorf("creds is %#v; want nil", creds)
		}
	})
}
