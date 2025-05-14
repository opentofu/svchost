// Copyright (c) The OpenTofu Authors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package svcauth

import (
	"context"

	"github.com/opentofu/svchost"
)

// StaticCredentialsSource returns a [CredentialsSource] that looks up any
// requested tokens directly in the provided map.
func StaticCredentialsSource(creds map[svchost.Hostname]HostCredentials) CredentialsSource {
	return staticCredentialsSource(creds)
}

type staticCredentialsSource map[svchost.Hostname]HostCredentials

// ForHost implements [CredentialsSource].
func (s staticCredentialsSource) ForHost(_ context.Context, host svchost.Hostname) (HostCredentials, error) {
	return s[host], nil
}
