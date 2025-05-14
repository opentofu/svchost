// Copyright (c) The OpenTofu Authors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"github.com/opentofu/svchost"
)

// StaticCredentialsSource is a credentials source that retrieves credentials
// from the provided map. It returns nil if a requested hostname is not
// present in the map.
//
// The caller should not modify the given map after passing it to this function.
func StaticCredentialsSource(creds map[svchost.Hostname]map[string]any) CredentialsSource {
	return staticCredentialsSource(creds)
}

type staticCredentialsSource map[svchost.Hostname]map[string]any

func (s staticCredentialsSource) ForHost(host svchost.Hostname) (HostCredentials, error) {
	if s == nil {
		return nil, nil
	}

	if m, exists := s[host]; exists {
		return HostCredentialsFromMap(m), nil
	}

	return nil, nil
}
