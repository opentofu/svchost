// Copyright (c) The OpenTofu Authors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package disco

import (
	"net/http"

	"github.com/opentofu/svchost/svcauth"
)

type DiscoOption interface {
	applyOption(disco *Disco)
}

type discoOption func(disco *Disco)

func (o discoOption) applyOption(disco *Disco) {
	o(disco)
}

func WithHTTPClient(client *http.Client) DiscoOption {
	return discoOption(func(disco *Disco) {
		disco.httpClient = client
	})
}

func WithCredentials(creds svcauth.CredentialsSource) DiscoOption {
	return discoOption(func(disco *Disco) {
		disco.credsSrc = creds
	})
}
