// Copyright (c) The OpenTofu Authors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package disco handles OpenTofu's remote service discovery protocol.
//
// This protocol allows mapping from a service hostname, as produced by the
// svchost package, to a set of services supported by that host and the
// endpoint information for each supported service.
package disco

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sync"
	"time"

	svchost "github.com/opentofu/svchost"
	"github.com/opentofu/svchost/svcauth"
)

const (
	// Fixed path to the discovery manifest. This is an IANA-registered name
	// established by OpenTofu's predecessor, which OpenTofu uses so that
	// vendors can support both products simultaneously.
	discoPath = "/.well-known/terraform.json"

	// Arbitrary-but-small number to prevent runaway redirect loops. This
	// is used only when the caller doesn't provide their own HTTP client.
	maxRedirects = 3

	// Arbitrary-but-small time limit to prevent UI "hangs" during discovery.
	// This is used only when the caller doesn't provide their own HTTP client.
	discoTimeout = 11 * time.Second

	// 1MB - to prevent abusive services from using loads of our memory.
	maxDiscoDocBytes = 1 * 1024 * 1024
)

// Disco is the main type in this package, which allows discovery on given
// hostnames and caches the results by hostname to avoid repeated requests
// for the same information.
type Disco struct {
	// must lock "mu" while interacting with these maps
	aliases   map[svchost.Hostname]svchost.Hostname
	hostCache map[svchost.Hostname]*Host
	mu        sync.Mutex

	credsSrc svcauth.CredentialsSource

	httpClient *http.Client
}

// ErrServiceDiscoveryNetworkRequest represents the error that occurs when
// the service discovery fails for an unknown network problem.
type ErrServiceDiscoveryNetworkRequest struct {
	err error
}

func (e ErrServiceDiscoveryNetworkRequest) Error() string {
	wrappedError := fmt.Errorf("failed to request discovery document: %w", e.err)
	return wrappedError.Error()
}

// Unwrap returns another [error] value representing the underlying problem.
//
// This is intended for use with the standard library errors package, and its
// "Is", "As", and "Unwrap" functions.
func (e ErrServiceDiscoveryNetworkRequest) Unwrap() error {
	return e.err
}

// New returns a new initialized discovery object initialized with the
// given options.
//
// Use [WithHTTPClient] to specify an HTTP client to use when making discovery
// requests. If no client is provided then one will be created automatically,
// but the details of its behavior are subject to change in future versions.
//
// Use [WithCredentials] to specify an [svcauth.CredentialsSource] that can
// provide credentials to use when performing service discovery. If none is
// provided then all requests are made anonymously.
func New(options ...DiscoOption) *Disco {
	ret := &Disco{
		aliases:   make(map[svchost.Hostname]svchost.Hostname),
		hostCache: make(map[svchost.Hostname]*Host),
	}
	for _, opt := range options {
		opt.applyOption(ret)
	}

	if ret.httpClient == nil {
		ret.httpClient = &http.Client{
			Timeout: discoTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > maxRedirects {
					return errors.New("too many redirects") // this error will never actually be seen
				}
				return nil
			},
		}
	}

	return ret
}

// SetCredentialsSource changes the credentials source that will be used to
// add credentials to outgoing discovery requests, where available.
func (d *Disco) SetCredentialsSource(src svcauth.CredentialsSource) {
	d.credsSrc = src
}

// CredentialsSource returns the credentials source associated with the receiver,
// or an empty credentials source if none is associated.
func (d *Disco) CredentialsSource() svcauth.CredentialsSource {
	if d.credsSrc == nil {
		// We'll return an empty one just to save the caller from having to
		// protect against the nil case, since this interface already allows
		// for the possibility of there being no credentials at all.
		return svcauth.NoCredentials
	}
	return d.credsSrc
}

// CredentialsForHost returns a non-nil HostCredentials if the embedded source has
// credentials available for the host, or host alias, and a nil HostCredentials if it does not.
func (d *Disco) CredentialsForHost(ctx context.Context, hostname svchost.Hostname) (svcauth.HostCredentials, error) {
	if d.credsSrc == nil {
		return nil, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if aliasedHost, aliasExists := d.aliases[hostname]; aliasExists {
		hostname = aliasedHost
	}
	return d.credsSrc.ForHost(ctx, hostname)
}

// ForceHostServices provides a pre-defined set of services for a given
// host, which prevents the receiver from attempting network-based discovery
// for the given host. Instead, the given services map will be returned
// verbatim.
//
// When providing "forced" services, any relative URLs are resolved against
// the initial discovery URL that would have been used for network-based
// discovery, yielding the same results as if the given map were published
// at the host's default discovery URL, though using absolute URLs is strongly
// recommended to make the configured behavior more explicit.
func (d *Disco) ForceHostServices(hostname svchost.Hostname, services map[string]any) {
	if services == nil {
		services = map[string]any{}
	}

	d.mu.Lock()
	d.hostCache[hostname] = &Host{
		discoURL: &url.URL{
			Scheme: "https",
			Host:   string(hostname),
			Path:   discoPath,
		},
		hostname: hostname.ForDisplay(),
		services: services,
	}
	d.mu.Unlock()
}

// Alias accepts an alias and target Hostname. When service discovery is performed
// or credentials are requested for the alias hostname, the target will be consulted instead.
func (d *Disco) Alias(alias, target svchost.Hostname) {
	d.mu.Lock()
	d.aliases[alias] = target
	d.mu.Unlock()
}

// Discover runs the discovery protocol against the given hostname (which must
// already have been validated and prepared with svchost.ForComparison) and
// returns an object describing the services available at that host.
//
// If a given hostname supports no OpenTofu services at all, a non-nil but
// empty Host object is returned. When giving feedback to the end user about
// such situations, we say "host <name> does not provide a <service> service",
// regardless of whether that is due to that service specifically being absent
// or due to the host not providing OpenTofu services at all, since we don't
// wish to expose the detail of whole-host discovery to an end-user.
func (d *Disco) Discover(ctx context.Context, hostname svchost.Hostname) (*Host, error) {
	// In this method we use d.mu locking only to avoid corrupting d.hostCache
	// by concurrent writes, and not to prevent concurrent discovery requests.
	// If two clients concurrently request the same hostname then we could
	// potentially send two concurrent discovery requests over the network,
	// in which case it's unspecified which one will "win" and end up being
	// stored in the cache for future requests. In practice this shouldn't
	// matter because we're already assuming (by caching the results at all)
	// that a host will generally not vary its results in meaningful ways
	// between requests made in close time proximity.
	d.mu.Lock()
	if host, cached := d.hostCache[hostname]; cached {
		d.mu.Unlock()
		return host, nil
	}
	d.mu.Unlock()

	host, err := d.discover(ctx, hostname)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.hostCache[hostname] = host
	d.mu.Unlock()

	return host, nil
}

// DiscoverServiceURL is a convenience wrapper for discovery on a given
// hostname and then looking up a particular service in the result.
func (d *Disco) DiscoverServiceURL(ctx context.Context, hostname svchost.Hostname, serviceID string) (*url.URL, error) {
	host, err := d.Discover(ctx, hostname)
	if err != nil {
		return nil, err
	}
	return host.ServiceURL(serviceID)
}

// discover implements the actual discovery process, with its result cached
// by the public-facing Discover method.
//
// This must be called _without_ d.mu locked. d.mu is there only to protect
// the integrity of our internal maps, and not to prevent multiple concurrent
// service discovery lookups even for the same hostname.
func (d *Disco) discover(ctx context.Context, hostname svchost.Hostname) (*Host, error) {
	d.mu.Lock()
	if aliasedHost, aliasExists := d.aliases[hostname]; aliasExists {
		hostname = aliasedHost
	}
	d.mu.Unlock()

	discoURL := &url.URL{
		Scheme: "https",
		Host:   hostname.String(),
		Path:   discoPath,
	}

	client := d.httpClient
	req, err := http.NewRequestWithContext(ctx, "GET", discoURL.String(), nil)
	if err != nil {
		// Should not get in here because everything about the request args is under our control.
		return nil, fmt.Errorf("invalid discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	creds, err := d.CredentialsForHost(ctx, hostname)
	if err != nil {
		// If we fail to obtain credentials then we just treat it as anonymous
		creds = nil
	}
	if creds != nil {
		// Update the request to include credentials.
		creds.PrepareRequest(req)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrServiceDiscoveryNetworkRequest{err}
	}
	defer resp.Body.Close()

	host := &Host{
		// Use the discovery URL from resp.Request in
		// case the client followed any redirects.
		discoURL: resp.Request.URL,
		hostname: hostname.ForDisplay(),
	}

	// Return the host without any services.
	if resp.StatusCode == 404 {
		return host, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to request discovery document: %s", resp.Status)
	}

	contentType := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("discovery URL has a malformed Content-Type %q", contentType)
	}
	if mediaType != "application/json" {
		return nil, fmt.Errorf("discovery URL returned an unsupported Content-Type %q", mediaType)
	}

	// This doesn't catch chunked encoding, because ContentLength is -1 in that case.
	if resp.ContentLength > maxDiscoDocBytes {
		// Size limit here is not a contractual requirement and so we may
		// adjust it over time if we find a different limit is warranted.
		return nil, fmt.Errorf(
			"discovery doc response is too large (got %d bytes; limit %d)",
			resp.ContentLength, maxDiscoDocBytes,
		)
	}

	// If the response is using chunked encoding then we can't predict its
	// size, but we'll at least prevent reading the entire thing into memory.
	lr := io.LimitReader(resp.Body, maxDiscoDocBytes)

	servicesBytes, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("error reading discovery document body: %v", err)
	}

	var services map[string]any
	err = json.Unmarshal(servicesBytes, &services)
	if err != nil {
		return nil, fmt.Errorf("failed to decode discovery document as a JSON object: %v", err)
	}
	host.services = services

	return host, nil
}

// Forget invalidates any cached record of the given hostname. If the host
// has no cache entry then this is a no-op.
func (d *Disco) Forget(hostname svchost.Hostname) {
	d.mu.Lock()
	d.forgetInternal(hostname)
	d.mu.Unlock()
}

// forgetInternal is the main implementation of Forget that assumes the
// caller has already locked d.mu, so this can also be used in other
// places like ForgetAlias.
func (d *Disco) forgetInternal(hostname svchost.Hostname) {
	delete(d.hostCache, hostname)
}

// ForgetAll is like Forget, but for all of the hostnames that have cache entries.
func (d *Disco) ForgetAll() {
	d.mu.Lock()
	d.hostCache = make(map[svchost.Hostname]*Host)
	d.mu.Unlock()
}

// ForgetAlias removes a previously aliased hostname as well as its cached entry, if any exist.
// If the alias has no target then this is a no-op.
func (d *Disco) ForgetAlias(alias svchost.Hostname) {
	d.mu.Lock()
	delete(d.aliases, alias)
	d.forgetInternal(alias)
	d.mu.Unlock()
}
