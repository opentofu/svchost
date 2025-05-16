// Copyright (c) The OpenTofu Authors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package svcauth

import (
	"context"
	"fmt"
	"sync"

	svchost "github.com/opentofu/svchost"
)

// CachingCredentialsSource creates a new credentials source that wraps another
// and caches its results in memory, on a per-hostname basis.
//
// No means is provided for expiration of cached credentials, so a caching
// credentials source should have a limited lifetime (one OpenTofu operation,
// for example) to ensure that time-limited credentials don't expire before
// their cache entries do.
//
// The result also implements [CredentialsStore] by forwarding to the inner
// source, but the store and forget methods will fail with an error if the
// wrapped source does not also implement that interface.
func CachingCredentialsSource(source CredentialsSource) CredentialsSource {
	return &cachingCredentialsSource{
		source: source,
		cache:  map[svchost.Hostname]HostCredentials{},
	}
}

// CachingCredentialsStore is really just an alias for
// [CachingCredentialsSource] that provides a statically-checkable guarantee
// that the inner object being wrapped is a [CredentialsStore] rather than
// just a [CredentialsSource], and so the store-specific methods will
// delegate to the given store instead of immediately returning an error.
//
// This is functionally equivalent to calling [CachingCredentialsSource]
// with the same argument and then type-asserting the result to
// [CredentialsStore], but this helper ensures that the "store-ness" of
// the implementation is checked at compile time rather than at runtime.
func CachingCredentialsStore(store CredentialsStore) CredentialsStore {
	// The following always succeeds because cachingCredentialsSource
	// statically implements both CredentialsSource and CredentialsStore,
	// and just has its CredentialsStore methods fail dynamically when
	// the inner source isn't a store.
	return CachingCredentialsSource(store).(CredentialsStore)
}

type cachingCredentialsSource struct {
	source CredentialsSource
	cache  map[svchost.Hostname]HostCredentials
	mu     sync.Mutex
}

// ForHost passes the given hostname on to the wrapped credentials source and
// caches the result to return for future requests with the same hostname.
//
// Both credentials and non-credentials (nil) responses are cached.
//
// No cache entry is created if the wrapped source returns an error, to allow
// the caller to retry the failing operation.
func (s *cachingCredentialsSource) ForHost(ctx context.Context, host svchost.Hostname) (HostCredentials, error) {
	s.mu.Lock()
	if cache, cached := s.cache[host]; cached {
		s.mu.Unlock()
		return cache, nil
	}
	s.mu.Unlock()

	result, err := s.source.ForHost(ctx, host)
	if err != nil {
		return result, err
	}

	s.mu.Lock()
	s.cache[host] = result
	s.mu.Unlock()
	return result, nil
}

func (s *cachingCredentialsSource) StoreForHost(ctx context.Context, host svchost.Hostname, credentials NewHostCredentials) error {
	// We'll delete the cache entry even if the store fails, since that just
	// means that the next read will go to the real store and get a chance to
	// see which object (old or new) is actually present.
	s.mu.Lock()
	delete(s.cache, host)
	s.mu.Unlock()

	store, ok := s.source.(CredentialsStore)
	if !ok {
		return fmt.Errorf("no credentials store is available")
	}
	return store.StoreForHost(ctx, host, credentials)
}

func (s *cachingCredentialsSource) ForgetForHost(ctx context.Context, host svchost.Hostname) error {
	// We'll delete the cache entry even if the store fails, since that just
	// means that the next read will go to the real store and get a chance to
	// see if the object is still present.
	s.mu.Lock()
	delete(s.cache, host)
	s.mu.Unlock()

	store, ok := s.source.(CredentialsStore)
	if !ok {
		return fmt.Errorf("no credentials store is available")
	}
	return store.ForgetForHost(ctx, host)
}
