// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0

// Package svcauth provides some supporting types for representing credentials
// used to authenticate to OpenTofu-native services.
//
// The API of this package is currently experimental and primarily intended for
// use in OpenTofu CLI itself, rather than external consumption. We may make
// breaking changes to the API before blessing this module with a stable version
// number, so third-party callers should be prepared to make adjustments if they
// choose to use this library before then.
package svcauth
