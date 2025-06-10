# OpenTofu `svchost`

This library contains a client implementation of
[OpenTofu's Remote Service Discovery protocol](https://opentofu.org/docs/internals/remote-service-discovery/),
and helpers for authenticating to OpenTofu-native services.

The API of this library is currently experimental and primarily intended for
use in OpenTofu CLI itself, rather than external consumption. We may make
breaking changes to the API before blessing it with a stable version number,
so third-party callers should be prepared to make adjustments if they choose
to use this library before then.
