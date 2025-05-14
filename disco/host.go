// Copyright (c) The OpenTofu Authors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package disco

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Host represents a service discovered host.
type Host struct {
	discoURL *url.URL
	hostname string
	services map[string]any
}

// ErrServiceNotProvided is returned when the service is not provided.
type ErrServiceNotProvided struct {
	hostname string
	service  string
}

// Error returns a customized error message.
func (e *ErrServiceNotProvided) Error() string {
	if e.hostname == "" {
		return fmt.Sprintf("host does not provide a %s service", e.service)
	}
	return fmt.Sprintf("host %s does not provide a %s service", e.hostname, e.service)
}

// ErrVersionNotSupported is returned when the version is not supported.
type ErrVersionNotSupported struct {
	hostname string
	service  string
	version  uint64
}

// Error returns a customized error message.
func (e *ErrVersionNotSupported) Error() string {
	if e.hostname == "" {
		return fmt.Sprintf("host does not support %s version %d", e.service, e.version)
	}
	return fmt.Sprintf("host %s does not support %s version %d", e.hostname, e.service, e.version)
}

// ServiceURL returns the URL associated with the given service identifier,
// which should be of the form "servicename.vN".
//
// A non-nil result is always an absolute URL with a scheme of either HTTPS
// or HTTP.
func (h *Host) ServiceURL(id string) (*url.URL, error) {
	svcName, version, err := parseServiceID(id)
	if err != nil {
		return nil, err
	}

	// No services supported for an empty Host.
	if h == nil || h.services == nil {
		return nil, &ErrServiceNotProvided{service: svcName}
	}

	urlStr, ok := h.services[id].(string)
	if !ok {
		// See if we have a matching service as that would indicate
		// the service is supported, but not the requested version.
		for serviceID := range h.services {
			if strings.HasPrefix(serviceID, svcName+".") {
				return nil, &ErrVersionNotSupported{
					hostname: h.hostname,
					service:  svcName,
					version:  version,
				}
			}
		}

		// No discovered services match the requested service.
		return nil, &ErrServiceNotProvided{hostname: h.hostname, service: svcName}
	}

	u, err := h.parseURL(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service URL: %v", err)
	}

	return u, nil
}

// ServiceOAuthClient returns the OAuth client configuration associated with the
// given service identifier, which should be of the form "servicename.vN".
//
// This is an alternative to ServiceURL for unusual services that require
// a full OAuth2 client definition rather than just a URL. Use this only
// for services whose specification calls for this sort of definition.
func (h *Host) ServiceOAuthClient(id string) (*OAuthClient, error) {
	serviceName, version, err := parseServiceID(id)
	if err != nil {
		return nil, err
	}

	// No services supported for an empty Host.
	if h == nil || h.services == nil {
		return nil, &ErrServiceNotProvided{service: serviceName}
	}

	if _, ok := h.services[id]; !ok {
		// See if we have a matching service as that would indicate
		// the service is supported, but not the requested version.
		for serviceID := range h.services {
			if strings.HasPrefix(serviceID, serviceName+".") {
				return nil, &ErrVersionNotSupported{
					hostname: h.hostname,
					service:  serviceName,
					version:  version,
				}
			}
		}

		// No discovered services match the requested service.
		return nil, &ErrServiceNotProvided{hostname: h.hostname, service: serviceName}
	}

	var raw map[string]any
	switch v := h.services[id].(type) {
	case map[string]any:
		raw = v // Great!
	case []map[string]any:
		// An absolutely infuriating legacy HCL ambiguity.
		raw = v[0]
	default:
		return nil, fmt.Errorf("service %s must be declared with an object value in the service discovery document", id)
	}

	var grantTypes OAuthGrantTypeSet
	//nolint:nestif
	if rawGTs, ok := raw["grant_types"]; ok {
		if gts, ok := rawGTs.([]any); ok {
			var kws []string
			for _, gtI := range gts {
				gt, ok := gtI.(string)
				if !ok {
					// We'll ignore this so that we can potentially introduce
					// other types into this array later if we need to.
					continue
				}
				kws = append(kws, gt)
			}
			grantTypes = NewOAuthGrantTypeSet(kws...)
		} else {
			return nil, fmt.Errorf("service %s is defined with invalid grant_types property: must be an array of grant type strings", id)
		}
	} else {
		grantTypes = NewOAuthGrantTypeSet("authz_code")
	}

	ret := &OAuthClient{
		SupportedGrantTypes: grantTypes,
	}
	if clientIDStr, ok := raw["client"].(string); ok {
		ret.ID = clientIDStr
	} else {
		return nil, fmt.Errorf("service %s definition is missing required property \"client\"", id)
	}
	if urlStr, ok := raw["authz"].(string); ok {
		u, err := h.parseURL(urlStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse authorization URL: %v", err)
		}
		ret.AuthorizationURL = u
	} else if grantTypes.RequiresAuthorizationEndpoint() {
		return nil, fmt.Errorf("service %s definition is missing required property \"authz\"", id)
	}
	if urlStr, ok := raw["token"].(string); ok {
		u, err := h.parseURL(urlStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse token URL: %v", err)
		}
		ret.TokenURL = u
	} else if grantTypes.RequiresTokenEndpoint() {
		return nil, fmt.Errorf("service %s definition is missing required property \"token\"", id)
	}
	//nolint:nestif
	if portsRaw, ok := raw["ports"].([]any); ok {
		if len(portsRaw) != 2 {
			return nil, fmt.Errorf("invalid \"ports\" definition for service %s: must be a two-element array", id)
		}
		invalidPortsErr := fmt.Errorf("invalid \"ports\" definition for service %s: both ports must be whole numbers between 1024 and 65535", id)
		ports := make([]uint16, 2)
		for i := range ports {
			switch v := portsRaw[i].(type) {
			case float64:
				// JSON unmarshaling always produces float64. HCL 2 might, if
				// an invalid fractional number were given.
				if float64(uint16(v)) != v || v < 1024 {
					return nil, invalidPortsErr
				}
				ports[i] = uint16(v)
			case int:
				// Legacy HCL produces int. HCL 2 will too, if the given number
				// is a whole number.
				if v < 1024 || v > 65535 {
					return nil, invalidPortsErr
				}
				ports[i] = uint16(v)
			default:
				return nil, invalidPortsErr
			}
		}
		if ports[1] < ports[0] {
			return nil, fmt.Errorf("invalid \"ports\" definition for service %s: minimum port cannot be greater than maximum port", id)
		}
		ret.MinPort = ports[0]
		ret.MaxPort = ports[1]
	} else {
		// Default is to accept any port in the range, for a client that is
		// able to call back to any localhost port.
		ret.MinPort = 1024
		ret.MaxPort = 65535
	}
	if scopesRaw, ok := raw["scopes"].([]any); ok {
		var scopes []string
		for _, scopeI := range scopesRaw {
			scope, ok := scopeI.(string)
			if !ok {
				return nil, fmt.Errorf("invalid \"scopes\" for service %s: all scopes must be strings", id)
			}
			scopes = append(scopes, scope)
		}
		ret.Scopes = scopes
	}

	return ret, nil
}

func (h *Host) parseURL(urlStr string) (*url.URL, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	// Make relative URLs absolute using our discovery URL.
	if !u.IsAbs() {
		u = h.discoURL.ResolveReference(u)
	}

	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported scheme %s", u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("embedded username/password information is not permitted")
	}

	// Fragment part is irrelevant, since we're not a browser.
	u.Fragment = ""

	return u, nil
}

func parseServiceID(id string) (string, uint64, error) {
	parts := strings.SplitN(id, ".", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid service ID format (i.e. service.vN): %s", id)
	}

	if !strings.HasPrefix(parts[1], "v") {
		return "", 0, fmt.Errorf("invalid service version: must be \"v\" followed by an integer major version number")
	}
	parsedVersion, err := strconv.ParseUint(parts[1][1:], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("invalid service version: %v", err)
	}

	return parts[0], parsedVersion, nil
}
