package service

import (
	"fmt"
	"strings"
	"time"

	v1 "github.com/stackrox/rox/generated/internalapi/central/v1"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/errox"
)

type tokenPolicy struct {
	maxLifetime        time.Duration
	allowedPermissions map[string]v1.Access
}

// newTokenPolicy creates a tokenPolicy with the given maximum lifetime and
// allowed permissions.
func newTokenPolicy(maxLifetime time.Duration, allowedPermissions map[string]v1.Access) *tokenPolicy {
	return &tokenPolicy{
		maxLifetime:        maxLifetime,
		allowedPermissions: allowedPermissions,
	}
}

// newTokenPolicyFromEnv creates a tokenPolicy from the environment variables
// ROX_MAX_INTERNAL_TOKEN_LIFETIME and ROX_INTERNAL_TOKEN_ALLOWED_PERMISSIONS.
func newTokenPolicyFromEnv() (*tokenPolicy, error) {
	allowedPerms, err := parseAllowedPermissions(
		env.InternalTokenAllowedPermissions.Setting())
	if err != nil {
		return nil, err
	}
	return newTokenPolicy(
		env.MaxInternalTokenLifetime.DurationSetting(),
		allowedPerms,
	), nil
}

// parseAllowedPermissions parses a comma-separated string of
// "Resource:ACCESS_LEVEL" pairs into a permission map.
// Example input: "Deployment:READ_ACCESS,Image:READ_ACCESS"
func parseAllowedPermissions(s string) (map[string]v1.Access, error) {
	result := make(map[string]v1.Access)
	s = strings.TrimSpace(s)
	if s == "" {
		return result, nil
	}
	pairs := strings.Split(s, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid permission format %q: expected Resource:ACCESS_LEVEL", pair)
		}
		resource := strings.TrimSpace(parts[0])
		accessStr := strings.TrimSpace(parts[1])
		accessVal, ok := v1.Access_value[accessStr]
		if !ok {
			return nil, fmt.Errorf("unknown access level %q in permission %q", accessStr, pair)
		}
		result[resource] = v1.Access(accessVal)
	}
	return result, nil
}

// validatePermissions checks that every requested permission is present in the
// allowlist with an access level no greater than the allowed level.
func (p *tokenPolicy) validatePermissions(requested map[string]v1.Access) error {
	for resource, requestedAccess := range requested {
		allowedAccess, ok := p.allowedPermissions[resource]
		if !ok {
			return errox.InvalidArgs.Newf(
				"permission for resource %q is not allowed", resource)
		}
		if requestedAccess > allowedAccess {
			return errox.InvalidArgs.Newf(
				"requested access %s for resource %q exceeds allowed %s",
				requestedAccess, resource, allowedAccess)
		}
	}
	return nil
}

// enforceClusterScope checks that every ClusterScope in the request references
// only the requesting sensor's own cluster.
func (p *tokenPolicy) enforceClusterScope(scopes []*v1.ClusterScope, sensorClusterID string) error {
	for _, scope := range scopes {
		if scope.GetClusterId() != sensorClusterID {
			return errox.InvalidArgs.Newf(
				"cluster scope references cluster %q, but requesting sensor belongs to cluster %q",
				scope.GetClusterId(), sensorClusterID)
		}
	}
	return nil
}

// capLifetime returns the lesser of the requested duration and the configured
// maximum lifetime.
func (p *tokenPolicy) capLifetime(requested time.Duration) time.Duration {
	if requested > p.maxLifetime {
		return p.maxLifetime
	}
	return requested
}
