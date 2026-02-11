package env

import "time"

var (
	// MaxInternalTokenLifetime is the maximum lifetime for internal tokens
	// issued to sensors via the internal token API.
	MaxInternalTokenLifetime = registerDurationSetting(
		"ROX_MAX_INTERNAL_TOKEN_LIFETIME", 1*time.Hour)

	// InternalTokenAllowedPermissions defines the allowlist of permissions
	// that sensors may request via the internal token API. The format is
	// "Resource1:ACCESS_LEVEL,Resource2:ACCESS_LEVEL".
	InternalTokenAllowedPermissions = RegisterSetting(
		"ROX_INTERNAL_TOKEN_ALLOWED_PERMISSIONS",
		WithDefault("Deployment:READ_ACCESS,Image:READ_ACCESS"))
)
