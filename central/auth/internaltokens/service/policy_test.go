package service

import (
	"testing"
	"time"

	v1 "github.com/stackrox/rox/generated/internalapi/central/v1"
	"github.com/stackrox/rox/pkg/errox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAllowedPermissions(t *testing.T) {
	for name, tc := range map[string]struct {
		input       string
		expected    map[string]v1.Access
		expectError bool
	}{
		"empty string": {
			input:    "",
			expected: map[string]v1.Access{},
		},
		"whitespace only": {
			input:    "   ",
			expected: map[string]v1.Access{},
		},
		"single permission": {
			input: "Deployment:READ_ACCESS",
			expected: map[string]v1.Access{
				"Deployment": v1.Access_READ_ACCESS,
			},
		},
		"multiple permissions": {
			input: "Deployment:READ_ACCESS,Image:READ_ACCESS",
			expected: map[string]v1.Access{
				"Deployment": v1.Access_READ_ACCESS,
				"Image":      v1.Access_READ_ACCESS,
			},
		},
		"read-write permission": {
			input: "Deployment:READ_WRITE_ACCESS",
			expected: map[string]v1.Access{
				"Deployment": v1.Access_READ_WRITE_ACCESS,
			},
		},
		"no-access permission": {
			input: "Deployment:NO_ACCESS",
			expected: map[string]v1.Access{
				"Deployment": v1.Access_NO_ACCESS,
			},
		},
		"with whitespace": {
			input: " Deployment : READ_ACCESS , Image : READ_ACCESS ",
			expected: map[string]v1.Access{
				"Deployment": v1.Access_READ_ACCESS,
				"Image":      v1.Access_READ_ACCESS,
			},
		},
		"missing colon": {
			input:       "DeploymentREAD_ACCESS",
			expectError: true,
		},
		"unknown access level": {
			input:       "Deployment:SUPER_ACCESS",
			expectError: true,
		},
		"trailing comma ignored": {
			input: "Deployment:READ_ACCESS,",
			expected: map[string]v1.Access{
				"Deployment": v1.Access_READ_ACCESS,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := parseAllowedPermissions(tc.input)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestValidatePermissions(t *testing.T) {
	policy := newTokenPolicy(0, map[string]v1.Access{
		"Deployment": v1.Access_READ_ACCESS,
		"Image":      v1.Access_READ_ACCESS,
	})

	for name, tc := range map[string]struct {
		requested   map[string]v1.Access
		expectError bool
	}{
		"nil permissions": {
			requested: nil,
		},
		"empty permissions": {
			requested: map[string]v1.Access{},
		},
		"valid subset - single": {
			requested: map[string]v1.Access{
				"Deployment": v1.Access_READ_ACCESS,
			},
		},
		"valid subset - both": {
			requested: map[string]v1.Access{
				"Deployment": v1.Access_READ_ACCESS,
				"Image":      v1.Access_READ_ACCESS,
			},
		},
		"lower access than allowed": {
			requested: map[string]v1.Access{
				"Deployment": v1.Access_NO_ACCESS,
			},
		},
		"resource not in allowlist": {
			requested: map[string]v1.Access{
				"NetworkGraph": v1.Access_READ_ACCESS,
			},
			expectError: true,
		},
		"access exceeds allowlist": {
			requested: map[string]v1.Access{
				"Deployment": v1.Access_READ_WRITE_ACCESS,
			},
			expectError: true,
		},
		"mixed - one valid, one not allowed resource": {
			requested: map[string]v1.Access{
				"Deployment":   v1.Access_READ_ACCESS,
				"NetworkGraph": v1.Access_READ_ACCESS,
			},
			expectError: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := policy.validatePermissions(tc.requested)
			if tc.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, errox.InvalidArgs)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEnforceClusterScope(t *testing.T) {
	policy := newTokenPolicy(0, nil)

	for name, tc := range map[string]struct {
		scopes          []*v1.ClusterScope
		sensorClusterID string
		expectError     bool
	}{
		"nil scopes": {
			scopes:          nil,
			sensorClusterID: "cluster-A",
		},
		"empty scopes": {
			scopes:          []*v1.ClusterScope{},
			sensorClusterID: "cluster-A",
		},
		"matching cluster": {
			scopes: []*v1.ClusterScope{
				{ClusterId: "cluster-A"},
			},
			sensorClusterID: "cluster-A",
		},
		"multiple matching clusters": {
			scopes: []*v1.ClusterScope{
				{ClusterId: "cluster-A"},
				{ClusterId: "cluster-A", Namespaces: []string{"ns1"}},
			},
			sensorClusterID: "cluster-A",
		},
		"mismatched cluster": {
			scopes: []*v1.ClusterScope{
				{ClusterId: "cluster-B"},
			},
			sensorClusterID: "cluster-A",
			expectError:     true,
		},
		"one matching, one mismatched": {
			scopes: []*v1.ClusterScope{
				{ClusterId: "cluster-A"},
				{ClusterId: "cluster-B"},
			},
			sensorClusterID: "cluster-A",
			expectError:     true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := policy.enforceClusterScope(tc.scopes, tc.sensorClusterID)
			if tc.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, errox.InvalidArgs)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCapLifetime(t *testing.T) {
	policy := newTokenPolicy(1*time.Hour, nil)

	for name, tc := range map[string]struct {
		requested time.Duration
		expected  time.Duration
	}{
		"below max": {
			requested: 5 * time.Minute,
			expected:  5 * time.Minute,
		},
		"exactly max": {
			requested: 1 * time.Hour,
			expected:  1 * time.Hour,
		},
		"above max": {
			requested: 2 * time.Hour,
			expected:  1 * time.Hour,
		},
	} {
		t.Run(name, func(t *testing.T) {
			result := policy.capLifetime(tc.requested)
			assert.Equal(t, tc.expected, result)
		})
	}
}
