package detection

import (
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/scopecomp"
)

// CompilePolicy compiles the given policy, making it ready for matching.
// For policies that need label-based scope matching, use CompilePolicyWithProviders instead.
func CompilePolicy(policy *storage.Policy) (CompiledPolicy, error) {
	cloned := policy.CloneVT()
	return newCompiledPolicy(cloned, nil, nil)
}

// CompilePolicyWithProviders compiles the given policy with label providers, making it ready for matching.
// The providers enable cluster_label and namespace_label scope matching.
func CompilePolicyWithProviders(policy *storage.Policy, clusterLabelProvider scopecomp.ClusterLabelProvider, namespaceLabelProvider scopecomp.NamespaceLabelProvider) (CompiledPolicy, error) {
	cloned := policy.CloneVT()
	return newCompiledPolicy(cloned, clusterLabelProvider, namespaceLabelProvider)
}
