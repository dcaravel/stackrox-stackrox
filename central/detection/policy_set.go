package detection

import (
	clusterDataStore "github.com/stackrox/rox/central/cluster/datastore"
	namespaceDataStore "github.com/stackrox/rox/central/namespace/datastore"
	policyDatastore "github.com/stackrox/rox/central/policy/datastore"
	"github.com/stackrox/rox/pkg/detection"
	"github.com/stackrox/rox/pkg/scopecomp"
)

// PolicySet is a set of policies.
type PolicySet interface {
	detection.PolicySet

	RemoveNotifier(notifierID string) error
}

// NewPolicySet returns a new instance of a PolicySet.
func NewPolicySet(store policyDatastore.DataStore, clusterDS clusterDataStore.DataStore, namespaceDS namespaceDataStore.DataStore) PolicySet {
	var clusterProvider scopecomp.ClusterLabelProvider
	var namespaceProvider scopecomp.NamespaceLabelProvider

	if clusterDS != nil {
		clusterProvider = NewClusterLabelProvider(clusterDS)
	}
	if namespaceDS != nil {
		namespaceProvider = NewNamespaceLabelProvider(namespaceDS)
	}

	return &setImpl{
		PolicySet:   detection.NewPolicySet(clusterProvider, namespaceProvider),
		policyStore: store,
	}
}
