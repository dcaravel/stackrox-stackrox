package detection

import (
	"context"

	clusterDataStore "github.com/stackrox/rox/central/cluster/datastore"
	namespaceDataStore "github.com/stackrox/rox/central/namespace/datastore"
	"github.com/stackrox/rox/pkg/scopecomp"
)

type clusterLabelDatastoreProvider struct {
	datastore clusterDataStore.DataStore
}

// NewClusterLabelProvider creates a provider that fetches cluster labels from the datastore.
func NewClusterLabelProvider(ds clusterDataStore.DataStore) scopecomp.ClusterLabelProvider {
	return &clusterLabelDatastoreProvider{datastore: ds}
}

func (p *clusterLabelDatastoreProvider) GetClusterLabels(clusterID string) (map[string]string, error) {
	ctx := context.TODO()
	cluster, exists, err := p.datastore.GetCluster(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return cluster.GetLabels(), nil
}

type namespaceLabelDatastoreProvider struct {
	datastore namespaceDataStore.DataStore
}

// NewNamespaceLabelProvider creates a provider that fetches namespace labels from the datastore.
func NewNamespaceLabelProvider(ds namespaceDataStore.DataStore) scopecomp.NamespaceLabelProvider {
	return &namespaceLabelDatastoreProvider{datastore: ds}
}

func (p *namespaceLabelDatastoreProvider) GetNamespaceLabels(namespaceID string) (map[string]string, error) {
	ctx := context.TODO()
	namespace, exists, err := p.datastore.GetNamespace(ctx, namespaceID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return namespace.GetLabels(), nil
}
