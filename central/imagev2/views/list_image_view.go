package views

import (
	"time"

	"github.com/stackrox/rox/generated/storage"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ListImageV2View holds the fields needed for ListImage responses, using view-based
// column selection instead of full protobuf deserialization.
type ListImageV2View struct {
	Digest          string     `db:"image_sha"`
	Name            string     `db:"image"`
	ComponentCount  int32      `db:"component_count"`
	CVECount        int32      `db:"image_cve_count"`
	FixableCVECount int32      `db:"fixable_cve_count"`
	Created         *time.Time `db:"image_created_time"`
	LastUpdated     *time.Time `db:"last_updated"`
}

// ToListImage converts a ListImageV2View to a storage.ListImage proto.
func (v *ListImageV2View) ToListImage() *storage.ListImage {
	img := &storage.ListImage{
		Id:   v.Digest,
		Name: v.Name,
		SetComponents: &storage.ListImage_Components{
			Components: v.ComponentCount,
		},
		SetCves: &storage.ListImage_Cves{
			Cves: v.CVECount,
		},
		SetFixable: &storage.ListImage_FixableCves{
			FixableCves: v.FixableCVECount,
		},
	}
	if v.Created != nil {
		img.Created = timestamppb.New(*v.Created)
	}
	if v.LastUpdated != nil {
		img.LastUpdated = timestamppb.New(*v.LastUpdated)
	}
	return img
}
