package views

import "time"

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
