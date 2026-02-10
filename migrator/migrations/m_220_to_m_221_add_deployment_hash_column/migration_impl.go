package m220tom221

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	"github.com/stackrox/rox/migrator/migrations/m_220_to_m_221_add_deployment_hash_column/schema"
	"github.com/stackrox/rox/migrator/types"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"github.com/stackrox/rox/pkg/sac"
)

var (
	log       = loghelper.LogWrapper{}
	batchSize = 500
)

func migrate(database *types.Databases) error {
	ctx := sac.WithAllAccess(context.Background())

	// Use GORM to add the hash column to the deployments table
	pgutils.CreateTableFromModel(ctx, database.GormDB, schema.CreateTableDeploymentsStmt)

	if err := backfillHash(ctx, database.PostgresDB, schema.DeploymentsTableName); err != nil {
		log.WriteToStderrf("unable to backfill hash: %v", err)
		return err
	}

	return nil
}

type commandResult interface {
	RowsAffected() int64
}

func backfillHash(ctx context.Context, db postgres.DB, table string) error {
	ctx, cancel := context.WithTimeout(ctx, types.DefaultMigrationTimeout)
	defer cancel()

	totalBackfilled := 0
	var result commandResult

	for result == nil || int(result.RowsAffected()) == batchSize {
		rows, err := db.Query(ctx, "SELECT id, serialized FROM "+table+" WHERE hash IS NULL OR hash = 0 LIMIT $1", batchSize)
		if err != nil {
			return errors.Wrap(err, "querying deployments for backfill")
		}

		var deploymentsToUpdate []struct {
			id   string
			hash uint64
		}

		for rows.Next() {
			var id string
			var serialized []byte
			if err := rows.Scan(&id, &serialized); err != nil {
				rows.Close()
				return errors.Wrap(err, "scanning deployment row")
			}

			deployment := &storage.Deployment{}
			if err := deployment.UnmarshalVT(serialized); err != nil {
				rows.Close()
				return errors.Wrapf(err, "deserializing deployment %s", id)
			}

			deploymentsToUpdate = append(deploymentsToUpdate, struct {
				id   string
				hash uint64
			}{
				id:   id,
				hash: deployment.GetHash(),
			})
		}
		rows.Close()

		if len(deploymentsToUpdate) == 0 {
			break
		}

		// Update deployments with their hash values
		for _, dep := range deploymentsToUpdate {
			result, err = db.Exec(ctx, "UPDATE "+table+" SET hash = $1 WHERE id = $2", dep.hash, dep.id)
			if err != nil {
				return errors.Wrapf(err, "updating hash for deployment %s", dep.id)
			}
		}

		totalBackfilled += len(deploymentsToUpdate)
		log.WriteToStderrf("Backfilled hash for %d deployments (total: %d)", len(deploymentsToUpdate), totalBackfilled)
	}

	log.WriteToStderrf("Successfully backfilled hash for %d total deployments", totalBackfilled)
	return nil
}
