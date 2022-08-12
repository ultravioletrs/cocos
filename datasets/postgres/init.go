package postgres

import (
	// used to register Postgres driver
	_ "github.com/lib/pq"
	migrate "github.com/rubenv/sql-migrate"
)

var Migrations = &migrate.MemoryMigrationSource{
	Migrations: []*migrate.Migration{
		{
			Id: "datasets_01",
			Up: []string{
				`CREATE TABLE IF NOT EXISTS datasets (
                        id                      UUID,
                        name                    VARCHAR(1025),
                        owner                   VARCHAR(255),
                        description             TEXT,
                        created_at              TIMESTAMP,
                        updated_at              TIMESTAMP,
                        size                    INT,
                        location                TEXT,
                        format                  VARCHAR(255),
                        metadata                JSON,
                        PRIMARY KEY (id, owner)
                        )`,
			},
			Down: []string{
				"DROP TABLE datasets",
			},
		},
	},
}
