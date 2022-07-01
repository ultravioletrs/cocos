package postgres

import migrate "github.com/rubenv/sql-migrate"

var Migrations = &migrate.MemoryMigrationSource{
	Migrations: []*migrate.Migration{
		{
			Id: "datasets",
			Up: []string{
				`CREATE TABLE IF NOT EXISTS datasets (
						id       		UUID,
						name                    VARCHAR(1025),
						owner                   VARCHAR(255),
						description             text,
						created_at              TIMESTAMP,
						updated_at              TIMESTAMP,
						syze                	INT,
						type                	VARCHAR(255),
						location              	TEXT,
						format       		VARCHAR(255),
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
