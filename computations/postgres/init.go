package postgres

import migrate "github.com/rubenv/sql-migrate"

var Migrations = &migrate.MemoryMigrationSource{
	Migrations: []*migrate.Migration{
		{
			Id: "computations_1",
			Up: []string{
				`CREATE TABLE IF NOT EXISTS computations (
                    id       				UUID,
                    owner                   VARCHAR(255),
                    name                    VARCHAR(1025),
                    description             text,
                    status                  VARCHAR(255),
                    start_time              timestamp NOT NULL,
                    end_time                timestamp,
                    datasets                text[],
                    algorithms              text[],
                    dataset_providers       text[],
                    algorithm_providers     text[],
                    ttl                     integer,
                    metadata                JSON,
                    PRIMARY KEY (id, owner)
                    )`,
			},
			Down: []string{
				"DROP TABLE computations",
			},
		},
	},
}
