package postgres

import migrate "github.com/rubenv/sql-migrate"

var Migrations = &migrate.MemoryMigrationSource{
	Migrations: []*migrate.Migration{
		{
			Id: "computations_1",
			Up: []string{
				`CREATE TABLE IF NOT EXISTS computations (
                        id       				UUID,
                        owner  					VARCHAR(255),
                        name  				  	VARCHAR(1025),
                        description 		    VARCHAR(1025),
                        status     				VARCHAR(1025),
                        start_time 				timestamp NOT NULL,
                        end_time 				timestamp NOT NULL,
                        datasets 				VARCHAR(1025),
                        algorithms 				VARCHAR(1025),
                        dataset_providers 		VARCHAR(1025),
                        algorithm_providers 	VARCHAR(1025),
                        ttl 					integer,
                        metadata 				JSON,
                        PRIMARY KEY (id, owner)
                    )`,
			},
			Down: []string{
				"DROP TABLE computations",
			},
		},
	},
}
