package main

import (
	"errors"
	"flag"
	"github.com/kxddry/sso-auth/internal/config"
	"github.com/kxddry/sso-auth/internal/lib/pqlinks"
	"log"
	// migration
	"github.com/golang-migrate/migrate/v4"

	// drivers
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// USAGE:
// --config=/path/to/config.yaml
// inside config.yaml:
// Storage: host, port, user, password, dbname, sslmode
// Migrations: path
func main() {
	var op string
	flag.StringVar(&op, "operation", "", "operation: up or down")

	cfg := config.MustLoadMigration()
	pSt := cfg.Storage
	pSt.DBName = "postgres"
	dsn := pqlinks.DataSourceName(pSt)
	link := pqlinks.Link(cfg.Storage)
	err := pqlinks.EnsureDBexists(cfg.Storage.DBName, dsn)
	if err != nil {
		panic(err)
	}

	m, err := migrate.New("file://"+cfg.Migrations.Path, link)
	if err != nil {
		panic(err)
	}
	switch {
	case op == "" || op == "up":
		if err = m.Up(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				log.Println("Nothing to migrate")
				return
			}
			panic(err)
		}
	case op == "down":
		if err = m.Force(1); err != nil {
			panic(err)
		}
		if err = m.Down(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				log.Println("Nothing to migrate")
				return
			}
			panic(err)
		}
	default:
		log.Fatalln("Unknown operation:", op)
	}

	log.Println("migration successful")
}
