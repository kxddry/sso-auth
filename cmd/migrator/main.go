package main

import (
	"database/sql"
	"errors"
	"flag"
	"log"
	"os"
	"sso-auth/internal/config"
	"sso-auth/internal/lib/pqlinks"
	"strings"

	// migration
	"github.com/golang-migrate/migrate/v4"
	// read config
	"github.com/ilyakaznacheev/cleanenv"

	// drivers
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

type MigrationConfig struct {
	Storage    config.Storage `yaml:"storage" env-required:"true"`
	Migrations Migrations     `yaml:"migrations" env-required:"true"`
}

type Migrations struct {
	Path string `yaml:"path" env-required:"true"`
}

// USAGE:
// --config=/path/to/config.yaml
// inside config.yaml:
// Storage: host, port, user, password, dbname, sslmode
// Migrations: path
func main() {
	cfg := MustLoad()
	fromLink := pqlinks.Link(cfg.Storage)
	pSt := cfg.Storage
	pSt.DBName = "postgres"
	dsn := pqlinks.DataSourceName(pSt)
	err := ensureDBexists(cfg.Storage.DBName, dsn)
	if err != nil {
		panic(err)
	}

	var op string
	flag.StringVar(&op, "operation", "", "operation: up or down")
	flag.Parse()

	m, err := migrate.New("file://"+cfg.Migrations.Path, fromLink)
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

func ensureDBexists(dbname, dsn string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	_, err = db.Exec("CREATE DATABASE" + " " + dbname)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// fetches config path from flag --config
func fetchConfigPath() string {
	var res string
	flag.StringVar(&res, "config", "", "path to config file")
	flag.Parse()
	return res
}

func MustLoad() *MigrationConfig {
	path := fetchConfigPath()
	if path == "" {
		log.Fatal("config path is empty")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Fatalln("config file doesn't exist:", path)
	}
	var cfg MigrationConfig
	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		log.Fatalln("error loading config:", err)
	}
	return &cfg
}
