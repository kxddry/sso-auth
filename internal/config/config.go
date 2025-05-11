package config

import (
	"flag"
	"github.com/ilyakaznacheev/cleanenv"
	"os"
	"time"
)

type Config struct {
	Env      string        `yaml:"env" env-required:"true"`
	Storage  Storage       `yaml:"postgres" env-required:"true"`
	TokenTTL time.Duration `yaml:"token_ttl" env:"TOKEN_TTL" env-required:"true" env-default:"1h"`
	GRPC     GRPCServer    `yaml:"grpc" env-required:"true"`
}
type Storage struct {
	Host     string `yaml:"host" env-required:"true"`
	Port     int    `yaml:"port" env-required:"true"`
	User     string `yaml:"user" env-required:"true"`
	Password string `yaml:"password" env-required:"true"`
	DBName   string `yaml:"dbname" env-required:"true"`
	SSLMode  string `yaml:"sslmode" env-default:"enable"`
}

type MigrationConfig struct {
	Storage    Storage    `yaml:"storage" env-required:"true"`
	Migrations Migrations `yaml:"migrations" env-required:"true"`
}

type Migrations struct {
	Path string `yaml:"path" env-required:"true"`
}

type GRPCServer struct {
	Port    int           `yaml:"port" env-required:"true"`
	Timeout time.Duration `yaml:"timeout" env-default:"10s"`
}

func MustLoad() *Config {
	path := fetchConfigPath()
	if path == "" {
		panic("config path is empty")
	}
	return MustLoadByPath(path)
}

func MustLoadMigration() *MigrationConfig {
	path := fetchConfigPath()
	if path == "" {
		panic("config path is empty")
	}
	return MustLoadMigrationByPath(path)
}

func MustLoadMigrationByPath(path string) *MigrationConfig {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("config file doesn't exist " + path)
	}
	var res MigrationConfig
	if err := cleanenv.ReadConfig(path, &res); err != nil {
		panic(err)
	}
	return &res
}

func MustLoadByPath(path string) *Config {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("config file doesn't exist " + path)
	}
	var res Config
	if err := cleanenv.ReadConfig(path, &res); err != nil {
		panic(err)
	}
	return &res
}

// get config path from flag or env.
// prioritize flag over env over default
// default: empty string
func fetchConfigPath() string {
	var res string
	flag.StringVar(&res, "config", "", "path to config file")
	flag.Parse()
	if res != "" {
		return res
	}
	env := os.Getenv("CONFIG_PATH")
	return env
}
