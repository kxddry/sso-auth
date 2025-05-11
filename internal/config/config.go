package config

import (
	"flag"
	"github.com/ilyakaznacheev/cleanenv"
	"log"
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
type GRPCServer struct {
	Port    int           `yaml:"port" env-required:"true"`
	Timeout time.Duration `yaml:"timeout" env-default:"10s"`
}

func MustLoad() *Config {
	path := fetchConfigPath()
	if path == "" {
		log.Fatal("config path is empty")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Fatalf("config file doesn't exist: %s", path)
	}
	var cfg Config
	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		log.Fatalf("failed to read config file: %s", err)
	}
	return &cfg
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
