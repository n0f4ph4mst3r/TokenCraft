package config

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	Env         string        `yaml:"env" env-default:"local"`
	DatabaseURL string        `yaml:"db_url" env-required:"true" env:"DATABASE_URL"`
	Cache       CacheConfig   `yaml:"cache_config"`
	JwtTTL      time.Duration `yaml:"access_token_ttl" env-default:"1h" env:"JWT_TTL"`
	TokenTTL    time.Duration `yaml:"refresh_token_ttl" env-default:"168h" env:"APP_TOKEN_TTL"`
	Secret      string        `yaml:"app_secret" env:"APP_SECRET"`
	GRPC        gRPCServer    `yaml:"grpc"`
}

type gRPCServer struct {
	Address string        `yaml:"address" env-default:"localhost" env:"HTTP_SERVER_ADDRESS"`
	Port    int           `yaml:"port" env-default:"8080" env:"HTTP_SERVER_PORT"`
	Timeout time.Duration `yaml:"timeout" env-default:"4s"`
}

type CacheConfig struct {
	Url string        `yaml:"cache_url" env:"CACHE_URL"`
	TTL time.Duration `yaml:"ttl" env-default:"30m"`

	Prefix  string `yaml:"prefix" env-default:"tc"`
	Version string `yaml:"version" env-default:"v1"`
}

func MustLoad() *Config {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found, using system environment")
	}

	var configPath string

	flag.StringVar(&configPath, "config", "", "path to config file")
	flag.Parse()

	if configPath == "" {
		configPath = os.Getenv("CONFIG_PATH")
		if configPath == "" {
			panic("config path is empty")
		} else {
			log.Println("Using config file:", configPath)
		}
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("config file does not exist: " + configPath)
	}

	var cfg Config
	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("cannot read config: " + err.Error())
	}

	return &cfg
}
