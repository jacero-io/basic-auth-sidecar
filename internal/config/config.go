package config

import (
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Auth struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"auth"`
	Server struct {
		GRPCPort int `yaml:"grpc_port"`
		HTTPPort int `yaml:"http_port"`
	} `yaml:"server"`
	Logging struct {
		Level string `yaml:"level"`
	} `yaml:"logging"`
	RateLimit struct {
		RequestsPerSecond float64       `yaml:"requests_per_second"`
		Burst             int           `yaml:"burst"`
		CleanupInterval   time.Duration `yaml:"cleanup_interval"`
		MaxInactivity     time.Duration `yaml:"max_inactivity"`
	} `yaml:"rate_limit"`
}

func Load(path string, logger *zap.Logger) (*Config, error) {
	cfg := &Config{}

	logger.Info("Loading configuration", zap.String("path", path))
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	err = yaml.Unmarshal(file, cfg)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	// Override with environment variables if set
	if username := os.Getenv("AUTH_USERNAME"); username != "" {
		cfg.Auth.Username = username
	}
	if password := os.Getenv("AUTH_PASSWORD"); password != "" {
		cfg.Auth.Password = password
	}

	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// Set defaults if not specified
	setDefaults(cfg)

	logger.Info("Configuration loaded successfully",
		zap.Int("grpcPort", cfg.Server.GRPCPort),
		zap.Int("httpPort", cfg.Server.HTTPPort),
		zap.Float64("requestsPerSecond", cfg.RateLimit.RequestsPerSecond),
		zap.Int("burst", cfg.RateLimit.Burst),
		zap.Duration("cleanupInterval", cfg.RateLimit.CleanupInterval),
		zap.Duration("maxInactivity", cfg.RateLimit.MaxInactivity))

	return cfg, nil
}

func validateConfig(cfg *Config) error {
	if cfg.Auth.Username == "" {
		return fmt.Errorf("username must be configured")
	}
	if cfg.Auth.Password == "" {
		return fmt.Errorf("password must be configured")
	}
	if cfg.Server.GRPCPort == 0 {
		return fmt.Errorf("GRPC port must be configured")
	}
	if cfg.Server.HTTPPort == 0 {
		return fmt.Errorf("HTTP port must be configured")
	}
	if cfg.RateLimit.RequestsPerSecond <= 0 {
		return fmt.Errorf("requests per second must be greater than 0")
	}
	if cfg.RateLimit.Burst <= 0 {
		return fmt.Errorf("burst must be greater than 0")
	}
	return nil
}

func setDefaults(cfg *Config) {
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.RateLimit.CleanupInterval == 0 {
		cfg.RateLimit.CleanupInterval = 5 * time.Minute
	}
	if cfg.RateLimit.MaxInactivity == 0 {
		cfg.RateLimit.MaxInactivity = 1 * time.Hour
	}
}