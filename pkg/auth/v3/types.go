package v3

import "time"

// Config represents the top-level structure of the basic-auth-sidecar configuration
type Config struct {
    Server    ServerConfig    `yaml:"server"`
    Logging   LoggingConfig   `yaml:"logging"`
    RateLimit RateLimitConfig `yaml:"rate_limit"`
}

// ServerConfig represents the server configuration section
type ServerConfig struct {
    GRPCPort int `yaml:"grpc_port"`
    HTTPPort int `yaml:"http_port"`
}

// LoggingConfig represents the logging configuration section
type LoggingConfig struct {
    Level string `yaml:"level"`
}

// RateLimitConfig represents the rate limiting configuration section
type RateLimitConfig struct {
    RequestsPerSecond float64       `yaml:"requests_per_second"`
    Burst             int           `yaml:"burst"`
    CleanupInterval   time.Duration `yaml:"cleanup_interval"`
    MaxInactivity     time.Duration `yaml:"max_inactivity"`
}

// NewDefaultConfig returns a Config with default values
func NewDefaultConfig() *Config {
    return &Config{
        Server: ServerConfig{
            GRPCPort: 9001,
            HTTPPort: 8080,
        },
        Logging: LoggingConfig{
            Level: "info",
        },
        RateLimit: RateLimitConfig{
            RequestsPerSecond: 5,
            Burst:             10,
            CleanupInterval:   5 * time.Minute,
            MaxInactivity:     1 * time.Hour,
        },
    }
}
