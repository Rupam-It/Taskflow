package config

import (
	"os"
	"time"
)

type Config struct {
	Server struct {
		Port string
		Host string
	}
	Database struct {
		Host     string
		Port     string
		User     string
		Password string
		Name     string
		SSLMode  string
	}
	JWT struct {
		Secret        string
		AccessExpiry  time.Duration
		RefreshExpiry time.Duration
	}
	Email struct {
		SMTPHost     string
		SMTPPort     int
		SMTPUsername string
		SMTPPassword string
		FromEmail    string
	}
}

func Load() *Config {
	config := &Config{}

	config.Server.Port = getEnv("PORT", "8080")
	config.Server.Host = getEnv("HOST", "0.0.0.0")

	config.Database.Host = getEnv("DB_HOST", "localhost")
	config.Database.Port = getEnv("DB_PORT", "5432")
	config.Database.User = getEnv("DB_USER", "taskflow")
	config.Database.Password = getEnv("DB_PASSWORD", "taskflow123")
	config.Database.Name = getEnv("DB_NAME", "taskflow_users")
	config.Database.SSLMode = getEnv("DB_SSL_MODE", "disable")

	config.JWT.Secret = getEnv("JWT_SECRET", "your-super-secret-jwt-key")
	config.JWT.AccessExpiry = parseDuration(getEnv("JWT_ACCESS_EXPIRY", "15m"))
	config.JWT.RefreshExpiry = parseDuration(getEnv("JWT_REFRESH_EXPIRY", "7d"))

	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Hour
	}
	return d
}
