package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Port                string
	AppEnv              string
	DBHost              string
	DBPort              string
	DBUser              string
	DBPassword          string
	DBName              string
	JWTSecret           string
	FrontendURL         string
	CORSAllowedOrigins  string
	SMTPHost            string
	SMTPPort            string
	SMTPUsername        string
	SMTPPassword        string
	SMTPFromAddress     string
	InstallerAdminEmail string
	InstallerAPISecret  string
	InstallerPassword   string
	AdminAPISecret      string
	UpdateVersion       string
	UpdateURL           string
	UpdateSHA256        string
	UpdateFile          string
	MobileUpdateVersion string
	MobileUpdateURL     string
	MobileUpdateSHA256  string
	MobileUpdateFile    string
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load() // Ignore error if .env is missing in production

	cfg := &Config{
		Port:                getEnv("PORT", "2092"),
		AppEnv:              getEnv("APP_ENV", "development"),
		DBHost:              getEnv("DB_HOST", "127.0.0.1"),
		DBPort:              getEnv("DB_PORT", "3306"),
		DBUser:              getEnv("DB_USER", "root"),
		DBPassword:          getEnv("DB_PASSWORD", ""),
		DBName:              getEnv("DB_NAME", "armss_gateway_db"),
		JWTSecret:           getEnv("JWT_SECRET", ""),
		FrontendURL:         getEnv("FRONTEND_URL", "*"),
		CORSAllowedOrigins:  getEnv("CORS_ALLOWED_ORIGINS", "*"),
		SMTPHost:            getEnv("SMTP_HOST", "mail.arminfo.in"),
		SMTPPort:            getEnv("SMTP_PORT", "465"),
		SMTPUsername:        getEnv("SMTP_USERNAME", ""),
		SMTPPassword:        getEnv("SMTP_PASSWORD", ""),
		SMTPFromAddress:     getEnv("SMTP_FROM_ADDRESS", "noreply@arminfo.in"),
		InstallerAdminEmail: getEnv("INSTALLER_ADMIN_EMAIL", ""),
		InstallerAPISecret:  getEnv("INSTALLER_API_SECRET", ""),
		InstallerPassword:   getEnv("INSTALLER_PASSWORD", "Armss@Installer2026"),
		AdminAPISecret:      getEnv("ADMIN_API_SECRET", ""),
		UpdateVersion:       getEnv("APP_UPDATE_VERSION", ""),
		UpdateURL:           getEnv("APP_UPDATE_URL", ""),
		UpdateSHA256:        getEnv("APP_UPDATE_SHA256", ""),
		UpdateFile:          getEnv("APP_UPDATE_FILE", ""),
		MobileUpdateVersion: getEnv("MOBILE_UPDATE_VERSION", ""),
		MobileUpdateURL:     getEnv("MOBILE_UPDATE_URL", ""),
		MobileUpdateSHA256:  getEnv("MOBILE_UPDATE_SHA256", ""),
		MobileUpdateFile:    getEnv("MOBILE_UPDATE_FILE", ""),
	}

	// Secrets must never have a hardcoded fallback in source — fail fast instead.
	if cfg.DBPassword == "" {
		return nil, fmt.Errorf("DB_PASSWORD must be set via environment/.env")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET must be set via environment/.env")
	}
	if cfg.SMTPUsername == "" {
		return nil, fmt.Errorf("SMTP_USERNAME must be set via environment/.env")
	}
	if cfg.SMTPPassword == "" {
		return nil, fmt.Errorf("SMTP_PASSWORD must be set via environment/.env")
	}
	if cfg.InstallerAdminEmail == "" {
		return nil, fmt.Errorf("INSTALLER_ADMIN_EMAIL must be set via environment/.env")
	}
	if cfg.InstallerAPISecret == "" {
		return nil, fmt.Errorf("INSTALLER_API_SECRET must be set via environment/.env")
	}
	if cfg.AdminAPISecret == "" {
		return nil, fmt.Errorf("ADMIN_API_SECRET must be set via environment/.env")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

func (c *Config) GetDSN() string {
	return c.DBUser + ":" + c.DBPassword + "@tcp(" + c.DBHost + ":" + c.DBPort + ")/" + c.DBName + "?charset=utf8mb4&parseTime=True&loc=Local"
}
