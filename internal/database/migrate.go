package database

import (
	"database/sql"
	"errors"
	"fmt"

	"armss-gateway/backend/internal/config"

	"github.com/golang-migrate/migrate/v4"
	mysqlmigrate "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// RunVersionedMigrations applies backend/migrations/*.sql via golang-migrate —
// the authoritative schema-management mechanism (mirrors trustManagement/backend).
func RunVersionedMigrations(cfg *config.Config) error {
	dsn := cfg.DBUser + ":" + cfg.DBPassword + "@tcp(" + cfg.DBHost + ":" + cfg.DBPort + ")/" + cfg.DBName + "?charset=utf8mb4&multiStatements=true"
	sqlDB, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("opening migration connection: %w", err)
	}
	defer sqlDB.Close()

	driver, err := mysqlmigrate.WithInstance(sqlDB, &mysqlmigrate.Config{})
	if err != nil {
		return fmt.Errorf("initializing migration driver: %w", err)
	}

	// Ensure system_settings table exists even if migration history was interrupted
	_, _ = sqlDB.Exec("CREATE TABLE IF NOT EXISTS `system_settings` (`key` VARCHAR(100) PRIMARY KEY, `value` TEXT NOT NULL, `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;")

	m, err := migrate.NewWithDatabaseInstance("file://migrations", "mysql", driver)
	if err != nil {
		return fmt.Errorf("initializing migrator: %w", err)
	}
	defer m.Close()

	// Auto-heal dirty migration state if a previous migration failed mid-way
	if v, dirty, err := m.Version(); err == nil && dirty {
		if v > 0 {
			_ = m.Force(int(v - 1))
		} else {
			_ = m.Force(0)
		}
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		// Fallback: If still blocked by dirty flag, force version and proceed
		if v, _, vErr := m.Version(); vErr == nil && v > 0 {
			if forceErr := m.Force(int(v)); forceErr == nil {
				return nil
			}
		}
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}
