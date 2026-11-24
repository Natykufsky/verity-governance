package pgstore

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// GetMigrationsFS exposes the raw embedded SQL migration files (`migrations/*.sql`)
// for external migration runners (such as golang-migrate).
func GetMigrationsFS() fs.FS {
	return migrationsFS
}

// MigrateUp executes all embedded *.up.sql migration scripts in order via *sql.DB.
// It tracks applied versions in "verity_governance_schema_migrations".
func MigrateUp(ctx context.Context, db *sql.DB) error {
	trackTableQuery := `
		CREATE TABLE IF NOT EXISTS verity_governance_schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`
	if _, err := db.ExecContext(ctx, trackTableQuery); err != nil {
		return fmt.Errorf("pgstore: failed to ensure verity_governance_schema_migrations table: %w", err)
	}

	return runTrackedSQLMigrations(ctx, ".up.sql", false,
		func(version string) (bool, error) {
			var exists bool
			err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM verity_governance_schema_migrations WHERE version = $1)`, version).Scan(&exists)
			return exists, err
		},
		func(version string, sqlText string) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, sqlText); err != nil {
				_ = tx.Rollback()
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO verity_governance_schema_migrations (version) VALUES ($1)`, version); err != nil {
				_ = tx.Rollback()
				return err
			}
			return tx.Commit()
		},
	)
}

// MigrateDown executes all embedded *.down.sql migration scripts in reverse order via *sql.DB.
func MigrateDown(ctx context.Context, db *sql.DB) error {
	return runSQLMigrations(ctx, ".down.sql", true, func(sqlText string) error {
		_, err := db.ExecContext(ctx, sqlText)
		return err
	})
}

// MigrateUpPool executes all embedded *.up.sql migration scripts in order via *pgxpool.Pool.
// It tracks applied versions in "verity_governance_schema_migrations".
func MigrateUpPool(ctx context.Context, pool *pgxpool.Pool) error {
	trackTableQuery := `
		CREATE TABLE IF NOT EXISTS verity_governance_schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`
	if _, err := pool.Exec(ctx, trackTableQuery); err != nil {
		return fmt.Errorf("pgstore: failed to ensure verity_governance_schema_migrations table: %w", err)
	}

	return runTrackedSQLMigrations(ctx, ".up.sql", false,
		func(version string) (bool, error) {
			var exists bool
			err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM verity_governance_schema_migrations WHERE version = $1)`, version).Scan(&exists)
			return exists, err
		},
		func(version string, sqlText string) error {
			tx, err := pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(ctx) }()

			if _, err := tx.Exec(ctx, sqlText); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO verity_governance_schema_migrations (version) VALUES ($1)`, version); err != nil {
				return err
			}
			return tx.Commit(ctx)
		},
	)
}

// MigrateDownPool executes all embedded *.down.sql migration scripts in reverse order via *pgxpool.Pool.
func MigrateDownPool(ctx context.Context, pool *pgxpool.Pool) error {
	return runSQLMigrations(ctx, ".down.sql", true, func(sqlText string) error {
		_, err := pool.Exec(ctx, sqlText)
		return err
	})
}

func runTrackedSQLMigrations(_ context.Context, suffix string, reverse bool, checkFn func(string) (bool, error), execFn func(string, string) error) error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("pgstore: read embedded migrations dir: %w", err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), suffix) {
			files = append(files, entry.Name())
		}
	}
	if reverse {
		sort.Sort(sort.Reverse(sort.StringSlice(files)))
	} else {
		sort.Strings(files)
	}
	for _, f := range files {
		applied, err := checkFn(f)
		if err != nil {
			return fmt.Errorf("pgstore: check migration %s: %w", f, err)
		}
		if applied {
			continue
		}

		b, err := migrationsFS.ReadFile("migrations/" + f)
		if err != nil {
			return fmt.Errorf("pgstore: read file %s: %w", f, err)
		}
		if err := execFn(f, string(b)); err != nil {
			return fmt.Errorf("pgstore: apply migration %s: %w", f, err)
		}
	}
	return nil
}

func runSQLMigrations(_ context.Context, suffix string, reverse bool, execFn func(string) error) error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("pgstore: read embedded migrations dir: %w", err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), suffix) {
			files = append(files, entry.Name())
		}
	}
	if reverse {
		sort.Sort(sort.Reverse(sort.StringSlice(files)))
	} else {
		sort.Strings(files)
	}

	for _, file := range files {
		raw, err := migrationsFS.ReadFile("migrations/" + file)
		if err != nil {
			return fmt.Errorf("pgstore: read migration %s: %w", file, err)
		}
		if err := execFn(string(raw)); err != nil {
			return fmt.Errorf("pgstore: apply migration %s: %w", file, err)
		}
	}
	return nil
}

