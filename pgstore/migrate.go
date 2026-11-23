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
func MigrateUp(ctx context.Context, db *sql.DB) error {
	return runSQLMigrations(ctx, ".up.sql", false, func(sqlText string) error {
		_, err := db.ExecContext(ctx, sqlText)
		return err
	})
}

// MigrateDown executes all embedded *.down.sql migration scripts in reverse order via *sql.DB.
func MigrateDown(ctx context.Context, db *sql.DB) error {
	return runSQLMigrations(ctx, ".down.sql", true, func(sqlText string) error {
		_, err := db.ExecContext(ctx, sqlText)
		return err
	})
}

// MigrateUpPool executes all embedded *.up.sql migration scripts in order via *pgxpool.Pool.
func MigrateUpPool(ctx context.Context, pool *pgxpool.Pool) error {
	return runSQLMigrations(ctx, ".up.sql", false, func(sqlText string) error {
		_, err := pool.Exec(ctx, sqlText)
		return err
	})
}

// MigrateDownPool executes all embedded *.down.sql migration scripts in reverse order via *pgxpool.Pool.
func MigrateDownPool(ctx context.Context, pool *pgxpool.Pool) error {
	return runSQLMigrations(ctx, ".down.sql", true, func(sqlText string) error {
		_, err := pool.Exec(ctx, sqlText)
		return err
	})
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

