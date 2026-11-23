package pgstore

import (
	"io/fs"
	"strings"
	"testing"
)

func TestGetMigrationsFS(t *testing.T) {
	mfs := GetMigrationsFS()
	entries, err := fs.ReadDir(mfs, "migrations")
	if err != nil {
		t.Fatalf("failed reading embedded migrations: %v", err)
	}
	var hasUp, hasDown bool
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			hasUp = true
		}
		if strings.HasSuffix(e.Name(), ".down.sql") {
			hasDown = true
		}
	}
	if !hasUp || !hasDown {
		t.Fatalf("expected both .up.sql and .down.sql embedded migrations, got hasUp=%v hasDown=%v", hasUp, hasDown)
	}
}

