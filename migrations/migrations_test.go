package migrations

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var fileNamePattern = regexp.MustCompile(`^(\d{6})_[a-z0-9_]+\.(up|down)\.sql$`)

// TestFS_EveryMigrationHasUpAndDown проверяет, что все файлы называются по
// шаблону golang-migrate и у каждой миграции есть пара up/down.
func TestFS_EveryMigrationHasUpAndDown(t *testing.T) {
	entries, err := fs.ReadDir(FS, ".")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	kinds := make(map[string]map[string]bool)

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}

		match := fileNamePattern.FindStringSubmatch(name)
		require.NotNil(t, match, "имя файла %q не соответствует шаблону", name)

		if kinds[match[1]] == nil {
			kinds[match[1]] = make(map[string]bool)
		}
		kinds[match[1]][match[2]] = true
	}

	for version, k := range kinds {
		assert.True(t, k["up"], "у миграции %s нет файла up", version)
		assert.True(t, k["down"], "у миграции %s нет файла down", version)
	}
}

// TestFS_InitCreatesTables проверяет, что начальная миграция создаёт
// таблицы, на которые рассчитан код хранилища, а откат их удаляет.
func TestFS_InitCreatesTables(t *testing.T) {
	up, err := fs.ReadFile(FS, "000001_init.up.sql")
	require.NoError(t, err)
	down, err := fs.ReadFile(FS, "000001_init.down.sql")
	require.NoError(t, err)

	for _, table := range []string{"users", "secrets"} {
		assert.Contains(t, string(up), "CREATE TABLE IF NOT EXISTS "+table+" ")
		assert.Contains(t, string(down), "DROP TABLE IF EXISTS "+table+";")
	}
}
