package localstore

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testExpiry = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

func testSession() Session {
	return Session{
		ExpiresAt: testExpiry,
		Server:    "localhost:8443",
		Login:     "alice",
		Token:     "token-value",
		KDFSalt:   []byte("0123456789abcdef"),
	}
}

func openTemp(t *testing.T) *Store {
	t.Helper()

	s, err := Open(filepath.Join(t.TempDir(), "state"))
	require.NoError(t, err)

	return s
}

// skipIfNoUnixModes пропускает проверки прав доступа там, где их нет (Windows).
func skipIfNoUnixModes(t *testing.T) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("права доступа Unix недоступны в Windows")
	}
}

func TestDefaultDir(t *testing.T) {
	dir, err := DefaultDir()
	require.NoError(t, err)

	assert.Equal(t, appDirName, filepath.Base(dir))
	assert.True(t, filepath.IsAbs(dir))
}

func TestOpen(t *testing.T) {
	t.Run("создаёт каталог с правами 0700", func(t *testing.T) {
		skipIfNoUnixModes(t)

		dir := filepath.Join(t.TempDir(), "a", "b")
		s, err := Open(dir)
		require.NoError(t, err)
		assert.Equal(t, dir, s.Dir())

		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, dirMode, info.Mode().Perm())
	})

	t.Run("не меняет права существующего каталога", func(t *testing.T) {
		skipIfNoUnixModes(t)

		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0o755))

		_, err := Open(dir)
		require.NoError(t, err)

		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
	})

	t.Run("пустой путь", func(t *testing.T) {
		s, err := Open("")
		require.Error(t, err)
		assert.Nil(t, s)
	})

	t.Run("путь занят файлом", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(file, nil, 0o600))

		_, err := Open(filepath.Join(file, "sub"))
		require.Error(t, err)
	})
}

func TestSession_Expired(t *testing.T) {
	sess := testSession()

	tests := []struct {
		now  time.Time
		name string
		want bool
	}{
		{name: "до истечения", now: testExpiry.Add(-time.Second)},
		{name: "в момент истечения", now: testExpiry, want: true},
		{name: "после истечения", now: testExpiry.Add(time.Hour), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sess.Expired(tt.now))
		})
	}
}

func TestStore_SessionRoundTrip(t *testing.T) {
	s := openTemp(t)

	_, err := s.LoadSession()
	require.ErrorIs(t, err, ErrNoSession)

	require.NoError(t, s.SaveSession(testSession()))

	got, err := s.LoadSession()
	require.NoError(t, err)
	assert.Equal(t, testSession(), got)
}

func TestStore_SessionFileIsPrivate(t *testing.T) {
	skipIfNoUnixModes(t)

	s := openTemp(t)
	require.NoError(t, s.SaveSession(testSession()))

	info, err := os.Stat(filepath.Join(s.Dir(), sessionFileName))
	require.NoError(t, err)
	assert.Equal(t, fileMode, info.Mode().Perm())
}

func TestStore_SaveSession_Validation(t *testing.T) {
	tests := []struct {
		mutate func(*Session)
		name   string
	}{
		{name: "нет токена", mutate: func(s *Session) { s.Token = "" }},
		{name: "нет сервера", mutate: func(s *Session) { s.Server = "" }},
		{name: "нет логина", mutate: func(s *Session) { s.Login = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openTemp(t)
			sess := testSession()
			tt.mutate(&sess)

			require.Error(t, s.SaveSession(sess))

			_, err := s.LoadSession()
			require.ErrorIs(t, err, ErrNoSession, "некорректная сессия не должна сохраняться")
		})
	}
}

func TestStore_SaveSession_ReplacesPrevious(t *testing.T) {
	s := openTemp(t)
	require.NoError(t, s.SaveSession(testSession()))

	other := testSession()
	other.Login = "bob"
	other.Token = "other-token"
	require.NoError(t, s.SaveSession(other))

	got, err := s.LoadSession()
	require.NoError(t, err)
	assert.Equal(t, "bob", got.Login)
	assert.Equal(t, "other-token", got.Token)
}

func TestStore_LoadSession_Corrupted(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "некорректный JSON", body: "{"},
		{name: "нет токена", body: `{"server":"s","login":"l"}`},
		{name: "пустой файл", body: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openTemp(t)
			require.NoError(t, os.WriteFile(filepath.Join(s.Dir(), sessionFileName), []byte(tt.body), 0o600))

			_, err := s.LoadSession()
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrNoSession, "повреждённый файл - не то же самое, что отсутствие входа")
		})
	}
}

func TestStore_ClearSession(t *testing.T) {
	s := openTemp(t)

	require.NoError(t, s.ClearSession(), "отсутствие сессии не ошибка")

	require.NoError(t, s.SaveSession(testSession()))
	require.NoError(t, s.ClearSession())

	_, err := s.LoadSession()
	require.ErrorIs(t, err, ErrNoSession)
}

func TestStore_ClearSession_KeepsCache(t *testing.T) {
	s := openTemp(t)
	require.NoError(t, s.SaveSession(testSession()))

	cache, err := s.OpenCache("srv", "alice")
	require.NoError(t, err)
	cache.Put(Record{ID: "id-1", Pending: PendingCreate, Payload: []byte("p"), Kind: 2})
	require.NoError(t, cache.Save())

	require.NoError(t, s.ClearSession())

	again, err := s.OpenCache("srv", "alice")
	require.NoError(t, err)
	_, ok := again.Get("id-1")
	assert.True(t, ok, "выход не должен терять несинхронизированные изменения")
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.json")

	require.NoError(t, writeFileAtomic(path, []byte("first")))
	require.NoError(t, writeFileAtomic(path, []byte("second")))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "second", string(data))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "временные файлы не должны оставаться")
	assert.Equal(t, "file.json", entries[0].Name())
}

func TestWriteFileAtomic_FailureKeepsOldContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.json")
	require.NoError(t, writeFileAtomic(path, []byte("old")))

	// Подкаталог вместо целевого файла делает переименование невозможным.
	blocked := filepath.Join(dir, "blocked")
	require.NoError(t, os.Mkdir(blocked, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(blocked, "x"), nil, 0o600))

	require.Error(t, writeFileAtomic(blocked, []byte("new")))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "old", string(data))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".tmp-"), "после сбоя не должно быть временных файлов: %s", e.Name())
	}
}

func TestWriteFileAtomic_MissingDirectory(t *testing.T) {
	require.Error(t, writeFileAtomic(filepath.Join(t.TempDir(), "no", "such", "file"), []byte("x")))
}

func TestCacheFileName(t *testing.T) {
	a := cacheFileName("srv", "alice")

	assert.Equal(t, a, cacheFileName("srv", "alice"), "имя детерминировано")
	assert.NotEqual(t, a, cacheFileName("srv", "bob"))
	assert.NotEqual(t, a, cacheFileName("other", "alice"))
	assert.NotEqual(t, cacheFileName("ab", "c"), cacheFileName("a", "bc"), "граница между сервером и логином учитывается")
	assert.True(t, strings.HasPrefix(a, "cache-") && strings.HasSuffix(a, ".json"))
}
