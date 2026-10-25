package localstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/e-l-l-a-r/gophkeeper/internal/model"
)

func sampleRecord(id string) Record {
	return Record{
		UpdatedAt: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		ID:        id,
		Payload:   []byte{0x00, 0xff, 0x10},
		Version:   3,
		Kind:      model.KindCard,
	}
}

func openCache(t *testing.T, s *Store, server, login string) *Cache {
	t.Helper()

	c, err := s.OpenCache(server, login)
	require.NoError(t, err)

	return c
}

func TestCache_Empty(t *testing.T) {
	c := openCache(t, openTemp(t), "srv", "alice")

	assert.Empty(t, c.Records())

	_, ok := c.Get("missing")
	assert.False(t, ok)
}

func TestCache_PutGetDelete(t *testing.T) {
	c := openCache(t, openTemp(t), "srv", "alice")

	c.Put(sampleRecord("a"))

	got, ok := c.Get("a")
	require.True(t, ok)
	assert.Equal(t, sampleRecord("a"), got)

	replaced := sampleRecord("a")
	replaced.Version = 4
	c.Put(replaced)
	got, _ = c.Get("a")
	assert.Equal(t, int64(4), got.Version, "Put заменяет запись с тем же идентификатором")
	assert.Len(t, c.Records(), 1)

	c.Delete("a")
	_, ok = c.Get("a")
	assert.False(t, ok)

	c.Delete("a") // повторное удаление не ошибка и не паника
}

func TestCache_RecordsSortedByID(t *testing.T) {
	c := openCache(t, openTemp(t), "srv", "alice")

	for _, id := range []string{"c", "a", "b", "d"} {
		c.Put(sampleRecord(id))
	}

	var ids []string
	for _, rec := range c.Records() {
		ids = append(ids, rec.ID)
	}

	assert.Equal(t, []string{"a", "b", "c", "d"}, ids)
}

func TestCache_SaveAndReload(t *testing.T) {
	s := openTemp(t)
	c := openCache(t, s, "srv", "alice")

	pending := sampleRecord("b")
	pending.Pending = PendingUpdate
	c.Put(sampleRecord("a"))
	c.Put(pending)
	require.NoError(t, c.Save())

	reloaded := openCache(t, s, "srv", "alice")
	assert.Equal(t, c.Records(), reloaded.Records())

	got, ok := reloaded.Get("b")
	require.True(t, ok)
	assert.Equal(t, PendingUpdate, got.Pending)
	assert.Equal(t, []byte{0x00, 0xff, 0x10}, got.Payload, "бинарное содержимое сохраняется без искажений")
	assert.Equal(t, model.KindCard, got.Kind)
}

func TestCache_SaveEmptyWritesEmptyArray(t *testing.T) {
	s := openTemp(t)
	c := openCache(t, s, "srv", "alice")
	require.NoError(t, c.Save())

	data, err := os.ReadFile(c.path)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"records": []`)
}

func TestCache_SaveReflectsDeletions(t *testing.T) {
	s := openTemp(t)
	c := openCache(t, s, "srv", "alice")
	c.Put(sampleRecord("a"))
	c.Put(sampleRecord("b"))
	require.NoError(t, c.Save())

	c.Delete("a")
	require.NoError(t, c.Save())

	reloaded := openCache(t, s, "srv", "alice")
	_, hasA := reloaded.Get("a")
	_, hasB := reloaded.Get("b")
	assert.False(t, hasA)
	assert.True(t, hasB)
}

func TestCache_FileIsPrivate(t *testing.T) {
	skipIfNoUnixModes(t)

	s := openTemp(t)
	c := openCache(t, s, "srv", "alice")
	require.NoError(t, c.Save())

	info, err := os.Stat(c.path)
	require.NoError(t, err)
	assert.Equal(t, fileMode, info.Mode().Perm())
}

func TestCache_SeparatedByServerAndLogin(t *testing.T) {
	s := openTemp(t)

	alice := openCache(t, s, "srv", "alice")
	alice.Put(sampleRecord("alice-record"))
	require.NoError(t, alice.Save())

	bob := openCache(t, s, "srv", "bob")
	assert.Empty(t, bob.Records(), "записи одного пользователя не видны другому")

	otherServer := openCache(t, s, "other", "alice")
	assert.Empty(t, otherServer.Records(), "записи с одного сервера не видны на другом")

	again := openCache(t, s, "srv", "alice")
	assert.Len(t, again.Records(), 1)
}

func TestCache_DoesNotContainPlaintextMeta(t *testing.T) {
	s := openTemp(t)
	c := openCache(t, s, "srv", "alice")

	rec := sampleRecord("a")
	rec.Payload = []byte("ciphertext-only")
	c.Put(rec)
	require.NoError(t, c.Save())

	data, err := os.ReadFile(c.path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "ciphertext-only", "содержимое хранится в base64, а не открытым текстом")
}

func TestOpenCache_Errors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "некорректный JSON", body: "{"},
		{name: "неизвестный формат", body: `{"format": 99, "records": []}`},
		{name: "формат не задан", body: `{"records": []}`},
		{name: "запись без идентификатора", body: `{"format": 1, "records": [{"version": 1}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openTemp(t)
			path := filepath.Join(s.Dir(), cacheFileName("srv", "alice"))
			require.NoError(t, os.WriteFile(path, []byte(tt.body), 0o600))

			c, err := s.OpenCache("srv", "alice")
			require.Error(t, err)
			assert.Nil(t, c)
		})
	}
}

func TestCache_SaveFailure(t *testing.T) {
	s := openTemp(t)
	c := openCache(t, s, "srv", "alice")
	c.Put(sampleRecord("a"))

	require.NoError(t, os.RemoveAll(s.Dir()))

	require.Error(t, c.Save())
}

func TestCache_Concurrent(t *testing.T) {
	c := openCache(t, openTemp(t), "srv", "alice")

	done := make(chan struct{})

	for i := range 8 {
		go func() {
			defer func() { done <- struct{}{} }()

			id := string(rune('a' + i))
			for range 50 {
				c.Put(sampleRecord(id))
				_, _ = c.Get(id)
				_ = c.Records()
				_ = c.Save()
				c.Delete(id)
			}
		}()
	}

	for range 8 {
		<-done
	}

	assert.Empty(t, c.Records())
}
