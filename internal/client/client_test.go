package client

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/e-l-l-a-r/gophkeeper/internal/crypto"
	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
	"github.com/e-l-l-a-r/gophkeeper/internal/model"
	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
)

var (
	testSalt = bytes.Repeat([]byte{0x33}, crypto.SaltSize)
	testTime = time.Date(2026, 8, 9, 10, 11, 12, 0, time.UTC)
)

// device - один «клиент» в тестах: свой каталог кеша, ключи и Remote.
type device struct {
	client *Client
	remote *fakeRemote
	store  *localstore.Store
	cache  *localstore.Cache
}

// newDevice создаёт клиента для пользователя userID на сервере srv. Каталог
// кеша задаётся, чтобы можно было «перезапустить» клиента на том же состоянии.
func newDevice(t *testing.T, srv *serverSide, userID int64, dir, password string) *device {
	t.Helper()

	store, err := localstore.Open(dir)
	require.NoError(t, err)

	cache, err := store.OpenCache("srv", "alice")
	require.NoError(t, err)

	keys, err := crypto.NewKeyring(password, testSalt, 5)
	require.NoError(t, err)

	remote := srv.remote(userID)
	c := New(remote, cache, keys)
	c.now = func() time.Time { return testTime }

	return &device{client: c, remote: remote, store: store, cache: cache}
}

func freshDevice(t *testing.T, srv *serverSide) *device {
	t.Helper()

	return newDevice(t, srv, 1, filepath.Join(t.TempDir(), "state"), "master")
}

func loginEntry(name string) model.Entry {
	return model.Entry{Kind: model.KindLoginPassword, Name: name, Login: "me", Password: "pw", Meta: "example.com"}
}

func TestClient_Add(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	id, err := d.client.Add(loginEntry("почта"))
	require.NoError(t, err)
	assert.Regexp(t, `^[0-9a-f]{8}-`, id)

	rec, ok := d.cache.Get(id)
	require.True(t, ok)
	assert.Equal(t, localstore.PendingCreate, rec.Pending)
	assert.Equal(t, model.KindLoginPassword, rec.Kind)
	assert.Equal(t, testTime, rec.UpdatedAt)
	assert.Zero(t, rec.Version)

	assert.NotContains(t, string(rec.Payload), "почта", "в кеше только шифротекст")
	assert.NotContains(t, string(rec.Payload), "pw")

	got, err := d.client.Get(id)
	require.NoError(t, err)
	assert.Equal(t, id, got.ID)
	assert.Equal(t, "почта", got.Name)
	assert.Equal(t, "pw", got.Password)
	assert.Equal(t, "example.com", got.Meta)
}

func TestClient_Add_IgnoresProvidedID(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	entry := loginEntry("n")
	entry.ID = "my-own-id"

	id, err := d.client.Add(entry)
	require.NoError(t, err)
	assert.NotEqual(t, "my-own-id", id)
}

func TestClient_Add_AllKinds(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	entries := []model.Entry{
		loginEntry("логин"),
		{Kind: model.KindText, Name: "текст", Text: "строка\nдве"},
		{Kind: model.KindBinary, Name: "файл", Data: []byte{0, 1, 2, 255}},
		{Kind: model.KindCard, Name: "карта", Card: &model.Card{Number: "4111111111111111", Holder: "A B", Expiry: "01/30", CVV: "123"}},
	}

	for _, e := range entries {
		id, err := d.client.Add(e)
		require.NoError(t, err, e.Name)

		got, err := d.client.Get(id)
		require.NoError(t, err)
		e.ID = id
		assert.Equal(t, e, got, e.Name)
	}
}

func TestClient_Add_Invalid(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	_, err := d.client.Add(model.Entry{Kind: model.KindText, Name: "n"})
	require.ErrorIs(t, err, model.ErrInvalid)
	assert.Empty(t, d.cache.Records(), "некорректная запись не попадает в кеш")
}

func TestClient_Add_TooLargeAfterEncryption(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	// Данные максимального размера укладываются в лимит; метаинформация сверх
	// разумного делает зашифрованную запись больше лимита сервера.
	entry := model.Entry{
		Kind: model.KindBinary, Name: "большой",
		Data: bytes.Repeat([]byte{0xfe}, model.MaxBinarySize),
		Meta: strings.Repeat("м", 3<<20),
	}

	_, err := d.client.Add(entry)
	require.ErrorIs(t, err, model.ErrInvalid)
	assert.Contains(t, err.Error(), "максимум")
	assert.Empty(t, d.cache.Records())
}

func TestClient_Add_MaxBinaryFitsServerLimit(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	id, err := d.client.Add(model.Entry{
		Kind: model.KindBinary, Name: strings.Repeat("я", model.MaxNameLen),
		Data: bytes.Repeat([]byte{0xfe}, model.MaxBinarySize),
	})
	require.NoError(t, err)

	rec, _ := d.cache.Get(id)
	assert.LessOrEqual(t, len(rec.Payload), pb.MaxPayloadSize)
}

func TestClient_Edit(t *testing.T) {
	srv := newServerSide(t)
	d := freshDevice(t, srv)

	id, err := d.client.Add(loginEntry("n"))
	require.NoError(t, err)

	t.Run("несинхронизированное создание остаётся созданием", func(t *testing.T) {
		edited := loginEntry("n2")
		edited.ID = id
		require.NoError(t, d.client.Edit(edited))

		rec, _ := d.cache.Get(id)
		assert.Equal(t, localstore.PendingCreate, rec.Pending)

		got, getErr := d.client.Get(id)
		require.NoError(t, getErr)
		assert.Equal(t, "n2", got.Name)
	})

	_, err = d.client.Sync(context.Background())
	require.NoError(t, err)

	t.Run("синхронизированная запись становится изменённой", func(t *testing.T) {
		edited := loginEntry("n3")
		edited.ID = strings.ToUpper(id) // идентификатор нормализуется
		require.NoError(t, d.client.Edit(edited))

		rec, _ := d.cache.Get(id)
		assert.Equal(t, localstore.PendingUpdate, rec.Pending)
		assert.Equal(t, int64(1), rec.Version, "версия остаётся серверной до синхронизации")
	})

	t.Run("можно сменить тип", func(t *testing.T) {
		require.NoError(t, d.client.Edit(model.Entry{ID: id, Kind: model.KindText, Name: "как текст", Text: "t"}))

		got, err := d.client.Get(id)
		require.NoError(t, err)
		assert.Equal(t, model.KindText, got.Kind)
		assert.Empty(t, got.Login)
	})

	t.Run("некорректное содержимое не меняет запись", func(t *testing.T) {
		before, _ := d.cache.Get(id)

		require.ErrorIs(t, d.client.Edit(model.Entry{ID: id, Kind: model.KindText, Name: "x"}), model.ErrInvalid)

		after, _ := d.cache.Get(id)
		assert.Equal(t, before, after)
	})

	t.Run("записи нет", func(t *testing.T) {
		err := d.client.Edit(model.Entry{ID: "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11", Kind: model.KindText, Name: "n", Text: "t"})
		require.ErrorIs(t, err, ErrNotFound)
	})
}

func TestClient_Edit_DeletedRecord(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	id, err := d.client.Add(loginEntry("n"))
	require.NoError(t, err)
	_, err = d.client.Sync(context.Background())
	require.NoError(t, err)
	require.NoError(t, d.client.Remove(id))

	edited := loginEntry("n2")
	edited.ID = id
	require.ErrorIs(t, d.client.Edit(edited), ErrNotFound)
}

func TestClient_Remove(t *testing.T) {
	srv := newServerSide(t)
	d := freshDevice(t, srv)

	t.Run("запись, не попавшая на сервер, исчезает сразу", func(t *testing.T) {
		id, err := d.client.Add(loginEntry("local"))
		require.NoError(t, err)

		require.NoError(t, d.client.Remove(id))

		_, ok := d.cache.Get(id)
		assert.False(t, ok)
	})

	t.Run("синхронизированная запись помечается удалённой", func(t *testing.T) {
		id, err := d.client.Add(loginEntry("synced"))
		require.NoError(t, err)
		_, err = d.client.Sync(context.Background())
		require.NoError(t, err)

		require.NoError(t, d.client.Remove(strings.ToUpper(id)))

		rec, ok := d.cache.Get(id)
		require.True(t, ok)
		assert.Equal(t, localstore.PendingDelete, rec.Pending)
		assert.Empty(t, rec.Payload, "содержимое удалённой записи не хранится")

		_, err = d.client.Get(id)
		require.ErrorIs(t, err, ErrNotFound)

		require.ErrorIs(t, d.client.Remove(id), ErrNotFound, "повторное удаление")
	})

	t.Run("записи нет", func(t *testing.T) {
		require.ErrorIs(t, d.client.Remove("0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11"), ErrNotFound)
	})
}

func TestClient_Get_NotFound(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	_, err := d.client.Get("0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestClient_List(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	idB, err := d.client.Add(loginEntry("банк"))
	require.NoError(t, err)
	_, err = d.client.Add(model.Entry{Kind: model.KindText, Name: "Альфа", Text: "t"})
	require.NoError(t, err)
	idGone, err := d.client.Add(loginEntry("удалю"))
	require.NoError(t, err)
	_, err = d.client.Sync(context.Background())
	require.NoError(t, err)
	require.NoError(t, d.client.Remove(idGone))

	list, err := d.client.List()
	require.NoError(t, err)

	require.Len(t, list, 2, "удалённые записи не показываются")
	assert.Equal(t, "Альфа", list[0].Name, "сортировка по названию без учёта регистра")
	assert.Equal(t, "банк", list[1].Name)
	assert.Equal(t, idB, list[1].ID)
	assert.Equal(t, model.KindLoginPassword, list[1].Kind)
	assert.Equal(t, "example.com", list[1].Meta)
	assert.Equal(t, localstore.PendingNone, list[0].Pending)
}

func TestClient_List_Empty(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	list, err := d.client.List()
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestClient_List_PendingFlag(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	_, err := d.client.Add(loginEntry("n"))
	require.NoError(t, err)

	list, err := d.client.List()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, localstore.PendingCreate, list[0].Pending)
}

func TestClient_WrongMasterPassword(t *testing.T) {
	srv := newServerSide(t)
	dir := filepath.Join(t.TempDir(), "state")

	good := newDevice(t, srv, 1, dir, "правильный")
	id, err := good.client.Add(loginEntry("секретная"))
	require.NoError(t, err)

	bad := newDevice(t, srv, 1, dir, "неправильный")

	t.Run("чтение", func(t *testing.T) {
		_, err := bad.client.Get(id)
		require.ErrorIs(t, err, crypto.ErrDecrypt)
		assert.NotContains(t, err.Error(), "секретная")
	})

	t.Run("список", func(t *testing.T) {
		_, err := bad.client.List()
		require.ErrorIs(t, err, crypto.ErrDecrypt)
	})

	t.Run("добавление записи отклоняется", func(t *testing.T) {
		_, err := bad.client.Add(loginEntry("испорченная"))
		require.ErrorIs(t, err, crypto.ErrDecrypt)
		assert.Len(t, bad.cache.Records(), 1, "запись, зашифрованная неверным ключом, не создаётся")
	})

	t.Run("изменение отклоняется", func(t *testing.T) {
		edited := loginEntry("новое имя")
		edited.ID = id

		require.ErrorIs(t, bad.client.Edit(edited), crypto.ErrDecrypt)

		got, err := good.client.Get(id)
		require.NoError(t, err)
		assert.Equal(t, "секретная", got.Name)
	})

	t.Run("верный пароль работает", func(t *testing.T) {
		_, err := good.client.Add(loginEntry("вторая"))
		require.NoError(t, err)
	})
}

func TestClient_VerifyKey_SkippedWithoutRecords(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	_, err := d.client.Add(loginEntry("первая"))
	require.NoError(t, err, "без существующих записей проверять нечем")
}

func TestClient_VerifyKey_IgnoresDeletedRecords(t *testing.T) {
	srv := newServerSide(t)
	dir := filepath.Join(t.TempDir(), "state")

	good := newDevice(t, srv, 1, dir, "правильный")
	id, err := good.client.Add(loginEntry("n"))
	require.NoError(t, err)
	_, err = good.client.Sync(context.Background())
	require.NoError(t, err)
	require.NoError(t, good.client.Remove(id))

	other := newDevice(t, srv, 1, dir, "другой")
	_, err = other.client.Add(loginEntry("новая"))
	require.NoError(t, err, "удалённая запись без содержимого не может подтвердить ключ")
}

func TestClient_Persistence(t *testing.T) {
	srv := newServerSide(t)
	dir := filepath.Join(t.TempDir(), "state")

	first := newDevice(t, srv, 1, dir, "master")
	id, err := first.client.Add(loginEntry("сохранится"))
	require.NoError(t, err)

	second := newDevice(t, srv, 1, dir, "master")
	got, err := second.client.Get(id)
	require.NoError(t, err)
	assert.Equal(t, "сохранится", got.Name)

	rec, _ := second.cache.Get(id)
	assert.Equal(t, localstore.PendingCreate, rec.Pending, "несинхронизированные изменения переживают перезапуск")
}

func TestNormalizeID(t *testing.T) {
	assert.Equal(t, "abc-def", normalizeID("  ABC-DEF\n"))
	assert.Empty(t, normalizeID("   "))
}
