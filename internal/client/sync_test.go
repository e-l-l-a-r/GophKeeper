package client

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
	"github.com/e-l-l-a-r/gophkeeper/internal/model"
)

// pair создаёт два устройства одного пользователя на общем сервере, у
// которых один мастер-пароль и разные локальные кеши.
func pair(t *testing.T) (laptop, phone *device, srv *serverSide) {
	t.Helper()

	srv = newServerSide(t)
	laptop = newDevice(t, srv, 1, filepath.Join(t.TempDir(), "laptop"), "master")
	phone = newDevice(t, srv, 1, filepath.Join(t.TempDir(), "phone"), "master")

	return laptop, phone, srv
}

func mustSync(t *testing.T, d *device) SyncResult {
	t.Helper()

	res, err := d.client.Sync(context.Background())
	require.NoError(t, err)

	return res
}

func TestSync_PushCreate(t *testing.T) {
	srv := newServerSide(t)
	d := freshDevice(t, srv)

	id, err := d.client.Add(loginEntry("n"))
	require.NoError(t, err)

	res := mustSync(t, d)
	assert.Equal(t, 1, res.Pushed)
	assert.Zero(t, res.Pulled)
	assert.Empty(t, res.Conflicts)

	rec, _ := d.cache.Get(id)
	assert.Equal(t, localstore.PendingNone, rec.Pending)
	assert.Equal(t, int64(1), rec.Version)

	again := mustSync(t, d)
	assert.Zero(t, again.Pushed, "повторная синхронизация ничего не отправляет")
	assert.Zero(t, again.Pulled)
}

func TestSync_NewDeviceGetsAllRecords(t *testing.T) {
	laptop, phone, _ := pair(t)

	idLogin, err := laptop.client.Add(loginEntry("логин"))
	require.NoError(t, err)
	idCard, err := laptop.client.Add(model.Entry{
		Kind: model.KindCard, Name: "карта",
		Card: &model.Card{Number: "4111111111111111", Holder: "A B", Expiry: "01/30", CVV: "123"},
	})
	require.NoError(t, err)
	mustSync(t, laptop)

	res := mustSync(t, phone)
	assert.Equal(t, 2, res.Pulled)

	login, err := phone.client.Get(idLogin)
	require.NoError(t, err)
	assert.Equal(t, "pw", login.Password)

	card, err := phone.client.Get(idCard)
	require.NoError(t, err)
	assert.Equal(t, "4111111111111111", card.Card.Number)
}

func TestSync_UpdatePropagates(t *testing.T) {
	laptop, phone, _ := pair(t)

	id, err := laptop.client.Add(loginEntry("v1"))
	require.NoError(t, err)
	mustSync(t, laptop)
	mustSync(t, phone)

	edited := loginEntry("v2")
	edited.ID = id
	require.NoError(t, laptop.client.Edit(edited))

	res := mustSync(t, laptop)
	assert.Equal(t, 1, res.Pushed)

	res = mustSync(t, phone)
	assert.Equal(t, 1, res.Pulled)

	got, err := phone.client.Get(id)
	require.NoError(t, err)
	assert.Equal(t, "v2", got.Name)

	rec, _ := phone.cache.Get(id)
	assert.Equal(t, int64(2), rec.Version)
}

func TestSync_DeletePropagates(t *testing.T) {
	laptop, phone, _ := pair(t)

	id, err := laptop.client.Add(loginEntry("n"))
	require.NoError(t, err)
	mustSync(t, laptop)
	mustSync(t, phone)

	require.NoError(t, laptop.client.Remove(id))
	res := mustSync(t, laptop)
	assert.Equal(t, 1, res.Pushed)

	_, ok := laptop.cache.Get(id)
	assert.False(t, ok, "после отправки удаления запись исчезает из кеша")

	res = mustSync(t, phone)
	assert.Equal(t, 1, res.Removed)

	_, err = phone.client.Get(id)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestSync_UsersAreIsolated(t *testing.T) {
	srv := newServerSide(t)
	alice := newDevice(t, srv, 1, filepath.Join(t.TempDir(), "a"), "master")
	bob := newDevice(t, srv, 2, filepath.Join(t.TempDir(), "b"), "master")

	_, err := alice.client.Add(loginEntry("секрет алисы"))
	require.NoError(t, err)
	mustSync(t, alice)

	res := mustSync(t, bob)
	assert.Zero(t, res.Pulled, "чужие записи не передаются")
	assert.Empty(t, bob.cache.Records())
}

func TestSync_Conflict_ServerChangedAndLocalChanged(t *testing.T) {
	laptop, phone, _ := pair(t)

	id, err := laptop.client.Add(loginEntry("исходная"))
	require.NoError(t, err)
	mustSync(t, laptop)
	mustSync(t, phone)

	fromLaptop := loginEntry("с ноутбука")
	fromLaptop.ID = id
	require.NoError(t, laptop.client.Edit(fromLaptop))
	mustSync(t, laptop)

	fromPhone := loginEntry("с телефона")
	fromPhone.ID = id
	require.NoError(t, phone.client.Edit(fromPhone))

	res, err := phone.client.Sync(context.Background())
	require.ErrorIs(t, err, ErrConflict)
	require.Len(t, res.Conflicts, 1)
	assert.Equal(t, Conflict{ID: id, Reason: ConflictVersion, Pending: localstore.PendingUpdate, Kind: model.KindLoginPassword}, res.Conflicts[0])

	// Ничего не перезаписано: ни на сервере, ни локально.
	got, err := phone.client.Get(id)
	require.NoError(t, err)
	assert.Equal(t, "с телефона", got.Name, "локальное изменение сохранено")

	remote, err := laptop.remote.Get(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, int64(2), remote.Version)

	rec, _ := phone.cache.Get(id)
	assert.Equal(t, localstore.PendingUpdate, rec.Pending)
}

func TestSync_Conflict_DoesNotBlockOtherRecords(t *testing.T) {
	laptop, phone, _ := pair(t)

	conflicting, err := laptop.client.Add(loginEntry("спорная"))
	require.NoError(t, err)
	mustSync(t, laptop)
	mustSync(t, phone)

	edit := loginEntry("ноутбук")
	edit.ID = conflicting
	require.NoError(t, laptop.client.Edit(edit))
	mustSync(t, laptop)

	edit.Name = "телефон"
	require.NoError(t, phone.client.Edit(edit))
	fresh, err := phone.client.Add(loginEntry("новая с телефона"))
	require.NoError(t, err)

	res, err := phone.client.Sync(context.Background())
	require.ErrorIs(t, err, ErrConflict)
	assert.Equal(t, 1, res.Pushed, "несвязанная запись отправлена")
	assert.Len(t, res.Conflicts, 1)

	rec, _ := phone.cache.Get(fresh)
	assert.Equal(t, localstore.PendingNone, rec.Pending)
}

func TestSync_Conflict_PullSkipsRecordWithLocalChanges(t *testing.T) {
	laptop, phone, _ := pair(t)

	id, err := laptop.client.Add(loginEntry("исходная"))
	require.NoError(t, err)
	mustSync(t, laptop)
	mustSync(t, phone)

	edit := loginEntry("ноутбук")
	edit.ID = id
	require.NoError(t, laptop.client.Edit(edit))
	mustSync(t, laptop)

	edit.Name = "телефон"
	require.NoError(t, phone.client.Edit(edit))

	_, err = phone.client.Sync(context.Background())
	require.ErrorIs(t, err, ErrConflict)

	got, err := phone.client.Get(id)
	require.NoError(t, err)
	assert.Equal(t, "телефон", got.Name, "серверная версия не затирает локальное изменение")
}

func TestSync_Conflict_UpdateOfServerDeletedRecord(t *testing.T) {
	laptop, phone, _ := pair(t)

	id, err := laptop.client.Add(loginEntry("n"))
	require.NoError(t, err)
	mustSync(t, laptop)
	mustSync(t, phone)

	require.NoError(t, laptop.client.Remove(id))
	mustSync(t, laptop)

	edit := loginEntry("правка на телефоне")
	edit.ID = id
	require.NoError(t, phone.client.Edit(edit))

	res, err := phone.client.Sync(context.Background())
	require.ErrorIs(t, err, ErrConflict)
	require.Len(t, res.Conflicts, 1)
	assert.Equal(t, ConflictDeleted, res.Conflicts[0].Reason)

	got, err := phone.client.Get(id)
	require.NoError(t, err)
	assert.Equal(t, "правка на телефоне", got.Name, "правка пользователя не потеряна")
}

func TestSync_Conflict_DeleteOfServerChangedRecord(t *testing.T) {
	laptop, phone, _ := pair(t)

	id, err := laptop.client.Add(loginEntry("n"))
	require.NoError(t, err)
	mustSync(t, laptop)
	mustSync(t, phone)

	edit := loginEntry("правка")
	edit.ID = id
	require.NoError(t, laptop.client.Edit(edit))
	mustSync(t, laptop)

	require.NoError(t, phone.client.Remove(id))

	res, err := phone.client.Sync(context.Background())
	require.ErrorIs(t, err, ErrConflict)
	require.Len(t, res.Conflicts, 1)
	assert.Equal(t, Conflict{ID: id, Reason: ConflictVersion, Pending: localstore.PendingDelete, Kind: model.KindLoginPassword}, res.Conflicts[0])

	remote, err := laptop.remote.Get(context.Background(), id)
	require.NoError(t, err, "запись, изменённая на сервере, не удалена")
	assert.Equal(t, int64(2), remote.Version)
}

func TestSync_DeleteOfAlreadyDeletedRecordSucceeds(t *testing.T) {
	laptop, phone, _ := pair(t)

	id, err := laptop.client.Add(loginEntry("n"))
	require.NoError(t, err)
	mustSync(t, laptop)
	mustSync(t, phone)

	require.NoError(t, laptop.client.Remove(id))
	mustSync(t, laptop)

	require.NoError(t, phone.client.Remove(id))
	res := mustSync(t, phone)
	assert.Equal(t, 1, res.Pushed, "запись уже удалена на сервере: цель достигнута")

	_, ok := phone.cache.Get(id)
	assert.False(t, ok)
}

func TestSync_Conflict_CreateWithTakenID(t *testing.T) {
	laptop, phone, _ := pair(t)

	id, err := laptop.client.Add(loginEntry("на сервере"))
	require.NoError(t, err)
	mustSync(t, laptop)

	// Телефон создал другую запись с тем же идентификатором (практически невозможно
	// для UUID, но клиент не должен ничего затирать).
	phone.cache.Put(localstore.Record{
		ID: id, Pending: localstore.PendingCreate, Payload: []byte("чужой шифротекст"), Kind: model.KindText,
	})

	res, err := phone.client.Sync(context.Background())
	require.ErrorIs(t, err, ErrConflict)
	require.Len(t, res.Conflicts, 1)
	assert.Equal(t, ConflictExists, res.Conflicts[0].Reason)

	remote, err := laptop.remote.Get(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, model.KindLoginPassword, remote.Kind, "серверная запись не изменена")
}

func TestSync_NetworkErrorKeepsPendingChanges(t *testing.T) {
	srv := newServerSide(t)
	d := freshDevice(t, srv)

	id, err := d.client.Add(loginEntry("n"))
	require.NoError(t, err)

	d.remote.beforeCall = failOn("create", errNetwork)

	_, err = d.client.Sync(context.Background())
	require.ErrorIs(t, err, errNetwork)

	rec, ok := d.cache.Get(id)
	require.True(t, ok)
	assert.Equal(t, localstore.PendingCreate, rec.Pending, "изменение не потеряно")

	d.remote.beforeCall = nil

	res := mustSync(t, d)
	assert.Equal(t, 1, res.Pushed, "повторная синхронизация отправляет изменение")
}

func TestSync_LostResponseOnCreateIsIdempotent(t *testing.T) {
	srv := newServerSide(t)
	d := freshDevice(t, srv)

	id, err := d.client.Add(loginEntry("n"))
	require.NoError(t, err)

	// Сервер принял запись, но ответ потерялся.
	d.remote.afterCall = failOnce("create", errNetwork)

	_, err = d.client.Sync(context.Background())
	require.ErrorIs(t, err, errNetwork)

	res := mustSync(t, d)
	assert.Empty(t, res.Conflicts, "уже принятая запись не считается конфликтом")
	assert.Equal(t, 1, res.Pushed)

	rec, _ := d.cache.Get(id)
	assert.Equal(t, localstore.PendingNone, rec.Pending)
	assert.Equal(t, int64(1), rec.Version)
}

func TestSync_LostResponseOnUpdateIsIdempotent(t *testing.T) {
	srv := newServerSide(t)
	d := freshDevice(t, srv)

	id, err := d.client.Add(loginEntry("n"))
	require.NoError(t, err)
	mustSync(t, d)

	edit := loginEntry("n2")
	edit.ID = id
	require.NoError(t, d.client.Edit(edit))

	d.remote.afterCall = failOnce("update", errNetwork)

	_, err = d.client.Sync(context.Background())
	require.ErrorIs(t, err, errNetwork)

	res := mustSync(t, d)
	assert.Empty(t, res.Conflicts, "уже принятое изменение не считается конфликтом")

	rec, _ := d.cache.Get(id)
	assert.Equal(t, localstore.PendingNone, rec.Pending)
	assert.Equal(t, int64(2), rec.Version)
}

func TestSync_LostResponseOnDeleteIsIdempotent(t *testing.T) {
	srv := newServerSide(t)
	d := freshDevice(t, srv)

	id, err := d.client.Add(loginEntry("n"))
	require.NoError(t, err)
	mustSync(t, d)
	require.NoError(t, d.client.Remove(id))

	d.remote.afterCall = failOnce("delete", errNetwork)

	_, err = d.client.Sync(context.Background())
	require.ErrorIs(t, err, errNetwork)

	res := mustSync(t, d)
	assert.Empty(t, res.Conflicts)

	_, ok := d.cache.Get(id)
	assert.False(t, ok)
}

func TestSync_PullErrorKeepsPushedChanges(t *testing.T) {
	srv := newServerSide(t)
	d := freshDevice(t, srv)

	id, err := d.client.Add(loginEntry("n"))
	require.NoError(t, err)

	d.remote.beforeCall = failOn("sync", errNetwork)

	res, err := d.client.Sync(context.Background())
	require.ErrorIs(t, err, errNetwork)
	assert.Equal(t, 1, res.Pushed)

	rec, _ := d.cache.Get(id)
	assert.Equal(t, localstore.PendingNone, rec.Pending, "отправленное сохранено, несмотря на сбой получения")

	reopened, err := d.store.OpenCache("srv", "alice")
	require.NoError(t, err)
	persisted, _ := reopened.Get(id)
	assert.Equal(t, int64(1), persisted.Version, "состояние сохранено на диск")
}

func TestSync_ContextCancelled(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	_, err := d.client.Add(loginEntry("n"))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = d.client.Sync(ctx)
	require.ErrorIs(t, err, context.Canceled)

	assert.Empty(t, d.remote.callLog(), "после отмены на сервер ничего не отправляется")
}

func TestSync_PushOrderCreatesBeforeNothingElseBreaks(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	for _, name := range []string{"a", "b", "c"} {
		_, err := d.client.Add(loginEntry(name))
		require.NoError(t, err)
	}

	res := mustSync(t, d)
	assert.Equal(t, 3, res.Pushed)

	ops := d.remote.callLog()
	assert.Equal(t, []string{"create", "create", "create", "sync"}, ops, "сначала отправка, затем получение дельты")
}

func TestSync_CorruptedRecordWithoutVersion(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	d.cache.Put(localstore.Record{ID: "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11", Pending: localstore.PendingUpdate, Payload: []byte("x"), Kind: model.KindText})

	_, err := d.client.Sync(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "нет версии")
}

func TestSync_UnknownPendingState(t *testing.T) {
	d := freshDevice(t, newServerSide(t))

	d.cache.Put(localstore.Record{ID: "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11", Pending: "странное", Version: 1, Payload: []byte("x"), Kind: model.KindText})

	_, err := d.client.Sync(context.Background())
	require.Error(t, err)
}

func TestSync_FullScenarioTwoDevices(t *testing.T) {
	laptop, phone, _ := pair(t)

	// Пользователь работает на двух устройствах попеременно.
	a, err := laptop.client.Add(loginEntry("почта"))
	require.NoError(t, err)
	mustSync(t, laptop)
	mustSync(t, phone)

	b, err := phone.client.Add(model.Entry{Kind: model.KindText, Name: "заметка", Text: "с телефона"})
	require.NoError(t, err)
	mustSync(t, phone)
	mustSync(t, laptop)

	edit := loginEntry("почта 2")
	edit.ID = a
	require.NoError(t, phone.client.Edit(edit))
	require.NoError(t, laptop.client.Remove(b))
	mustSync(t, phone)
	mustSync(t, laptop)
	mustSync(t, phone)

	listLaptop, err := laptop.client.List()
	require.NoError(t, err)
	listPhone, err := phone.client.List()
	require.NoError(t, err)

	require.Len(t, listLaptop, 1)
	require.Len(t, listPhone, 1)
	assert.Equal(t, "почта 2", listLaptop[0].Name)
	assert.Equal(t, listLaptop, listPhone, "после синхронизации устройства видят одно и то же")
}

func TestResolve(t *testing.T) {
	t.Run("оставить локальное: версия переносится, затем отправка проходит", func(t *testing.T) {
		laptop, phone, _ := pair(t)

		id, _ := conflictOnUpdate(t, laptop, phone)

		require.NoError(t, phone.client.Resolve(context.Background(), strings.ToUpper(id), KeepLocal))

		rec, _ := phone.cache.Get(id)
		assert.Equal(t, int64(2), rec.Version, "версия перенесена на серверную")
		assert.Equal(t, localstore.PendingUpdate, rec.Pending)

		res := mustSync(t, phone)
		assert.Equal(t, 1, res.Pushed)

		got, err := laptop.remote.Get(context.Background(), id)
		require.NoError(t, err)
		assert.Equal(t, int64(3), got.Version)

		mustSync(t, laptop)
		entry, err := laptop.client.Get(id)
		require.NoError(t, err)
		assert.Equal(t, "с телефона", entry.Name, "победила локальная правка")
	})

	t.Run("оставить серверное: локальная правка отбрасывается", func(t *testing.T) {
		laptop, phone, _ := pair(t)

		id, _ := conflictOnUpdate(t, laptop, phone)

		require.NoError(t, phone.client.Resolve(context.Background(), id, KeepServer))

		rec, _ := phone.cache.Get(id)
		assert.Equal(t, localstore.PendingNone, rec.Pending)
		assert.Equal(t, int64(2), rec.Version)

		entry, err := phone.client.Get(id)
		require.NoError(t, err)
		assert.Equal(t, "с ноутбука", entry.Name)

		res := mustSync(t, phone)
		assert.Zero(t, res.Pushed)
	})

	t.Run("запись удалена на сервере, оставить локальное: новая запись", func(t *testing.T) {
		laptop, phone, _ := pair(t)

		id, err := laptop.client.Add(loginEntry("n"))
		require.NoError(t, err)
		mustSync(t, laptop)
		mustSync(t, phone)

		require.NoError(t, laptop.client.Remove(id))
		mustSync(t, laptop)

		edit := loginEntry("правка телефона")
		edit.ID = id
		require.NoError(t, phone.client.Edit(edit))

		_, err = phone.client.Sync(context.Background())
		require.ErrorIs(t, err, ErrConflict)

		require.NoError(t, phone.client.Resolve(context.Background(), id, KeepLocal))

		_, ok := phone.cache.Get(id)
		assert.False(t, ok, "удалённый идентификатор не используется повторно")

		list, err := phone.client.List()
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, "правка телефона", list[0].Name)
		assert.Equal(t, localstore.PendingCreate, list[0].Pending)

		res := mustSync(t, phone)
		assert.Equal(t, 1, res.Pushed)
		assert.Empty(t, res.Conflicts)
	})

	t.Run("запись удалена на сервере, оставить серверное: запись исчезает", func(t *testing.T) {
		laptop, phone, _ := pair(t)

		id, err := laptop.client.Add(loginEntry("n"))
		require.NoError(t, err)
		mustSync(t, laptop)
		mustSync(t, phone)

		require.NoError(t, laptop.client.Remove(id))
		mustSync(t, laptop)

		edit := loginEntry("правка телефона")
		edit.ID = id
		require.NoError(t, phone.client.Edit(edit))

		require.NoError(t, phone.client.Resolve(context.Background(), id, KeepServer))

		_, ok := phone.cache.Get(id)
		assert.False(t, ok)
	})

	t.Run("удаление против удаления", func(t *testing.T) {
		laptop, phone, _ := pair(t)

		id, err := laptop.client.Add(loginEntry("n"))
		require.NoError(t, err)
		mustSync(t, laptop)
		mustSync(t, phone)

		require.NoError(t, laptop.client.Remove(id))
		mustSync(t, laptop)

		require.NoError(t, phone.client.Remove(id))
		require.NoError(t, phone.client.Resolve(context.Background(), id, KeepLocal))

		_, ok := phone.cache.Get(id)
		assert.False(t, ok)
	})

	t.Run("локальное удаление против изменения на сервере: оставить локальное", func(t *testing.T) {
		laptop, phone, _ := pair(t)

		id, err := laptop.client.Add(loginEntry("n"))
		require.NoError(t, err)
		mustSync(t, laptop)
		mustSync(t, phone)

		edit := loginEntry("правка")
		edit.ID = id
		require.NoError(t, laptop.client.Edit(edit))
		mustSync(t, laptop)

		require.NoError(t, phone.client.Remove(id))
		_, err = phone.client.Sync(context.Background())
		require.ErrorIs(t, err, ErrConflict)

		require.NoError(t, phone.client.Resolve(context.Background(), id, KeepLocal))
		mustSync(t, phone)

		_, err = laptop.remote.Get(context.Background(), id)
		require.ErrorIs(t, err, ErrNotFound, "удаление пользователя применено")
	})

	t.Run("новая запись с занятым идентификатором: оставить локальное", func(t *testing.T) {
		laptop, phone, _ := pair(t)

		id, err := laptop.client.Add(loginEntry("на сервере"))
		require.NoError(t, err)
		mustSync(t, laptop)

		phone.cache.Put(localstore.Record{ID: id, Pending: localstore.PendingCreate, Payload: []byte("x"), Kind: model.KindText})
		_, err = phone.client.Sync(context.Background())
		require.ErrorIs(t, err, ErrConflict)

		require.NoError(t, phone.client.Resolve(context.Background(), id, KeepLocal))

		rec, _ := phone.cache.Get(id)
		assert.Equal(t, localstore.PendingUpdate, rec.Pending, "создание превращается в изменение серверной записи")
		assert.Equal(t, int64(1), rec.Version)
	})
}

// conflictOnUpdate создаёт конфликт версий: ноутбук и телефон изменили одну
// запись, ноутбук успел отправить. Возвращает идентификатор записи и результат
// неудачной синхронизации телефона.
func conflictOnUpdate(t *testing.T, laptop, phone *device) (string, SyncResult) {
	t.Helper()

	id, err := laptop.client.Add(loginEntry("исходная"))
	require.NoError(t, err)
	mustSync(t, laptop)
	mustSync(t, phone)

	edit := loginEntry("с ноутбука")
	edit.ID = id
	require.NoError(t, laptop.client.Edit(edit))
	mustSync(t, laptop)

	edit.Name = "с телефона"
	require.NoError(t, phone.client.Edit(edit))

	res, err := phone.client.Sync(context.Background())
	require.ErrorIs(t, err, ErrConflict)

	return id, res
}

func TestResolve_Errors(t *testing.T) {
	laptop, phone, _ := pair(t)
	id, _ := conflictOnUpdate(t, laptop, phone)
	synced, err := laptop.client.Add(loginEntry("чистая"))
	require.NoError(t, err)
	mustSync(t, laptop)

	tests := []struct {
		err  error
		name string
		id   string
		keep Keep
	}{
		{name: "записи нет", id: "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11", keep: KeepLocal, err: ErrNotFound},
		{name: "нет изменений", id: synced, keep: KeepLocal, err: ErrNoPending},
		{name: "неизвестное решение", id: id, keep: 0},
		{name: "неизвестное решение (большое число)", id: id, keep: 99},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := laptop
			if tt.id == id {
				d = phone
			}

			err := d.client.Resolve(context.Background(), tt.id, tt.keep)
			require.Error(t, err)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			}
		})
	}
}

func TestResolve_NetworkError(t *testing.T) {
	laptop, phone, _ := pair(t)
	id, _ := conflictOnUpdate(t, laptop, phone)

	phone.remote.beforeCall = failOn("get", errNetwork)

	require.ErrorIs(t, phone.client.Resolve(context.Background(), id, KeepServer), errNetwork)

	rec, _ := phone.cache.Get(id)
	assert.Equal(t, localstore.PendingUpdate, rec.Pending, "при сбое сети конфликт остаётся нерешённым")
}
