package client

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/e-l-l-a-r/gophkeeper/internal/crypto"
	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
	"github.com/e-l-l-a-r/gophkeeper/internal/model"
)

// newRemoteClient создаёт клиента с кешем в каталоге dir поверх настоящего
// соединения conn. Мастер-ключи выводятся из password и соли сервера salt.
func newRemoteClient(t *testing.T, conn *Conn, dir string, password string, salt []byte) (*Client, *localstore.Cache) {
	t.Helper()

	store, err := localstore.Open(dir)
	require.NoError(t, err)
	cache, err := store.OpenCache("srv", "alice")
	require.NoError(t, err)
	keys, err := crypto.NewKeyring(password, salt, 5)
	require.NoError(t, err)

	return New(conn, cache, keys), cache
}

// TestEndToEnd_TwoDevicesOverGRPC проходит весь пользовательский путь из ТЗ
// через настоящие gRPC-соединения: регистрация на первом устройстве, вход на
// втором (с получением соли ключа шифрования от сервера), обмен записями и
// конфликт версий.
func TestEndToEnd_TwoDevicesOverGRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	lis := startListener(t)

	// Первое устройство: регистрация с новой солью ключа шифрования.
	laptopConn := connect(t, lis)
	salt, err := crypto.NewSalt()
	require.NoError(t, err)
	_, err = laptopConn.Register(ctx, "alice", "s3cretpass", salt)
	require.NoError(t, err)

	laptop, _ := newRemoteClient(t, laptopConn, filepath.Join(t.TempDir(), "laptop"), "master-password", salt)

	cardID, err := laptop.Add(model.Entry{
		Kind: model.KindCard, Name: "зарплатная", Meta: "банк",
		Card: &model.Card{Number: "4111 1111 1111 1111", Holder: "IVAN IVANOV", Expiry: "07/30", CVV: "123"},
	})
	require.NoError(t, err)
	loginID, err := laptop.Add(model.Entry{Kind: model.KindLoginPassword, Name: "почта", Login: "me", Password: "p@ss"})
	require.NoError(t, err)

	res, err := laptop.Sync(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, res.Pushed)

	// Второе устройство: вход, соль приходит с сервера, тот же мастер-пароль.
	phoneConn := connect(t, lis)
	login, err := phoneConn.Login(ctx, "alice", "s3cretpass")
	require.NoError(t, err)
	assert.Equal(t, salt, login.KDFSalt)

	phone, phoneCache := newRemoteClient(t, phoneConn, filepath.Join(t.TempDir(), "phone"), "master-password", login.KDFSalt)

	res, err = phone.Sync(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, res.Pulled)

	card, err := phone.Get(cardID)
	require.NoError(t, err)
	assert.Equal(t, "4111111111111111", card.Card.Number)
	assert.Equal(t, "банк", card.Meta)

	// Сервер хранит только шифротекст.
	secret, err := phoneConn.Get(ctx, cardID)
	require.NoError(t, err)
	assert.NotContains(t, string(secret.Payload), "4111")
	assert.NotContains(t, string(secret.Payload), "зарплатная")

	// Изменение на телефоне доходит до ноутбука.
	edit := model.Entry{ID: loginID, Kind: model.KindLoginPassword, Name: "почта (новая)", Login: "me", Password: "n3w"}
	require.NoError(t, phone.Edit(edit))
	_, err = phone.Sync(ctx)
	require.NoError(t, err)

	_, err = laptop.Sync(ctx)
	require.NoError(t, err)
	got, err := laptop.Get(loginID)
	require.NoError(t, err)
	assert.Equal(t, "n3w", got.Password)

	// Конфликт: оба меняют одну запись, ничего не затирается.
	edit.Name, edit.Password = "правка ноутбука", "from-laptop"
	require.NoError(t, laptop.Edit(edit))
	_, err = laptop.Sync(ctx)
	require.NoError(t, err)

	edit.Name, edit.Password = "правка телефона", "from-phone"
	require.NoError(t, phone.Edit(edit))

	res, err = phone.Sync(ctx)
	require.ErrorIs(t, err, ErrConflict)
	require.Len(t, res.Conflicts, 1)
	assert.Equal(t, ConflictVersion, res.Conflicts[0].Reason)

	// Пользователь оставляет серверную версию.
	require.NoError(t, phone.Resolve(ctx, loginID, KeepServer))
	got, err = phone.Get(loginID)
	require.NoError(t, err)
	assert.Equal(t, "from-laptop", got.Password)

	// Удаление на ноутбуке доходит до телефона.
	require.NoError(t, laptop.Remove(cardID))
	_, err = laptop.Sync(ctx)
	require.NoError(t, err)

	res, err = phone.Sync(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Removed)

	_, ok := phoneCache.Get(cardID)
	assert.False(t, ok)

	list, err := phone.List()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, loginID, list[0].ID)

	// Мастер-пароль, отличный от исходного, не открывает записи.
	thiefConn := connect(t, lis)
	_, err = thiefConn.Login(ctx, "alice", "s3cretpass")
	require.NoError(t, err)

	thief, _ := newRemoteClient(t, thiefConn, filepath.Join(t.TempDir(), "thief"), "wrong-master", salt)
	_, err = thief.Sync(ctx)
	require.NoError(t, err)

	_, err = thief.List()
	require.ErrorIs(t, err, crypto.ErrDecrypt, "знание пароля входа без мастер-пароля не раскрывает записи")
}
