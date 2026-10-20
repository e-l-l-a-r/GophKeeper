package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	secretID1 = "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11"
	secretID2 = "7a1f6c52-1c53-4a45-8d61-0a8f2b9e4c22"
)

// stepClock возвращает время, которое растёт на секунду при каждом обращении.
func stepClock() func() time.Time {
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	return func() time.Time {
		current = current.Add(time.Second)

		return current
	}
}

func newUser(login string) User {
	return User{
		Login:        login,
		PasswordHash: []byte("hash"),
		PasswordSalt: []byte("salt"),
		KDFSalt:      []byte("kdf"),
	}
}

func TestNewMemory(t *testing.T) {
	m := NewMemory()
	require.NotNil(t, m)

	user, err := m.CreateUser(context.Background(), newUser("alice"))
	require.NoError(t, err)
	assert.False(t, user.CreatedAt.IsZero())
}

func TestMemory_CreateUser(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryWithClock(stepClock())

	first, err := m.CreateUser(ctx, newUser("alice"))
	require.NoError(t, err)
	assert.Equal(t, int64(1), first.ID)
	assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC), first.CreatedAt)

	second, err := m.CreateUser(ctx, newUser("bob"))
	require.NoError(t, err)
	assert.Equal(t, int64(2), second.ID)

	_, err = m.CreateUser(ctx, newUser("alice"))
	require.ErrorIs(t, err, ErrUserExists)
}

func TestMemory_UserByLogin(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	created, err := m.CreateUser(ctx, newUser("alice"))
	require.NoError(t, err)

	tests := []struct {
		wantErr error
		name    string
		login   string
	}{
		{name: "существующий пользователь", login: "alice"},
		{name: "неизвестный пользователь", login: "carol", wantErr: ErrUserNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := m.UserByLogin(ctx, tt.login)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, created, got)
		})
	}
}

func TestMemory_UserIsolatedFromCallerChanges(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	input := newUser("alice")
	_, err := m.CreateUser(ctx, input)
	require.NoError(t, err)

	input.PasswordHash[0] = 'X'

	got, err := m.UserByLogin(ctx, "alice")
	require.NoError(t, err)
	got.KDFSalt[0] = 'Y'

	again, err := m.UserByLogin(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, []byte("hash"), again.PasswordHash)
	assert.Equal(t, []byte("kdf"), again.KDFSalt)
}

func TestMemory_CreateAndGetSecret(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryWithClock(stepClock())

	created, err := m.CreateSecret(ctx, 1, Secret{ID: secretID1, Type: 2, EncryptedPayload: []byte("cipher"), Version: 99, Deleted: true})
	require.NoError(t, err)
	assert.Equal(t, int64(1), created.Version, "версия новой записи всегда 1")
	assert.False(t, created.Deleted)
	assert.False(t, created.UpdatedAt.IsZero())

	got, err := m.GetSecret(ctx, 1, secretID1)
	require.NoError(t, err)
	assert.Equal(t, created, got)

	_, err = m.CreateSecret(ctx, 1, Secret{ID: secretID1, Type: 1})
	require.ErrorIs(t, err, ErrSecretExists)

	// тот же идентификатор у другого пользователя - другая запись
	_, err = m.CreateSecret(ctx, 2, Secret{ID: secretID1, Type: 1})
	require.NoError(t, err)

	// чужие записи недоступны
	_, err = m.GetSecret(ctx, 3, secretID1)
	require.ErrorIs(t, err, ErrSecretNotFound)
	_, err = m.GetSecret(ctx, 1, secretID2)
	require.ErrorIs(t, err, ErrSecretNotFound)
}

func TestMemory_SecretPayloadIsCopied(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	payload := []byte("cipher")
	_, err := m.CreateSecret(ctx, 1, Secret{ID: secretID1, Type: 1, EncryptedPayload: payload})
	require.NoError(t, err)

	payload[0] = 'X'

	got, err := m.GetSecret(ctx, 1, secretID1)
	require.NoError(t, err)
	assert.Equal(t, []byte("cipher"), got.EncryptedPayload)

	got.EncryptedPayload[0] = 'Y'

	again, err := m.GetSecret(ctx, 1, secretID1)
	require.NoError(t, err)
	assert.Equal(t, []byte("cipher"), again.EncryptedPayload)
}

func TestMemory_UpdateSecret(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryWithClock(stepClock())

	created, err := m.CreateSecret(ctx, 1, Secret{ID: secretID1, Type: 1, EncryptedPayload: []byte("v1")})
	require.NoError(t, err)

	_, err = m.CreateSecret(ctx, 1, Secret{ID: secretID2, Type: 1})
	require.NoError(t, err)
	require.NoError(t, m.DeleteSecret(ctx, 1, secretID2, 1))

	tests := []struct {
		wantErr error
		name    string
		id      string
		version int64
	}{
		{name: "успешное изменение", id: secretID1, version: 1},
		{name: "устаревшая версия", id: secretID1, version: 1, wantErr: ErrVersionConflict},
		{name: "версия из будущего", id: secretID1, version: 5, wantErr: ErrVersionConflict},
		{name: "запись удалена", id: secretID2, version: 2, wantErr: ErrSecretNotFound},
		{name: "записи нет", id: "unknown", version: 1, wantErr: ErrSecretNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := m.UpdateSecret(ctx, 1, Secret{ID: tt.id, Type: 3, EncryptedPayload: []byte("v2")}, tt.version)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, int64(2), got.Version)
			assert.Equal(t, int16(3), got.Type)
			assert.Equal(t, []byte("v2"), got.EncryptedPayload)
			assert.True(t, got.UpdatedAt.After(created.UpdatedAt))
		})
	}
}

func TestMemory_DeleteSecret(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	_, err := m.CreateSecret(ctx, 1, Secret{ID: secretID1, Type: 1, EncryptedPayload: []byte("cipher")})
	require.NoError(t, err)

	require.ErrorIs(t, m.DeleteSecret(ctx, 1, secretID1, 7), ErrVersionConflict)
	require.ErrorIs(t, m.DeleteSecret(ctx, 1, "unknown", 1), ErrSecretNotFound)
	require.NoError(t, m.DeleteSecret(ctx, 1, secretID1, 1))

	_, err = m.GetSecret(ctx, 1, secretID1)
	require.ErrorIs(t, err, ErrSecretNotFound)

	require.ErrorIs(t, m.DeleteSecret(ctx, 1, secretID1, 2), ErrSecretNotFound, "повторное удаление")

	_, err = m.CreateSecret(ctx, 1, Secret{ID: secretID1, Type: 1})
	require.ErrorIs(t, err, ErrSecretExists, "идентификатор удалённой записи занят")
}

func TestMemory_ListSecrets(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryWithClock(stepClock())

	empty, err := m.ListSecrets(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, empty)

	_, err = m.CreateSecret(ctx, 1, Secret{ID: secretID1, Type: 1, EncryptedPayload: []byte("a")})
	require.NoError(t, err)
	_, err = m.CreateSecret(ctx, 1, Secret{ID: secretID2, Type: 2, EncryptedPayload: []byte("b")})
	require.NoError(t, err)
	_, err = m.CreateSecret(ctx, 2, Secret{ID: "foreign", Type: 1})
	require.NoError(t, err)

	// порядок определяется временем последнего изменения: сначала изменяется
	// первая запись, затем удаляется вторая, поэтому вторая оказывается последней
	_, err = m.UpdateSecret(ctx, 1, Secret{ID: secretID1, Type: 1, EncryptedPayload: []byte("a2")}, 1)
	require.NoError(t, err)
	// удалённая запись остаётся в списке как «надгробие»
	require.NoError(t, m.DeleteSecret(ctx, 1, secretID2, 1))

	got, err := m.ListSecrets(ctx, 1)
	require.NoError(t, err)
	require.Len(t, got, 2, "чужие записи в список не попадают")

	assert.Equal(t, secretID1, got[0].ID)
	assert.False(t, got[0].Deleted)
	assert.Equal(t, []byte("a2"), got[0].EncryptedPayload)
	assert.Equal(t, int64(2), got[0].Version)

	assert.Equal(t, secretID2, got[1].ID)
	assert.True(t, got[1].Deleted)
	assert.Empty(t, got[1].EncryptedPayload)
	assert.Equal(t, int64(2), got[1].Version)
	assert.True(t, got[1].UpdatedAt.After(got[0].UpdatedAt))
}

func TestMemory_ListSecrets_SameTimestampOrderedByID(t *testing.T) {
	ctx := context.Background()
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := NewMemoryWithClock(func() time.Time { return fixed })

	for _, id := range []string{"c", "a", "b"} {
		_, err := m.CreateSecret(ctx, 1, Secret{ID: id, Type: 1})
		require.NoError(t, err)
	}

	got, err := m.ListSecrets(ctx, 1)
	require.NoError(t, err)

	ids := make([]string, 0, len(got))
	for _, s := range got {
		ids = append(ids, s.ID)
	}
	assert.Equal(t, []string{"a", "b", "c"}, ids)
}

func TestCompareStrings(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "меньше", a: "a", b: "b", want: -1},
		{name: "больше", a: "b", b: "a", want: 1},
		{name: "равны", a: "a", b: "a", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, compareStrings(tt.a, tt.b))
		})
	}
}

// TestMemory_ConcurrentUpdates проверяет оптимистичную блокировку под
// нагрузкой: из N одновременных изменений с одной и той же версией успешным
// должно быть ровно одно. Тест имеет смысл только с флагом -race.
func TestMemory_ConcurrentUpdates(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	_, err := m.CreateSecret(ctx, 1, Secret{ID: secretID1, Type: 1})
	require.NoError(t, err)

	const workers = 32

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		conflicts int
	)

	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, updateErr := m.UpdateSecret(ctx, 1, Secret{ID: secretID1, Type: 1, EncryptedPayload: []byte(fmt.Sprint(i))}, 1)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case updateErr == nil:
				succeeded++
			case errors.Is(updateErr, ErrVersionConflict):
				conflicts++
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, succeeded)
	assert.Equal(t, workers-1, conflicts)

	got, err := m.GetSecret(ctx, 1, secretID1)
	require.NoError(t, err)
	assert.Equal(t, int64(2), got.Version)
}
