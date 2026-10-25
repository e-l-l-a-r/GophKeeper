package service

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/e-l-l-a-r/gophkeeper/internal/auth"
	"github.com/e-l-l-a-r/gophkeeper/internal/logger"
	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
	"github.com/e-l-l-a-r/gophkeeper/internal/storage"
)

const (
	idA = "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11"
	idB = "7a1f6c52-1c53-4a45-8d61-0a8f2b9e4c22"
	idC = "c3d4e5f6-0000-4000-8000-000000000003"
)

// failingSecrets - хранилище записей, все методы которого возвращают err.
type failingSecrets struct{ err error }

func (f failingSecrets) CreateSecret(context.Context, int64, storage.Secret) (storage.Secret, error) {
	return storage.Secret{}, f.err
}

func (f failingSecrets) GetSecret(context.Context, int64, string) (storage.Secret, error) {
	return storage.Secret{}, f.err
}

func (f failingSecrets) UpdateSecret(context.Context, int64, storage.Secret, int64) (storage.Secret, error) {
	return storage.Secret{}, f.err
}

func (f failingSecrets) DeleteSecret(context.Context, int64, string, int64) error { return f.err }

func (f failingSecrets) ListSecrets(context.Context, int64) ([]storage.Secret, error) {
	return nil, f.err
}

func userCtx(userID int64) context.Context {
	return auth.ContextWithUserID(context.Background(), userID)
}

func newSecretsService(store storage.SecretStorage) *SecretsService {
	return NewSecretsService(store, logger.Nop())
}

func payload(s string) []byte { return []byte(s) }

func TestSecretsService_RequiresAuthentication(t *testing.T) {
	svc := newSecretsService(storage.NewMemory())
	ctx := context.Background()

	tests := []struct {
		call func() error
		name string
	}{
		{name: "Create", call: func() error {
			_, err := svc.Create(ctx, &pb.CreateSecretRequest{})
			return err
		}},
		{name: "Get", call: func() error {
			_, err := svc.Get(ctx, &pb.GetSecretRequest{})
			return err
		}},
		{name: "Update", call: func() error {
			_, err := svc.Update(ctx, &pb.UpdateSecretRequest{})
			return err
		}},
		{name: "Delete", call: func() error {
			_, err := svc.Delete(ctx, &pb.DeleteSecretRequest{})
			return err
		}},
		{name: "Sync", call: func() error {
			_, err := svc.Sync(ctx, &pb.SyncRequest{})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, codes.Unauthenticated, status.Code(tt.call()))
		})
	}
}

func TestSecretsService_Create(t *testing.T) {
	tooBig := bytes.Repeat([]byte{1}, pb.MaxPayloadSize+1)
	maxSize := bytes.Repeat([]byte{1}, pb.MaxPayloadSize)

	tests := []struct {
		req      *pb.CreateSecretRequest
		name     string
		wantID   string
		wantCode codes.Code
	}{
		{
			name:   "успех",
			req:    &pb.CreateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_LOGIN_PASSWORD, EncryptedPayload: payload("c")},
			wantID: idA,
		},
		{
			name:   "идентификатор приводится к нижнему регистру",
			req:    &pb.CreateSecretRequest{Id: strings.ToUpper(idA), Type: pb.SecretType_SECRET_TYPE_CARD, EncryptedPayload: payload("c")},
			wantID: idA,
		},
		{
			name:   "максимальный размер",
			req:    &pb.CreateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_BINARY, EncryptedPayload: maxSize},
			wantID: idA,
		},
		{name: "размер больше максимального", req: &pb.CreateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_BINARY, EncryptedPayload: tooBig}, wantCode: codes.InvalidArgument},
		{name: "пустое содержимое", req: &pb.CreateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT}, wantCode: codes.InvalidArgument},
		{name: "тип не задан", req: &pb.CreateSecretRequest{Id: idA, EncryptedPayload: payload("c")}, wantCode: codes.InvalidArgument},
		{name: "неизвестный тип", req: &pb.CreateSecretRequest{Id: idA, Type: 5, EncryptedPayload: payload("c")}, wantCode: codes.InvalidArgument},
		{name: "отрицательный тип", req: &pb.CreateSecretRequest{Id: idA, Type: -1, EncryptedPayload: payload("c")}, wantCode: codes.InvalidArgument},
		{name: "пустой идентификатор", req: &pb.CreateSecretRequest{Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("c")}, wantCode: codes.InvalidArgument},
		{name: "идентификатор не UUID", req: &pb.CreateSecretRequest{Id: "not-a-uuid", Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("c")}, wantCode: codes.InvalidArgument},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newSecretsService(storage.NewMemory())

			got, err := svc.Create(userCtx(1), tt.req)
			require.Equal(t, tt.wantCode, status.Code(err), "%v", err)
			if tt.wantCode != codes.OK {
				assert.Nil(t, got)
				return
			}

			assert.Equal(t, tt.wantID, got.GetId())
			assert.Equal(t, tt.req.GetType(), got.GetType())
			assert.Equal(t, int64(1), got.GetVersion())
			assert.Equal(t, tt.req.GetEncryptedPayload(), got.GetEncryptedPayload())
			assert.False(t, got.GetUpdatedAt().AsTime().IsZero())
		})
	}
}

func TestSecretsService_Create_Duplicate(t *testing.T) {
	svc := newSecretsService(storage.NewMemory())
	req := &pb.CreateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("c")}

	_, err := svc.Create(userCtx(1), req)
	require.NoError(t, err)

	_, err = svc.Create(userCtx(1), req)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))

	upper := &pb.CreateSecretRequest{Id: strings.ToUpper(idA), Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("c")}
	_, err = svc.Create(userCtx(1), upper)
	assert.Equal(t, codes.AlreadyExists, status.Code(err), "регистр идентификатора не создаёт новую запись")

	_, err = svc.Create(userCtx(2), req)
	assert.NoError(t, err, "тот же идентификатор у другого пользователя - другая запись")
}

func TestSecretsService_Get(t *testing.T) {
	svc := newSecretsService(storage.NewMemory())

	_, err := svc.Create(userCtx(1), &pb.CreateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("secret")})
	require.NoError(t, err)
	_, err = svc.Create(userCtx(1), &pb.CreateSecretRequest{Id: idB, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("gone")})
	require.NoError(t, err)
	_, err = svc.Delete(userCtx(1), &pb.DeleteSecretRequest{Id: idB, ExpectedVersion: 1})
	require.NoError(t, err)

	tests := []struct {
		name     string
		id       string
		userID   int64
		wantCode codes.Code
	}{
		{name: "своя запись", id: idA, userID: 1},
		{name: "идентификатор в верхнем регистре", id: strings.ToUpper(idA), userID: 1},
		{name: "чужая запись", id: idA, userID: 2, wantCode: codes.NotFound},
		{name: "записи нет", id: idC, userID: 1, wantCode: codes.NotFound},
		{name: "запись удалена", id: idB, userID: 1, wantCode: codes.NotFound},
		{name: "некорректный идентификатор", id: "x", userID: 1, wantCode: codes.InvalidArgument},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := svc.Get(userCtx(tt.userID), &pb.GetSecretRequest{Id: tt.id})
			require.Equal(t, tt.wantCode, status.Code(err), "%v", err)
			if tt.wantCode != codes.OK {
				assert.Nil(t, got)
				return
			}

			assert.Equal(t, idA, got.GetId())
			assert.Equal(t, payload("secret"), got.GetEncryptedPayload())
		})
	}
}

func TestSecretsService_Update(t *testing.T) {
	tests := []struct {
		req      *pb.UpdateSecretRequest
		name     string
		userID   int64
		wantCode codes.Code
	}{
		{
			name:   "успех",
			userID: 1,
			req:    &pb.UpdateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_CARD, EncryptedPayload: payload("new"), ExpectedVersion: 1},
		},
		{
			name:     "устаревшая версия",
			userID:   1,
			req:      &pb.UpdateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("new"), ExpectedVersion: 7},
			wantCode: codes.Aborted,
		},
		{
			name:     "чужая запись",
			userID:   2,
			req:      &pb.UpdateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("new"), ExpectedVersion: 1},
			wantCode: codes.NotFound,
		},
		{
			name:     "записи нет",
			userID:   1,
			req:      &pb.UpdateSecretRequest{Id: idC, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("new"), ExpectedVersion: 1},
			wantCode: codes.NotFound,
		},
		{
			name:     "нулевая ожидаемая версия",
			userID:   1,
			req:      &pb.UpdateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("new")},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "неизвестный тип",
			userID:   1,
			req:      &pb.UpdateSecretRequest{Id: idA, EncryptedPayload: payload("new"), ExpectedVersion: 1},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "пустое содержимое",
			userID:   1,
			req:      &pb.UpdateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, ExpectedVersion: 1},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "некорректный идентификатор",
			userID:   1,
			req:      &pb.UpdateSecretRequest{Id: "x", Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("new"), ExpectedVersion: 1},
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newSecretsService(storage.NewMemory())
			_, err := svc.Create(userCtx(1), &pb.CreateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("old")})
			require.NoError(t, err)

			got, err := svc.Update(userCtx(tt.userID), tt.req)
			require.Equal(t, tt.wantCode, status.Code(err), "%v", err)
			if tt.wantCode != codes.OK {
				assert.Nil(t, got)

				stored, getErr := svc.Get(userCtx(1), &pb.GetSecretRequest{Id: idA})
				require.NoError(t, getErr)
				assert.Equal(t, payload("old"), stored.GetEncryptedPayload(), "неудачное изменение не меняет запись")

				return
			}

			assert.Equal(t, int64(2), got.GetVersion())
			assert.Equal(t, pb.SecretType_SECRET_TYPE_CARD, got.GetType())
			assert.Equal(t, payload("new"), got.GetEncryptedPayload())
		})
	}
}

func TestSecretsService_Update_AfterDelete(t *testing.T) {
	svc := newSecretsService(storage.NewMemory())
	_, err := svc.Create(userCtx(1), &pb.CreateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("c")})
	require.NoError(t, err)
	_, err = svc.Delete(userCtx(1), &pb.DeleteSecretRequest{Id: idA, ExpectedVersion: 1})
	require.NoError(t, err)

	_, err = svc.Update(userCtx(1), &pb.UpdateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("n"), ExpectedVersion: 2})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSecretsService_Delete(t *testing.T) {
	tests := []struct {
		req      *pb.DeleteSecretRequest
		name     string
		userID   int64
		wantCode codes.Code
	}{
		{name: "успех", userID: 1, req: &pb.DeleteSecretRequest{Id: idA, ExpectedVersion: 1}},
		{name: "устаревшая версия", userID: 1, req: &pb.DeleteSecretRequest{Id: idA, ExpectedVersion: 9}, wantCode: codes.Aborted},
		{name: "чужая запись", userID: 2, req: &pb.DeleteSecretRequest{Id: idA, ExpectedVersion: 1}, wantCode: codes.NotFound},
		{name: "записи нет", userID: 1, req: &pb.DeleteSecretRequest{Id: idC, ExpectedVersion: 1}, wantCode: codes.NotFound},
		{name: "нулевая ожидаемая версия", userID: 1, req: &pb.DeleteSecretRequest{Id: idA}, wantCode: codes.InvalidArgument},
		{name: "некорректный идентификатор", userID: 1, req: &pb.DeleteSecretRequest{Id: "x", ExpectedVersion: 1}, wantCode: codes.InvalidArgument},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newSecretsService(storage.NewMemory())
			_, err := svc.Create(userCtx(1), &pb.CreateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("c")})
			require.NoError(t, err)

			got, err := svc.Delete(userCtx(tt.userID), tt.req)
			require.Equal(t, tt.wantCode, status.Code(err), "%v", err)

			_, getErr := svc.Get(userCtx(1), &pb.GetSecretRequest{Id: idA})
			if tt.wantCode != codes.OK {
				assert.Nil(t, got)
				assert.NoError(t, getErr, "неудачное удаление не трогает запись")

				return
			}

			assert.NotNil(t, got)
			assert.Equal(t, codes.NotFound, status.Code(getErr))
		})
	}
}

func TestSecretsService_Delete_Twice(t *testing.T) {
	svc := newSecretsService(storage.NewMemory())
	_, err := svc.Create(userCtx(1), &pb.CreateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("c")})
	require.NoError(t, err)

	_, err = svc.Delete(userCtx(1), &pb.DeleteSecretRequest{Id: idA, ExpectedVersion: 1})
	require.NoError(t, err)

	_, err = svc.Delete(userCtx(1), &pb.DeleteSecretRequest{Id: idA, ExpectedVersion: 2})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSecretsService_Sync(t *testing.T) {
	svc := newSecretsService(storage.NewMemory())
	ctx := userCtx(1)

	for _, id := range []string{idA, idB} {
		_, err := svc.Create(ctx, &pb.CreateSecretRequest{Id: id, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("v1")})
		require.NoError(t, err)
	}
	_, err := svc.Create(userCtx(2), &pb.CreateSecretRequest{Id: idC, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("foreign")})
	require.NoError(t, err)

	ids := func(resp *pb.SyncResponse) []string {
		out := make([]string, 0, len(resp.GetChanged()))
		for _, s := range resp.GetChanged() {
			out = append(out, s.GetId())
		}

		return out
	}

	t.Run("новый клиент получает все записи, но не чужие", func(t *testing.T) {
		resp, syncErr := svc.Sync(ctx, &pb.SyncRequest{})
		require.NoError(t, syncErr)
		assert.ElementsMatch(t, []string{idA, idB}, ids(resp))
		assert.Empty(t, resp.GetDeletedIds())
	})

	t.Run("актуальный клиент ничего не получает", func(t *testing.T) {
		resp, syncErr := svc.Sync(ctx, &pb.SyncRequest{Known: []*pb.SecretVersion{{Id: idA, Version: 1}, {Id: idB, Version: 1}}})
		require.NoError(t, syncErr)
		assert.Empty(t, resp.GetChanged())
		assert.Empty(t, resp.GetDeletedIds())
	})

	t.Run("идентификаторы в верхнем регистре распознаются", func(t *testing.T) {
		resp, syncErr := svc.Sync(ctx, &pb.SyncRequest{Known: []*pb.SecretVersion{{Id: strings.ToUpper(idA), Version: 1}, {Id: idB, Version: 1}}})
		require.NoError(t, syncErr)
		assert.Empty(t, resp.GetChanged())
	})

	_, err = svc.Update(ctx, &pb.UpdateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("v2"), ExpectedVersion: 1})
	require.NoError(t, err)
	_, err = svc.Delete(ctx, &pb.DeleteSecretRequest{Id: idB, ExpectedVersion: 1})
	require.NoError(t, err)

	t.Run("изменённая и удалённая записи", func(t *testing.T) {
		resp, syncErr := svc.Sync(ctx, &pb.SyncRequest{Known: []*pb.SecretVersion{{Id: idA, Version: 1}, {Id: idB, Version: 1}}})
		require.NoError(t, syncErr)

		require.Len(t, resp.GetChanged(), 1)
		assert.Equal(t, idA, resp.GetChanged()[0].GetId())
		assert.Equal(t, int64(2), resp.GetChanged()[0].GetVersion())
		assert.Equal(t, payload("v2"), resp.GetChanged()[0].GetEncryptedPayload())
		assert.Equal(t, []string{idB}, resp.GetDeletedIds())
	})

	t.Run("удалённую запись, которой клиент не знал, не сообщаем", func(t *testing.T) {
		resp, syncErr := svc.Sync(ctx, &pb.SyncRequest{})
		require.NoError(t, syncErr)
		assert.Equal(t, []string{idA}, ids(resp))
		assert.Empty(t, resp.GetDeletedIds())
	})

	t.Run("клиент с более новой версией ничего не получает", func(t *testing.T) {
		resp, syncErr := svc.Sync(ctx, &pb.SyncRequest{Known: []*pb.SecretVersion{{Id: idA, Version: 9}}})
		require.NoError(t, syncErr)
		assert.Empty(t, resp.GetChanged())
	})

	t.Run("неизвестные серверу записи игнорируются", func(t *testing.T) {
		resp, syncErr := svc.Sync(ctx, &pb.SyncRequest{Known: []*pb.SecretVersion{{Id: idC, Version: 1}}})
		require.NoError(t, syncErr)
		assert.Equal(t, []string{idA}, ids(resp))
		assert.Empty(t, resp.GetDeletedIds())
	})

	t.Run("после синхронизации клиент актуален", func(t *testing.T) {
		resp, syncErr := svc.Sync(ctx, &pb.SyncRequest{Known: []*pb.SecretVersion{{Id: idA, Version: 2}}})
		require.NoError(t, syncErr)
		assert.Empty(t, resp.GetChanged())
		assert.Empty(t, resp.GetDeletedIds())
	})
}

func TestSecretsService_Sync_InvalidKnown(t *testing.T) {
	svc := newSecretsService(storage.NewMemory())

	tests := []struct {
		name  string
		known []*pb.SecretVersion
	}{
		{name: "некорректный идентификатор", known: []*pb.SecretVersion{{Id: "x", Version: 1}}},
		{name: "нулевая версия", known: []*pb.SecretVersion{{Id: idA}}},
		{name: "отрицательная версия", known: []*pb.SecretVersion{{Id: idA, Version: -3}}},
		{name: "повтор идентификатора", known: []*pb.SecretVersion{{Id: idA, Version: 1}, {Id: strings.ToUpper(idA), Version: 2}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.Sync(userCtx(1), &pb.SyncRequest{Known: tt.known})
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Nil(t, resp)
		})
	}
}

func TestSecretsService_StorageErrorsAreHidden(t *testing.T) {
	svc := newSecretsService(failingSecrets{err: errStorage})
	ctx := userCtx(1)

	tests := []struct {
		call func() error
		name string
	}{
		{name: "Create", call: func() error {
			_, err := svc.Create(ctx, &pb.CreateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("c")})
			return err
		}},
		{name: "Get", call: func() error {
			_, err := svc.Get(ctx, &pb.GetSecretRequest{Id: idA})
			return err
		}},
		{name: "Update", call: func() error {
			_, err := svc.Update(ctx, &pb.UpdateSecretRequest{Id: idA, Type: pb.SecretType_SECRET_TYPE_TEXT, EncryptedPayload: payload("c"), ExpectedVersion: 1})
			return err
		}},
		{name: "Delete", call: func() error {
			_, err := svc.Delete(ctx, &pb.DeleteSecretRequest{Id: idA, ExpectedVersion: 1})
			return err
		}},
		{name: "Sync", call: func() error {
			_, err := svc.Sync(ctx, &pb.SyncRequest{})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			assert.Equal(t, codes.Internal, status.Code(err))
			assert.NotContains(t, err.Error(), errStorage.Error(), "детали сбоя не должны уходить клиенту")
		})
	}
}

func TestDiffSecrets(t *testing.T) {
	live := func(id string, version int64) storage.Secret { return storage.Secret{ID: id, Version: version} }
	dead := func(id string, version int64) storage.Secret {
		return storage.Secret{ID: id, Version: version, Deleted: true}
	}

	tests := []struct {
		known       map[string]int64
		name        string
		server      []storage.Secret
		wantChanged []string
		wantDeleted []string
	}{
		{name: "пусто"},
		{
			name:        "клиент ничего не знает",
			server:      []storage.Secret{live("a", 1), dead("b", 2), live("c", 3)},
			wantChanged: []string{"a", "c"},
		},
		{
			name:        "версия на сервере новее",
			server:      []storage.Secret{live("a", 3)},
			known:       map[string]int64{"a": 2},
			wantChanged: []string{"a"},
		},
		{
			name:   "версии равны",
			server: []storage.Secret{live("a", 2)},
			known:  map[string]int64{"a": 2},
		},
		{
			name:   "версия клиента новее",
			server: []storage.Secret{live("a", 2)},
			known:  map[string]int64{"a": 5},
		},
		{
			name:        "удалённая известная запись",
			server:      []storage.Secret{dead("a", 4)},
			known:       map[string]int64{"a": 3},
			wantDeleted: []string{"a"},
		},
		{
			name:   "удалённая неизвестная запись",
			server: []storage.Secret{dead("a", 4)},
		},
		{
			name:        "порядок сохраняется",
			server:      []storage.Secret{live("z", 1), dead("y", 2), live("x", 1), dead("w", 2)},
			known:       map[string]int64{"y": 1, "w": 1},
			wantChanged: []string{"z", "x"},
			wantDeleted: []string{"y", "w"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed, deleted := diffSecrets(tt.server, tt.known)

			gotChanged := make([]string, 0, len(changed))
			for _, s := range changed {
				gotChanged = append(gotChanged, s.ID)
			}

			assert.ElementsMatch(t, tt.wantChanged, gotChanged)
			assert.ElementsMatch(t, tt.wantDeleted, deleted)
			if len(tt.wantChanged) > 1 {
				assert.Equal(t, tt.wantChanged, gotChanged, "порядок записей сохраняется")
			}
			if len(tt.wantDeleted) > 1 {
				assert.Equal(t, tt.wantDeleted, deleted, "порядок удалений сохраняется")
			}
		})
	}
}

func TestValidateSecretID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		want    string
		wantErr bool
	}{
		{name: "UUID в нижнем регистре", id: idA, want: idA},
		{name: "UUID в верхнем регистре", id: strings.ToUpper(idA), want: idA},
		{name: "UUID в смешанном регистре", id: "0B9d0a43-6A2f-4c3c-9D57-6a1b3f6a8b11", want: idA},
		{name: "пустая строка", id: "", wantErr: true},
		{name: "без дефисов", id: strings.ReplaceAll(idA, "-", ""), wantErr: true},
		{name: "в фигурных скобках", id: "{" + idA + "}", wantErr: true},
		{name: "дефис не на месте", id: "0b9d0a436-a2f-4c3c-9d57-6a1b3f6a8b11", wantErr: true},
		{name: "не шестнадцатеричный символ", id: "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b1g", wantErr: true},
		{name: "слишком длинный", id: idA + "0", wantErr: true},
		{name: "слишком короткий", id: idA[:35], wantErr: true},
		{name: "юникод той же длины", id: strings.Repeat("я", 18), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateSecretID(tt.id)
			if tt.wantErr {
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				assert.Empty(t, got)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSecretToProto(t *testing.T) {
	updated := time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)

	got := secretToProto(storage.Secret{
		UpdatedAt:        updated,
		ID:               idA,
		EncryptedPayload: payload("c"),
		Version:          4,
		Type:             int16(pb.SecretType_SECRET_TYPE_CARD),
	})

	assert.Equal(t, idA, got.GetId())
	assert.Equal(t, pb.SecretType_SECRET_TYPE_CARD, got.GetType())
	assert.Equal(t, payload("c"), got.GetEncryptedPayload())
	assert.Equal(t, int64(4), got.GetVersion())
	assert.Equal(t, updated, got.GetUpdatedAt().AsTime())
}
