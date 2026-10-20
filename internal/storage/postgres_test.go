package storage

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errBoom    = errors.New("сбой базы данных")
	uniqueErr  = &pgconn.PgError{Code: pgerrcode.UniqueViolation}
	otherPgErr = &pgconn.PgError{Code: pgerrcode.SerializationFailure}
	testTime   = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
)

// newFakePostgres создаёт Postgres поверх поддельной базы, отвечающей по handler.
func newFakePostgres(handler fakeHandler) (*Postgres, *fakeDB) {
	db := &fakeDB{handler: handler}

	return NewPostgresFromDB(db.open()), db
}

// byQuery строит handler, который отвечает на запросы по таблице ответов;
// неизвестный запрос приводит к ошибке, что ловит опечатки в тестах.
func byQuery(responses map[string]fakeResponse) fakeHandler {
	return func(query string, _ []driver.NamedValue) fakeResponse {
		if resp, ok := responses[query]; ok {
			return resp
		}

		return fakeResponse{err: errors.New("неожиданный запрос: " + query)}
	}
}

// TestNewPostgres_DSNValidatedLazily фиксирует поведение драйвера pgx:
// sql.Open не разбирает строку подключения, поэтому NewPostgres не возвращает
// ошибку для некорректной строки, а сбой проявляется при первом обращении к базе.
func TestNewPostgres_DSNValidatedLazily(t *testing.T) {
	tests := []struct {
		name string
		dsn  string
	}{
		{name: "корректная строка подключения", dsn: "postgres://user:pass@127.0.0.1:1/db?sslmode=disable&connect_timeout=1"},
		{name: "некорректный порт", dsn: "postgres://user:pass@localhost:port/db"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewPostgres(tt.dsn)
			require.NoError(t, err)
			require.NotNil(t, p)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			require.Error(t, p.Ping(ctx), "база по этому адресу недоступна")
			require.NoError(t, p.Close())
		})
	}
}

func TestPostgres_PingAndClose(t *testing.T) {
	t.Run("база доступна", func(t *testing.T) {
		p, _ := newFakePostgres(byQuery(nil))
		require.NoError(t, p.Ping(context.Background()))
		require.NoError(t, p.Close())
	})

	t.Run("база недоступна", func(t *testing.T) {
		p := NewPostgresFromDB((&fakeDB{handler: byQuery(nil)}).open())
		require.NoError(t, p.Close())
		require.Error(t, p.Ping(context.Background()))
	})
}

func TestPostgres_Migrate_ConnectionError(t *testing.T) {
	p, db := newFakePostgres(func(string, []driver.NamedValue) fakeResponse {
		return fakeResponse{err: errBoom}
	})

	// golang-migrate не оборачивает исходную ошибку через %w, поэтому
	// проверяется текст, а не цепочка ошибок
	err := p.Migrate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), errBoom.Error())
	assert.NotEmpty(t, db.executed(), "мигратор должен был обратиться к базе")
}

func TestPostgres_CreateUser(t *testing.T) {
	tests := []struct {
		wantErr error
		name    string
		resp    fakeResponse
		wantID  int64
	}{
		{
			name:   "успех",
			resp:   fakeResponse{cols: []string{"id", "created_at"}, rows: [][]driver.Value{{int64(7), testTime}}},
			wantID: 7,
		},
		{name: "логин занят", resp: fakeResponse{err: uniqueErr}, wantErr: ErrUserExists},
		{name: "другая ошибка PostgreSQL", resp: fakeResponse{err: otherPgErr}, wantErr: otherPgErr},
		{name: "сбой базы", resp: fakeResponse{err: errBoom}, wantErr: errBoom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, db := newFakePostgres(byQuery(map[string]fakeResponse{queryCreateUser: tt.resp}))

			got, err := p.CreateUser(context.Background(), newUser("alice"))
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.NotErrorIs(t, err, ErrUserNotFound)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantID, got.ID)
			assert.Equal(t, testTime, got.CreatedAt)
			assert.Equal(t, "alice", got.Login)

			require.Len(t, db.args, 1)
			assert.Equal(t, "alice", db.args[0][0].Value)
		})
	}
}

func TestPostgres_CreateUser_OtherErrorIsNotUserExists(t *testing.T) {
	p, _ := newFakePostgres(byQuery(map[string]fakeResponse{queryCreateUser: {err: otherPgErr}}))

	_, err := p.CreateUser(context.Background(), newUser("alice"))
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrUserExists)
}

func TestPostgres_UserByLogin(t *testing.T) {
	cols := []string{"id", "login", "password_hash", "password_salt", "kdf_salt", "created_at"}

	tests := []struct {
		wantErr error
		name    string
		resp    fakeResponse
	}{
		{
			name: "найден",
			resp: fakeResponse{cols: cols, rows: [][]driver.Value{{int64(3), "alice", []byte("h"), []byte("s"), []byte("k"), testTime}}},
		},
		{name: "не найден", resp: fakeResponse{cols: cols}, wantErr: ErrUserNotFound},
		{name: "сбой базы", resp: fakeResponse{err: errBoom}, wantErr: errBoom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newFakePostgres(byQuery(map[string]fakeResponse{queryUserByLogin: tt.resp}))

			got, err := p.UserByLogin(context.Background(), "alice")
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, User{
				CreatedAt:    testTime,
				Login:        "alice",
				PasswordHash: []byte("h"),
				PasswordSalt: []byte("s"),
				KDFSalt:      []byte("k"),
				ID:           3,
			}, got)
		})
	}
}

func TestPostgres_CreateSecret(t *testing.T) {
	tests := []struct {
		wantErr error
		name    string
		resp    fakeResponse
	}{
		{
			name: "успех",
			resp: fakeResponse{cols: []string{"version", "updated_at"}, rows: [][]driver.Value{{int64(1), testTime}}},
		},
		{name: "идентификатор занят", resp: fakeResponse{err: uniqueErr}, wantErr: ErrSecretExists},
		{name: "сбой базы", resp: fakeResponse{err: errBoom}, wantErr: errBoom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newFakePostgres(byQuery(map[string]fakeResponse{queryCreateSecret: tt.resp}))

			got, err := p.CreateSecret(context.Background(), 1, Secret{ID: secretID1, Type: 2, EncryptedPayload: []byte("c"), Deleted: true})
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, int64(1), got.Version)
			assert.Equal(t, testTime, got.UpdatedAt)
			assert.False(t, got.Deleted)
		})
	}
}

func TestPostgres_GetSecret(t *testing.T) {
	cols := []string{"id", "type", "encrypted_payload", "version", "updated_at"}

	tests := []struct {
		wantErr error
		name    string
		resp    fakeResponse
	}{
		{
			name: "найдена",
			resp: fakeResponse{cols: cols, rows: [][]driver.Value{{secretID1, int64(2), []byte("c"), int64(4), testTime}}},
		},
		{name: "не найдена", resp: fakeResponse{cols: cols}, wantErr: ErrSecretNotFound},
		{name: "сбой базы", resp: fakeResponse{err: errBoom}, wantErr: errBoom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newFakePostgres(byQuery(map[string]fakeResponse{queryGetSecret: tt.resp}))

			got, err := p.GetSecret(context.Background(), 1, secretID1)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, Secret{
				UpdatedAt:        testTime,
				ID:               secretID1,
				EncryptedPayload: []byte("c"),
				Version:          4,
				Type:             2,
			}, got)
		})
	}
}

// missCases описывает ответ на проверочный запрос состояния записи после
// «пустого» UPDATE и ожидаемую по нему ошибку.
var missCases = []struct {
	wantErr error
	name    string
	state   fakeResponse
}{
	{
		name:    "записи нет",
		state:   fakeResponse{cols: []string{"deleted"}},
		wantErr: ErrSecretNotFound,
	},
	{
		name:    "запись удалена",
		state:   fakeResponse{cols: []string{"deleted"}, rows: [][]driver.Value{{true}}},
		wantErr: ErrSecretNotFound,
	},
	{
		name:    "версия не совпала",
		state:   fakeResponse{cols: []string{"deleted"}, rows: [][]driver.Value{{false}}},
		wantErr: ErrVersionConflict,
	},
	{
		name:    "сбой при проверке состояния",
		state:   fakeResponse{err: errBoom},
		wantErr: errBoom,
	},
}

func TestPostgres_UpdateSecret(t *testing.T) {
	updateCols := []string{"version", "updated_at"}

	t.Run("успех", func(t *testing.T) {
		p, db := newFakePostgres(byQuery(map[string]fakeResponse{
			queryUpdateSecret: {cols: updateCols, rows: [][]driver.Value{{int64(5), testTime}}},
		}))

		got, err := p.UpdateSecret(context.Background(), 1, Secret{ID: secretID1, Type: 3, EncryptedPayload: []byte("n")}, 4)
		require.NoError(t, err)
		assert.Equal(t, int64(5), got.Version)
		assert.Equal(t, testTime, got.UpdatedAt)
		assert.Equal(t, []string{queryUpdateSecret}, db.executed())
		assert.Equal(t, int64(4), db.args[0][4].Value, "ожидаемая версия передаётся последним аргументом")
	})

	t.Run("сбой базы при обновлении", func(t *testing.T) {
		p, _ := newFakePostgres(byQuery(map[string]fakeResponse{queryUpdateSecret: {err: errBoom}}))

		_, err := p.UpdateSecret(context.Background(), 1, Secret{ID: secretID1, Type: 3}, 1)
		require.ErrorIs(t, err, errBoom)
	})

	for _, tt := range missCases {
		t.Run(tt.name, func(t *testing.T) {
			p, db := newFakePostgres(byQuery(map[string]fakeResponse{
				queryUpdateSecret: {cols: updateCols},
				querySecretState:  tt.state,
			}))

			_, err := p.UpdateSecret(context.Background(), 1, Secret{ID: secretID1, Type: 3}, 1)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, []string{queryUpdateSecret, querySecretState}, db.executed())
		})
	}
}

func TestPostgres_DeleteSecret(t *testing.T) {
	deleteCols := []string{"version"}

	t.Run("успех", func(t *testing.T) {
		p, db := newFakePostgres(byQuery(map[string]fakeResponse{
			queryDeleteSecret: {cols: deleteCols, rows: [][]driver.Value{{int64(3)}}},
		}))

		require.NoError(t, p.DeleteSecret(context.Background(), 1, secretID1, 2))
		assert.Equal(t, []string{queryDeleteSecret}, db.executed())
	})

	t.Run("сбой базы при удалении", func(t *testing.T) {
		p, _ := newFakePostgres(byQuery(map[string]fakeResponse{queryDeleteSecret: {err: errBoom}}))

		require.ErrorIs(t, p.DeleteSecret(context.Background(), 1, secretID1, 2), errBoom)
	})

	for _, tt := range missCases {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newFakePostgres(byQuery(map[string]fakeResponse{
				queryDeleteSecret: {cols: deleteCols},
				querySecretState:  tt.state,
			}))

			require.ErrorIs(t, p.DeleteSecret(context.Background(), 1, secretID1, 2), tt.wantErr)
		})
	}
}

func TestPostgres_ListSecrets(t *testing.T) {
	cols := []string{"id", "type", "encrypted_payload", "version", "updated_at", "deleted"}

	t.Run("несколько записей", func(t *testing.T) {
		p, _ := newFakePostgres(byQuery(map[string]fakeResponse{
			queryListSecrets: {cols: cols, rows: [][]driver.Value{
				{secretID1, int64(1), []byte("a"), int64(1), testTime, false},
				{secretID2, int64(2), []byte{}, int64(3), testTime, true},
			}},
		}))

		got, err := p.ListSecrets(context.Background(), 1)
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, secretID1, got[0].ID)
		assert.False(t, got[0].Deleted)
		assert.Equal(t, secretID2, got[1].ID)
		assert.True(t, got[1].Deleted)
		assert.Equal(t, int64(3), got[1].Version)
	})

	t.Run("записей нет", func(t *testing.T) {
		p, _ := newFakePostgres(byQuery(map[string]fakeResponse{queryListSecrets: {cols: cols}}))

		got, err := p.ListSecrets(context.Background(), 1)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("сбой запроса", func(t *testing.T) {
		p, _ := newFakePostgres(byQuery(map[string]fakeResponse{queryListSecrets: {err: errBoom}}))

		_, err := p.ListSecrets(context.Background(), 1)
		require.ErrorIs(t, err, errBoom)
	})

	t.Run("ошибка чтения строки", func(t *testing.T) {
		p, _ := newFakePostgres(byQuery(map[string]fakeResponse{
			queryListSecrets: {cols: cols, rows: [][]driver.Value{
				{secretID1, "не число", []byte("a"), int64(1), testTime, false},
			}},
		}))

		_, err := p.ListSecrets(context.Background(), 1)
		require.Error(t, err)
	})
}

func TestIsUniqueViolation(t *testing.T) {
	tests := []struct {
		err  error
		name string
		want bool
	}{
		{name: "нарушение уникальности", err: uniqueErr, want: true},
		{name: "обёрнутое нарушение уникальности", err: errors.Join(errBoom, uniqueErr), want: true},
		{name: "другая ошибка PostgreSQL", err: otherPgErr},
		{name: "обычная ошибка", err: errBoom},
		{name: "нет ошибки"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isUniqueViolation(tt.err))
		})
	}
}

func TestNonNil(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want []byte
	}{
		{name: "nil заменяется пустым срезом", want: []byte{}},
		{name: "пустой срез остаётся", in: []byte{}, want: []byte{}},
		{name: "данные не меняются", in: []byte("abc"), want: []byte("abc")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nonNil(tt.in)
			assert.NotNil(t, got)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestPostgres_NilPayloadIsSentAsEmptyBytes проверяет, что запись без
// шифротекста уходит в базу пустым значением, а не NULL.
func TestPostgres_NilPayloadIsSentAsEmptyBytes(t *testing.T) {
	p, db := newFakePostgres(byQuery(map[string]fakeResponse{
		queryCreateSecret: {cols: []string{"version", "updated_at"}, rows: [][]driver.Value{{int64(1), testTime}}},
		queryUpdateSecret: {cols: []string{"version", "updated_at"}, rows: [][]driver.Value{{int64(2), testTime}}},
	}))

	_, err := p.CreateSecret(context.Background(), 1, Secret{ID: secretID1, Type: 1})
	require.NoError(t, err)
	_, err = p.UpdateSecret(context.Background(), 1, Secret{ID: secretID1, Type: 1}, 1)
	require.NoError(t, err)

	require.Len(t, db.args, 2)
	assert.Equal(t, []byte{}, db.args[0][3].Value)
	assert.Equal(t, []byte{}, db.args[1][3].Value)
}
