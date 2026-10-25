package service

import (
	"bytes"
	"context"
	"errors"
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

var (
	errStorage = errors.New("сбой хранилища")
	kdfSalt    = bytes.Repeat([]byte{0x07}, 16)
)

// failingUsers - хранилище пользователей, возвращающее заданную ошибку.
type failingUsers struct{ err error }

func (f failingUsers) CreateUser(context.Context, storage.User) (storage.User, error) {
	return storage.User{}, f.err
}

func (f failingUsers) UserByLogin(context.Context, string) (storage.User, error) {
	return storage.User{}, f.err
}

func newAuthService(t *testing.T, users storage.UserStorage) (*AuthService, *auth.TokenManager) {
	t.Helper()

	hasher, err := auth.NewPasswordHasher(10)
	require.NoError(t, err)
	tokens, err := auth.NewTokenManager(bytes.Repeat([]byte{0x01}, auth.MinTokenKeySize), time.Hour)
	require.NoError(t, err)

	svc, err := NewAuthService(users, hasher, tokens, logger.Nop())
	require.NoError(t, err)

	return svc, tokens
}

func TestAuthService_Register(t *testing.T) {
	tests := []struct {
		req      *pb.RegisterRequest
		name     string
		wantCode codes.Code
	}{
		{name: "успех", req: &pb.RegisterRequest{Login: "alice", Password: "s3cretpass", KdfSalt: kdfSalt}},
		{name: "логин с юникодом", req: &pb.RegisterRequest{Login: "алиса", Password: "s3cretpass", KdfSalt: kdfSalt}},
		{name: "короткий логин", req: &pb.RegisterRequest{Login: "ab", Password: "s3cretpass", KdfSalt: kdfSalt}, wantCode: codes.InvalidArgument},
		{name: "длинный логин", req: &pb.RegisterRequest{Login: strings.Repeat("a", 65), Password: "s3cretpass", KdfSalt: kdfSalt}, wantCode: codes.InvalidArgument},
		{name: "пробел в логине", req: &pb.RegisterRequest{Login: "al ice", Password: "s3cretpass", KdfSalt: kdfSalt}, wantCode: codes.InvalidArgument},
		{name: "управляющий символ в логине", req: &pb.RegisterRequest{Login: "ali\x00ce", Password: "s3cretpass", KdfSalt: kdfSalt}, wantCode: codes.InvalidArgument},
		{name: "некорректный UTF-8 в логине", req: &pb.RegisterRequest{Login: "ali\xffce", Password: "s3cretpass", KdfSalt: kdfSalt}, wantCode: codes.InvalidArgument},
		{name: "короткий пароль", req: &pb.RegisterRequest{Login: "alice", Password: "short", KdfSalt: kdfSalt}, wantCode: codes.InvalidArgument},
		{name: "слишком длинный пароль", req: &pb.RegisterRequest{Login: "alice", Password: strings.Repeat("p", 129), KdfSalt: kdfSalt}, wantCode: codes.InvalidArgument},
		{name: "нет соли", req: &pb.RegisterRequest{Login: "alice", Password: "s3cretpass"}, wantCode: codes.InvalidArgument},
		{name: "короткая соль", req: &pb.RegisterRequest{Login: "alice", Password: "s3cretpass", KdfSalt: []byte{1, 2, 3}}, wantCode: codes.InvalidArgument},
		{name: "слишком длинная соль", req: &pb.RegisterRequest{Login: "alice", Password: "s3cretpass", KdfSalt: make([]byte, 65)}, wantCode: codes.InvalidArgument},
		{name: "пустой запрос", req: &pb.RegisterRequest{}, wantCode: codes.InvalidArgument},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, tokens := newAuthService(t, storage.NewMemory())

			resp, err := svc.Register(context.Background(), tt.req)
			require.Equal(t, tt.wantCode, status.Code(err), "%v", err)
			if tt.wantCode != codes.OK {
				assert.Nil(t, resp)
				return
			}

			userID, err := tokens.Parse(resp.GetToken())
			require.NoError(t, err, "выданный токен должен проходить проверку")
			assert.Positive(t, userID)
			assert.Equal(t, kdfSalt, resp.GetKdfSalt())
			assert.True(t, resp.GetExpiresAt().AsTime().After(time.Now()))
		})
	}
}

func TestAuthService_Register_DuplicateLogin(t *testing.T) {
	svc, _ := newAuthService(t, storage.NewMemory())
	req := &pb.RegisterRequest{Login: "alice", Password: "s3cretpass", KdfSalt: kdfSalt}

	_, err := svc.Register(context.Background(), req)
	require.NoError(t, err)

	resp, err := svc.Register(context.Background(), req)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
	assert.Nil(t, resp)
}

func TestAuthService_Register_StoresHashNotPassword(t *testing.T) {
	users := storage.NewMemory()
	svc, _ := newAuthService(t, users)

	_, err := svc.Register(context.Background(), &pb.RegisterRequest{Login: "alice", Password: "s3cretpass", KdfSalt: kdfSalt})
	require.NoError(t, err)

	user, err := users.UserByLogin(context.Background(), "alice")
	require.NoError(t, err)
	assert.NotContains(t, string(user.PasswordHash), "s3cretpass")
	assert.NotEmpty(t, user.PasswordSalt)
	assert.Equal(t, kdfSalt, user.KDFSalt)
}

func TestAuthService_Register_StorageError(t *testing.T) {
	svc, _ := newAuthService(t, failingUsers{err: errStorage})

	resp, err := svc.Register(context.Background(), &pb.RegisterRequest{Login: "alice", Password: "s3cretpass", KdfSalt: kdfSalt})
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.NotContains(t, err.Error(), errStorage.Error(), "детали ошибки не должны уходить клиенту")
	assert.Nil(t, resp)
}

func TestAuthService_Login(t *testing.T) {
	tests := []struct {
		req      *pb.LoginRequest
		name     string
		wantCode codes.Code
	}{
		{name: "верные данные", req: &pb.LoginRequest{Login: "alice", Password: "s3cretpass"}},
		{name: "неверный пароль", req: &pb.LoginRequest{Login: "alice", Password: "wrongpass1"}, wantCode: codes.Unauthenticated},
		{name: "неизвестный логин", req: &pb.LoginRequest{Login: "bob", Password: "s3cretpass"}, wantCode: codes.Unauthenticated},
		{name: "логин другого регистра", req: &pb.LoginRequest{Login: "ALICE", Password: "s3cretpass"}, wantCode: codes.Unauthenticated},
		{name: "пустой логин", req: &pb.LoginRequest{Password: "s3cretpass"}, wantCode: codes.InvalidArgument},
		{name: "пустой пароль", req: &pb.LoginRequest{Login: "alice"}, wantCode: codes.InvalidArgument},
		{name: "слишком длинный пароль", req: &pb.LoginRequest{Login: "alice", Password: strings.Repeat("p", 129)}, wantCode: codes.Unauthenticated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, tokens := newAuthService(t, storage.NewMemory())
			registered, err := svc.Register(context.Background(), &pb.RegisterRequest{Login: "alice", Password: "s3cretpass", KdfSalt: kdfSalt})
			require.NoError(t, err)

			resp, err := svc.Login(context.Background(), tt.req)
			require.Equal(t, tt.wantCode, status.Code(err), "%v", err)
			if tt.wantCode != codes.OK {
				assert.Nil(t, resp)
				return
			}

			wantID, err := tokens.Parse(registered.GetToken())
			require.NoError(t, err)
			gotID, err := tokens.Parse(resp.GetToken())
			require.NoError(t, err)
			assert.Equal(t, wantID, gotID)
			assert.Equal(t, kdfSalt, resp.GetKdfSalt(), "соль ключа шифрования возвращается при входе")
		})
	}
}

func TestAuthService_Login_SameMessageForUnknownUserAndWrongPassword(t *testing.T) {
	svc, _ := newAuthService(t, storage.NewMemory())
	_, err := svc.Register(context.Background(), &pb.RegisterRequest{Login: "alice", Password: "s3cretpass", KdfSalt: kdfSalt})
	require.NoError(t, err)

	_, wrongPassword := svc.Login(context.Background(), &pb.LoginRequest{Login: "alice", Password: "wrongpass1"})
	_, unknownUser := svc.Login(context.Background(), &pb.LoginRequest{Login: "bob", Password: "wrongpass1"})

	assert.Equal(t, status.Convert(wrongPassword).Message(), status.Convert(unknownUser).Message(),
		"по сообщению нельзя узнать, существует ли логин")
}

func TestAuthService_Login_StorageError(t *testing.T) {
	svc, _ := newAuthService(t, failingUsers{err: errStorage})

	resp, err := svc.Login(context.Background(), &pb.LoginRequest{Login: "alice", Password: "s3cretpass"})
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Nil(t, resp)
}

func TestNewAuthService(t *testing.T) {
	hasher, err := auth.NewPasswordHasher(1)
	require.NoError(t, err)
	tokens, err := auth.NewTokenManager(bytes.Repeat([]byte{0x01}, auth.MinTokenKeySize), time.Hour)
	require.NoError(t, err)

	svc, err := NewAuthService(storage.NewMemory(), hasher, tokens, logger.Nop())
	require.NoError(t, err)
	assert.NotEmpty(t, svc.dummyHash)
	assert.NotEmpty(t, svc.dummySalt)
}
