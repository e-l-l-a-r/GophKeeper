// Package service содержит реализации gRPC-сервисов GophKeeper. Сервисы
// зависят от интерфейсов хранилища (internal/storage), поэтому тестируются без
// базы данных.
package service

import (
	"context"
	"errors"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/e-l-l-a-r/gophkeeper/internal/auth"
	"github.com/e-l-l-a-r/gophkeeper/internal/logger"
	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
	"github.com/e-l-l-a-r/gophkeeper/internal/storage"
)

const (
	// minLoginLen и maxLoginLen - границы длины логина в символах.
	minLoginLen = 3
	maxLoginLen = 64
	// minPasswordLen - минимальная длина пароля в символах.
	minPasswordLen = 8
	// maxPasswordBytes - максимальный размер пароля в байтах. Ограничение
	// защищает сервер от ресурсоёмкого хеширования огромных строк.
	maxPasswordBytes = 128
	// minKDFSaltLen и maxKDFSaltLen - границы размера соли вывода ключа в байтах.
	minKDFSaltLen = 16
	maxKDFSaltLen = 64
)

// errInvalidCredentials - общее сообщение для неверного логина и неверного
// пароля: по нему нельзя понять, существует ли пользователь.
const errInvalidCredentials = "неверный логин или пароль"

// AuthService реализует pb.AuthServiceServer: регистрацию и вход пользователей.
type AuthService struct {
	pb.UnimplementedAuthServiceServer

	users  storage.UserStorage
	hasher *auth.PasswordHasher
	tokens *auth.TokenManager
	log    *logger.Logger

	// dummyHash и dummySalt используются для проверки пароля несуществующего
	// пользователя, чтобы время ответа не выдавало, что логина нет в системе.
	dummyHash []byte
	dummySalt []byte
}

var _ pb.AuthServiceServer = (*AuthService)(nil)

// NewAuthService создаёт сервис аутентификации.
func NewAuthService(
	users storage.UserStorage,
	hasher *auth.PasswordHasher,
	tokens *auth.TokenManager,
	log *logger.Logger,
) (*AuthService, error) {
	dummyHash, dummySalt, err := hasher.Hash("gophkeeper-dummy-password")
	if err != nil {
		return nil, err
	}

	return &AuthService{
		users:     users,
		hasher:    hasher,
		tokens:    tokens,
		log:       log,
		dummyHash: dummyHash,
		dummySalt: dummySalt,
	}, nil
}

// Register регистрирует нового пользователя и выдаёт токен доступа.
// Возвращает INVALID_ARGUMENT при некорректных данных и ALREADY_EXISTS, если
// логин занят.
func (s *AuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.AuthResponse, error) {
	if err := validateLogin(req.GetLogin()); err != nil {
		return nil, err
	}
	if err := validatePassword(req.GetPassword()); err != nil {
		return nil, err
	}
	if n := len(req.GetKdfSalt()); n < minKDFSaltLen || n > maxKDFSaltLen {
		return nil, status.Errorf(codes.InvalidArgument,
			"соль ключа шифрования должна быть от %d до %d байт", minKDFSaltLen, maxKDFSaltLen)
	}

	hash, salt, err := s.hasher.Hash(req.GetPassword())
	if err != nil {
		return nil, s.internal("хеширование пароля", err)
	}

	user, err := s.users.CreateUser(ctx, storage.User{
		Login:        req.GetLogin(),
		PasswordHash: hash,
		PasswordSalt: salt,
		KDFSalt:      req.GetKdfSalt(),
	})
	switch {
	case errors.Is(err, storage.ErrUserExists):
		return nil, status.Error(codes.AlreadyExists, "логин уже занят")
	case err != nil:
		return nil, s.internal("создание пользователя", err)
	}

	return s.response(user), nil
}

// Login проверяет учётные данные и выдаёт токен доступа. Возвращает
// UNAUTHENTICATED при неверном логине или пароле.
func (s *AuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	if req.GetLogin() == "" || req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "логин и пароль обязательны")
	}
	if len(req.GetPassword()) > maxPasswordBytes {
		return nil, status.Error(codes.Unauthenticated, errInvalidCredentials)
	}

	user, err := s.users.UserByLogin(ctx, req.GetLogin())
	switch {
	case errors.Is(err, storage.ErrUserNotFound):
		// Выполняем ту же работу, что и для существующего пользователя.
		if _, verr := s.hasher.Verify(req.GetPassword(), s.dummyHash, s.dummySalt); verr != nil {
			return nil, s.internal("проверка пароля", verr)
		}

		return nil, status.Error(codes.Unauthenticated, errInvalidCredentials)
	case err != nil:
		return nil, s.internal("поиск пользователя", err)
	}

	ok, err := s.hasher.Verify(req.GetPassword(), user.PasswordHash, user.PasswordSalt)
	if err != nil {
		return nil, s.internal("проверка пароля", err)
	}
	if !ok {
		return nil, status.Error(codes.Unauthenticated, errInvalidCredentials)
	}

	return s.response(user), nil
}

// response выпускает токен для пользователя и собирает ответ.
func (s *AuthService) response(user storage.User) *pb.AuthResponse {
	token, expiresAt := s.tokens.Issue(user.ID)

	return &pb.AuthResponse{
		Token:     token,
		ExpiresAt: timestamppb.New(expiresAt),
		KdfSalt:   user.KDFSalt,
	}
}

// internal логирует внутреннюю ошибку и возвращает клиенту общий код
// codes.Internal без подробностей.
func (s *AuthService) internal(action string, err error) error {
	return internalError(s.log, "auth", action, err)
}

// validateLogin проверяет длину логина и отсутствие пробельных и управляющих символов.
func validateLogin(login string) error {
	if n := utf8.RuneCountInString(login); n < minLoginLen || n > maxLoginLen {
		return status.Errorf(codes.InvalidArgument,
			"логин должен содержать от %d до %d символов", minLoginLen, maxLoginLen)
	}
	if !utf8.ValidString(login) {
		return status.Error(codes.InvalidArgument, "логин содержит некорректные символы")
	}

	for _, r := range login {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return status.Error(codes.InvalidArgument, "логин не должен содержать пробелов и управляющих символов")
		}
	}

	return nil
}

// validatePassword проверяет длину пароля.
func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < minPasswordLen {
		return status.Errorf(codes.InvalidArgument, "пароль должен содержать не менее %d символов", minPasswordLen)
	}
	if len(password) > maxPasswordBytes {
		return status.Errorf(codes.InvalidArgument, "пароль не должен превышать %d байт", maxPasswordBytes)
	}

	return nil
}
