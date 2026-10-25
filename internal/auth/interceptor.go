package auth

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// authorizationHeader - ключ метаданных gRPC с токеном доступа.
	authorizationHeader = "authorization"
	// bearerScheme - схема авторизации, с которой начинается значение заголовка.
	bearerScheme = "bearer "
)

// userIDKey - ключ контекста, под которым хранится идентификатор пользователя.
type userIDKey struct{}

// ContextWithUserID возвращает контекст, в котором сохранён идентификатор
// аутентифицированного пользователя.
func ContextWithUserID(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, userIDKey{}, userID)
}

// UserIDFromContext возвращает идентификатор пользователя, сохранённый
// интерцептором. Второе значение false означает, что запрос не прошёл
// аутентификацию.
func UserIDFromContext(ctx context.Context) (int64, bool) {
	userID, ok := ctx.Value(userIDKey{}).(int64)

	return userID, ok
}

// UnaryInterceptor возвращает унарный gRPC-интерцептор, который требует токен
// доступа в метаданных authorization (Bearer <token>) и кладёт идентификатор
// пользователя в контекст обработчика. Методы из publicMethods (полные имена
// вида /gophkeeper.v1.AuthService/Login) пропускаются без проверки.
//
// Запрос без токена, с неверным или просроченным токеном завершается кодом
// codes.Unauthenticated.
func UnaryInterceptor(tokens *TokenManager, publicMethods ...string) grpc.UnaryServerInterceptor {
	public := make(map[string]struct{}, len(publicMethods))
	for _, method := range publicMethods {
		public[method] = struct{}{}
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, ok := public[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		token, ok := bearerToken(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "требуется токен доступа")
		}

		userID, err := tokens.Parse(token)
		switch {
		case errors.Is(err, ErrExpiredToken):
			return nil, status.Error(codes.Unauthenticated, ErrExpiredToken.Error())
		case err != nil:
			return nil, status.Error(codes.Unauthenticated, ErrInvalidToken.Error())
		}

		return handler(ContextWithUserID(ctx, userID), req)
	}
}

// bearerToken извлекает токен из заголовка authorization входящего запроса.
func bearerToken(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}

	for _, value := range md.Get(authorizationHeader) {
		if len(value) > len(bearerScheme) && strings.EqualFold(value[:len(bearerScheme)], bearerScheme) {
			return strings.TrimSpace(value[len(bearerScheme):]), true
		}
	}

	return "", false
}
