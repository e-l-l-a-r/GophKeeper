package service

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/e-l-l-a-r/gophkeeper/internal/auth"
	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
	"github.com/e-l-l-a-r/gophkeeper/internal/storage"
)

// startGRPC поднимает gRPC-сервер в памяти (bufconn) с интерцептором
// авторизации и сервисом AuthService. Сервис SecretsService зарегистрирован
// заглушкой, которая отвечает Unimplemented: этого достаточно, чтобы проверить,
// что интерцептор пропускает или отклоняет запрос до обработчика.
func startGRPC(t *testing.T) (pb.AuthServiceClient, pb.SecretsServiceClient) {
	t.Helper()

	svc, tokens := newAuthService(t, storage.NewMemory())

	srv := grpc.NewServer(grpc.UnaryInterceptor(auth.UnaryInterceptor(tokens,
		pb.AuthService_Register_FullMethodName,
		pb.AuthService_Login_FullMethodName,
	)))
	pb.RegisterAuthServiceServer(srv, svc)
	pb.RegisterSecretsServiceServer(srv, pb.UnimplementedSecretsServiceServer{})

	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return pb.NewAuthServiceClient(conn), pb.NewSecretsServiceClient(conn)
}

func TestGRPC_RegisterLoginAndAuthorization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authClient, secretsClient := startGRPC(t)
	salt := bytes.Repeat([]byte{0x09}, 16)

	// Регистрация и вход доступны без токена.
	registered, err := authClient.Register(ctx, &pb.RegisterRequest{Login: "alice", Password: "s3cretpass", KdfSalt: salt})
	require.NoError(t, err)
	require.NotEmpty(t, registered.GetToken())

	_, err = authClient.Register(ctx, &pb.RegisterRequest{Login: "alice", Password: "s3cretpass", KdfSalt: salt})
	assert.Equal(t, codes.AlreadyExists, status.Code(err))

	loggedIn, err := authClient.Login(ctx, &pb.LoginRequest{Login: "alice", Password: "s3cretpass"})
	require.NoError(t, err)
	assert.Equal(t, salt, loggedIn.GetKdfSalt())

	_, err = authClient.Login(ctx, &pb.LoginRequest{Login: "alice", Password: "wrongpass1"})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	// Закрытые методы без токена и с чужим токеном отклоняются интерцептором.
	_, err = secretsClient.Get(ctx, &pb.GetSecretRequest{Id: "x"})
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "без токена")

	// Значения заголовков gRPC должны быть ASCII: клиент отвергает другие сам.
	badCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer not-a-token")
	_, err = secretsClient.Get(badCtx, &pb.GetSecretRequest{Id: "x"})
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "с неверным токеном")

	// С токеном из Register и из Login запрос доходит до обработчика
	// (заглушка отвечает Unimplemented).
	for name, token := range map[string]string{"из Register": registered.GetToken(), "из Login": loggedIn.GetToken()} {
		okCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		_, err = secretsClient.Get(okCtx, &pb.GetSecretRequest{Id: "x"})
		assert.Equal(t, codes.Unimplemented, status.Code(err), "токен %s", name)
	}
}
