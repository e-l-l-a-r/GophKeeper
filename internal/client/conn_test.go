package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/e-l-l-a-r/gophkeeper/internal/auth"
	"github.com/e-l-l-a-r/gophkeeper/internal/logger"
	"github.com/e-l-l-a-r/gophkeeper/internal/model"
	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
	"github.com/e-l-l-a-r/gophkeeper/internal/service"
	"github.com/e-l-l-a-r/gophkeeper/internal/storage"
)

const connSecretID = "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11"

// startListener поднимает настоящий gRPC-сервер (сервисы, интерцептор
// авторизации, хранилище в памяти) на bufconn и возвращает его слушатель.
// Опции opts применяются к серверу.
func startListener(t *testing.T, opts ...grpc.ServerOption) *bufconn.Listener {
	t.Helper()

	users := storage.NewMemory()
	log := logger.Nop()

	hasher, err := auth.NewPasswordHasher(5)
	require.NoError(t, err)
	tokens, err := auth.NewTokenManager(bytes.Repeat([]byte{1}, auth.MinTokenKeySize), time.Hour)
	require.NoError(t, err)
	authSvc, err := service.NewAuthService(users, hasher, tokens, log)
	require.NoError(t, err)

	opts = append(opts,
		grpc.MaxRecvMsgSize(pb.MaxMessageSize),
		grpc.UnaryInterceptor(auth.UnaryInterceptor(tokens,
			pb.AuthService_Register_FullMethodName, pb.AuthService_Login_FullMethodName)),
	)

	srv := grpc.NewServer(opts...)
	pb.RegisterAuthServiceServer(srv, authSvc)
	pb.RegisterSecretsServiceServer(srv, service.NewSecretsService(users, log))

	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return lis
}

// connect создаёт ещё одно соединение с сервером на слушателе lis.
func connect(t *testing.T, lis *bufconn.Listener) *Conn {
	t.Helper()

	conn, err := dial("passthrough:///bufnet", insecure.NewCredentials(),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return conn
}

// startServer поднимает сервер и возвращает подключённый к нему Conn.
func startServer(t *testing.T, opts ...grpc.ServerOption) *Conn {
	t.Helper()

	return connect(t, startListener(t, opts...))
}

func registered(t *testing.T) *Conn {
	t.Helper()

	conn := startServer(t)

	_, err := conn.Register(context.Background(), "alice", "s3cretpass", bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)

	return conn
}

func TestConn_RegisterLogin(t *testing.T) {
	conn := startServer(t)
	ctx := context.Background()
	salt := bytes.Repeat([]byte{9}, 32)

	reg, err := conn.Register(ctx, "alice", "s3cretpass", salt)
	require.NoError(t, err)
	assert.NotEmpty(t, reg.Token)
	assert.Equal(t, salt, reg.KDFSalt)
	assert.True(t, reg.ExpiresAt.After(time.Now()))
	assert.Equal(t, reg.Token, conn.currentToken(), "токен сохраняется в соединении")

	_, err = conn.Register(ctx, "alice", "s3cretpass", salt)
	require.ErrorIs(t, err, ErrLoginTaken)

	_, err = conn.Register(ctx, "x", "s3cretpass", salt)
	require.ErrorIs(t, err, ErrRejected, "слишком короткий логин")

	login, err := conn.Login(ctx, "alice", "s3cretpass")
	require.NoError(t, err)
	assert.Equal(t, salt, login.KDFSalt, "соль возвращается при входе")

	_, err = conn.Login(ctx, "alice", "wrongpass1")
	require.ErrorIs(t, err, ErrInvalidCredentials)

	_, err = conn.Login(ctx, "nobody", "s3cretpass")
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestConn_RequestsRequireToken(t *testing.T) {
	conn := startServer(t)
	ctx := context.Background()

	_, err := conn.Get(ctx, connSecretID)
	require.ErrorIs(t, err, ErrUnauthenticated, "без токена доступ закрыт")

	conn.SetToken("not-a-token")
	_, err = conn.Get(ctx, connSecretID)
	require.ErrorIs(t, err, ErrUnauthenticated, "с неверным токеном доступ закрыт")
}

func TestConn_SetTokenFromSavedSession(t *testing.T) {
	first := registered(t)
	token := first.currentToken()

	// Тот же сервер недоступен из другого Conn в тесте, поэтому проверяем, что токен
	// подставляется в запросы после SetToken на том же соединении.
	first.SetToken("")
	_, err := first.Get(context.Background(), connSecretID)
	require.ErrorIs(t, err, ErrUnauthenticated)

	first.SetToken(token)
	_, err = first.Get(context.Background(), connSecretID)
	require.ErrorIs(t, err, ErrNotFound, "с токеном запрос доходит до обработчика")
}

func TestConn_SecretsLifecycle(t *testing.T) {
	conn := registered(t)
	ctx := context.Background()

	created, err := conn.Create(ctx, connSecretID, model.KindCard, []byte("cipher-1"))
	require.NoError(t, err)
	assert.Equal(t, connSecretID, created.ID)
	assert.Equal(t, model.KindCard, created.Kind)
	assert.Equal(t, int64(1), created.Version)
	assert.Equal(t, []byte("cipher-1"), created.Payload)
	assert.False(t, created.UpdatedAt.IsZero())

	_, err = conn.Create(ctx, connSecretID, model.KindCard, []byte("cipher-1"))
	require.ErrorIs(t, err, ErrAlreadyExists)

	got, err := conn.Get(ctx, connSecretID)
	require.NoError(t, err)
	assert.Equal(t, created, got)

	updated, err := conn.Update(ctx, connSecretID, model.KindText, []byte("cipher-2"), 1)
	require.NoError(t, err)
	assert.Equal(t, int64(2), updated.Version)
	assert.Equal(t, model.KindText, updated.Kind)

	_, err = conn.Update(ctx, connSecretID, model.KindText, []byte("cipher-3"), 1)
	require.ErrorIs(t, err, ErrVersionConflict)

	_, err = conn.Update(ctx, "7a1f6c52-1c53-4a45-8d61-0a8f2b9e4c22", model.KindText, []byte("x"), 1)
	require.ErrorIs(t, err, ErrNotFound)

	require.ErrorIs(t, conn.Delete(ctx, connSecretID, 1), ErrVersionConflict)
	require.NoError(t, conn.Delete(ctx, connSecretID, 2))
	require.ErrorIs(t, conn.Delete(ctx, connSecretID, 3), ErrNotFound)

	_, err = conn.Get(ctx, connSecretID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestConn_Sync(t *testing.T) {
	conn := registered(t)
	ctx := context.Background()

	const other = "7a1f6c52-1c53-4a45-8d61-0a8f2b9e4c22"

	_, err := conn.Create(ctx, connSecretID, model.KindText, []byte("a"))
	require.NoError(t, err)
	_, err = conn.Create(ctx, other, model.KindBinary, []byte("b"))
	require.NoError(t, err)

	changed, deleted, err := conn.Sync(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, changed, 2)
	assert.Empty(t, deleted)

	require.NoError(t, conn.Delete(ctx, other, 1))

	changed, deleted, err = conn.Sync(ctx, []Known{{ID: connSecretID, Version: 1}, {ID: other, Version: 1}})
	require.NoError(t, err)
	assert.Empty(t, changed)
	assert.Equal(t, []string{other}, deleted)
}

func TestConn_Sync_InvalidKnownIsRejected(t *testing.T) {
	conn := registered(t)

	_, _, err := conn.Sync(context.Background(), []Known{{ID: "not-uuid", Version: 1}})
	require.ErrorIs(t, err, ErrRejected)
}

func TestConn_LargeRecordPassesDefaultGRPCLimit(t *testing.T) {
	conn := registered(t)
	ctx := context.Background()

	// 5 МиБ больше стандартного лимита gRPC (4 МиБ): без явных лимитов запись бы не прошла.
	payload := bytes.Repeat([]byte{0xab}, 5<<20)

	_, err := conn.Create(ctx, connSecretID, model.KindBinary, payload)
	require.NoError(t, err)

	got, err := conn.Get(ctx, connSecretID)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(payload, got.Payload))
}

func TestConn_OversizedRecordIsRejected(t *testing.T) {
	conn := registered(t)

	_, err := conn.Create(context.Background(), connSecretID, model.KindBinary, bytes.Repeat([]byte{1}, pb.MaxPayloadSize+1))
	require.ErrorIs(t, err, ErrRejected)
}

func TestConn_ContextErrors(t *testing.T) {
	conn := registered(t)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := conn.Get(canceled, connSecretID)
	require.ErrorIs(t, err, context.Canceled)

	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()

	_, err = conn.Get(expired, connSecretID)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestConn_Close(t *testing.T) {
	conn, err := dial("passthrough:///x", insecure.NewCredentials())
	require.NoError(t, err)

	require.NoError(t, conn.Close())
	require.Error(t, conn.Close(), "повторное закрытие возвращает ошибку")
}

func TestConn_ServerUnavailable(t *testing.T) {
	addr := func() string {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()

		return ln.Addr().String()
	}()

	conn, err := Dial(addr, DialOptions{Insecure: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = conn.Login(ctx, "alice", "s3cretpass")
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestMapError(t *testing.T) {
	tests := []struct {
		err     error
		wantIs  error
		name    string
		wantNil bool
	}{
		{name: "нет ошибки", err: nil, wantNil: true},
		{name: "не найдено", err: status.Error(codes.NotFound, "x"), wantIs: ErrNotFound},
		{name: "уже есть", err: status.Error(codes.AlreadyExists, "x"), wantIs: ErrAlreadyExists},
		{name: "конфликт версий", err: status.Error(codes.Aborted, "x"), wantIs: ErrVersionConflict},
		{name: "не аутентифицирован", err: status.Error(codes.Unauthenticated, "x"), wantIs: ErrUnauthenticated},
		{name: "недоступен", err: status.Error(codes.Unavailable, "x"), wantIs: ErrUnavailable},
		{name: "некорректный запрос", err: status.Error(codes.InvalidArgument, "плохо"), wantIs: ErrRejected},
		{name: "отмена", err: status.Error(codes.Canceled, "x"), wantIs: context.Canceled},
		{name: "истёк срок", err: status.Error(codes.DeadlineExceeded, "x"), wantIs: context.DeadlineExceeded},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapError(tt.err)
			if tt.wantNil {
				require.NoError(t, got)
				return
			}

			require.ErrorIs(t, got, tt.wantIs)
		})
	}

	t.Run("прочий код gRPC", func(t *testing.T) {
		got := mapError(status.Error(codes.Internal, "сбой"))
		require.Error(t, got)
		assert.Contains(t, got.Error(), "Internal")
		assert.Contains(t, got.Error(), "сбой")
	})

	t.Run("ошибка не из gRPC возвращается как есть", func(t *testing.T) {
		plain := errors.New("обычная ошибка")
		assert.Equal(t, plain, mapError(plain))
	})
}

func TestSecretFromProto(t *testing.T) {
	t.Run("корректная запись", func(t *testing.T) {
		got, err := secretFromProto(&pb.Secret{
			Id: connSecretID, Type: pb.SecretType_SECRET_TYPE_CARD, EncryptedPayload: []byte("p"), Version: 3,
		})
		require.NoError(t, err)
		assert.Equal(t, model.KindCard, got.Kind)
		assert.Equal(t, int64(3), got.Version)
	})

	for _, kind := range []pb.SecretType{pb.SecretType_SECRET_TYPE_UNSPECIFIED, 5, -1, 65537} {
		t.Run("недопустимый тип", func(t *testing.T) {
			_, err := secretFromProto(&pb.Secret{Id: connSecretID, Type: kind})
			require.Error(t, err, "тип %d", int32(kind))
		})
	}
}

// writeCert создаёт самоподписанный сертификат для 127.0.0.1 и localhost,
// записывает его и ключ в PEM-файлы и возвращает пути к ним.
func writeCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))

	return certFile, keyFile
}

// startTLSServer запускает настоящий TLS-сервер AuthService на TCP и возвращает его адрес.
func startTLSServer(t *testing.T, certFile, keyFile string) string {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	users := storage.NewMemory()
	hasher, err := auth.NewPasswordHasher(5)
	require.NoError(t, err)
	tokens, err := auth.NewTokenManager(bytes.Repeat([]byte{1}, auth.MinTokenKeySize), time.Hour)
	require.NoError(t, err)
	authSvc, err := service.NewAuthService(users, hasher, tokens, logger.Nop())
	require.NoError(t, err)

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
	})))
	pb.RegisterAuthServiceServer(srv, authSvc)

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	return ln.Addr().String()
}

func TestDial_TLS(t *testing.T) {
	certFile, keyFile := writeCert(t)
	addr := startTLSServer(t, certFile, keyFile)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	salt := bytes.Repeat([]byte{4}, 32)

	t.Run("доверенный сертификат", func(t *testing.T) {
		conn, err := Dial(addr, DialOptions{CAFile: certFile})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		_, err = conn.Register(ctx, "alice", "s3cretpass", salt)
		require.NoError(t, err)
	})

	t.Run("недоверенный сертификат", func(t *testing.T) {
		conn, err := Dial(addr, DialOptions{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		_, err = conn.Login(ctx, "alice", "s3cretpass")
		require.ErrorIs(t, err, ErrUnavailable, "самоподписанный сертификат без CAFile отвергается")
	})

	t.Run("клиент без TLS", func(t *testing.T) {
		conn, err := Dial(addr, DialOptions{Insecure: true})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		_, err = conn.Login(ctx, "alice", "s3cretpass")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrInvalidCredentials, "запрос не должен дойти до обработчика")
	})
}

func TestTransportCredentials_Errors(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "garbage.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("не сертификат"), 0o600))

	tests := []struct {
		name string
		opts DialOptions
	}{
		{name: "файл не существует", opts: DialOptions{CAFile: filepath.Join(dir, "missing.pem")}},
		{name: "нет сертификатов в файле", opts: DialOptions{CAFile: notPEM}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := Dial("localhost:1", tt.opts)
			require.Error(t, err)
			assert.Nil(t, conn)
		})
	}

	t.Run("без параметров", func(t *testing.T) {
		creds, err := transportCredentials(DialOptions{})
		require.NoError(t, err)
		assert.Equal(t, "tls", creds.Info().SecurityProtocol)
	})

	t.Run("insecure", func(t *testing.T) {
		creds, err := transportCredentials(DialOptions{Insecure: true})
		require.NoError(t, err)
		assert.Equal(t, "insecure", creds.Info().SecurityProtocol)
	})
}
