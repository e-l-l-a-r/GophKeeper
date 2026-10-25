package main

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
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
	"github.com/e-l-l-a-r/gophkeeper/internal/storage"
)

const testSecretID = "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11"

// memoryStores - провайдер хранилища для тестов: данные в памяти вместо PostgreSQL.
func memoryStores() stores {
	mem := storage.NewMemory()

	return stores{Users: mem, Secrets: mem}
}

// freeAddr возвращает свободный адрес локального TCP-порта.
func freeAddr(t *testing.T) string {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	return addr
}

// startServer запускает сервер через run и ждёт, пока он начнёт принимать
// соединения. Возвращает функцию остановки, которая отменяет контекст и
// возвращает результат run.
func startServer(t *testing.T, args []string, storageProvider any) (addr string, stop func() error) {
	t.Helper()

	cleanEnv(t)
	addr = freeAddr(t)
	t.Setenv("ADDRESS", addr)
	t.Setenv("DATABASE_DSN", "postgres://unused")
	t.Setenv("TOKEN_KEY", testTokenKey)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, args, storageProvider) }()

	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()

		return true
	}, 5*time.Second, 20*time.Millisecond, "сервер не начал принимать соединения")

	var once bool
	stop = func() error {
		if once {
			return nil
		}
		once = true
		cancel()

		select {
		case err := <-done:
			return err
		case <-time.After(15 * time.Second):
			return fmt.Errorf("сервер не остановился")
		}
	}
	t.Cleanup(func() { _ = stop() })

	return addr, stop
}

// scenario проходит через клиент все основные операции: регистрация, вход,
// создание, чтение, изменение, синхронизация и удаление записи.
func scenario(t *testing.T, conn *grpc.ClientConn) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authClient := pb.NewAuthServiceClient(conn)
	secrets := pb.NewSecretsServiceClient(conn)

	salt := bytes.Repeat([]byte{7}, 16)
	registered, err := authClient.Register(ctx, &pb.RegisterRequest{Login: "alice", Password: "s3cretpass", KdfSalt: salt})
	require.NoError(t, err)

	loggedIn, err := authClient.Login(ctx, &pb.LoginRequest{Login: "alice", Password: "s3cretpass"})
	require.NoError(t, err)
	assert.Equal(t, salt, loggedIn.GetKdfSalt())

	_, err = secrets.Get(ctx, &pb.GetSecretRequest{Id: testSecretID})
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "без токена доступ закрыт")

	authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+registered.GetToken())

	created, err := secrets.Create(authed, &pb.CreateSecretRequest{
		Id: testSecretID, Type: pb.SecretType_SECRET_TYPE_LOGIN_PASSWORD, EncryptedPayload: []byte("cipher-1"),
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), created.GetVersion())

	// Запись крупнее стандартного лимита gRPC (4 МиБ) должна проходить.
	big := bytes.Repeat([]byte{9}, 5<<20)
	const bigID = "7a1f6c52-1c53-4a45-8d61-0a8f2b9e4c22"
	_, err = secrets.Create(authed, &pb.CreateSecretRequest{Id: bigID, Type: pb.SecretType_SECRET_TYPE_BINARY, EncryptedPayload: big})
	require.NoError(t, err, "запись 5 МиБ должна приниматься")

	got, err := secrets.Get(authed, &pb.GetSecretRequest{Id: bigID})
	require.NoError(t, err)
	assert.Equal(t, big, got.GetEncryptedPayload())

	updated, err := secrets.Update(authed, &pb.UpdateSecretRequest{
		Id: testSecretID, Type: pb.SecretType_SECRET_TYPE_LOGIN_PASSWORD, EncryptedPayload: []byte("cipher-2"), ExpectedVersion: 1,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), updated.GetVersion())

	_, err = secrets.Update(authed, &pb.UpdateSecretRequest{
		Id: testSecretID, Type: pb.SecretType_SECRET_TYPE_LOGIN_PASSWORD, EncryptedPayload: []byte("cipher-3"), ExpectedVersion: 1,
	})
	assert.Equal(t, codes.Aborted, status.Code(err), "устаревшая версия")

	delta, err := secrets.Sync(authed, &pb.SyncRequest{Known: []*pb.SecretVersion{{Id: testSecretID, Version: 1}}})
	require.NoError(t, err)
	require.Len(t, delta.GetChanged(), 2)
	assert.Empty(t, delta.GetDeletedIds())

	_, err = secrets.Delete(authed, &pb.DeleteSecretRequest{Id: bigID, ExpectedVersion: 1})
	require.NoError(t, err)

	delta, err = secrets.Sync(authed, &pb.SyncRequest{Known: []*pb.SecretVersion{
		{Id: testSecretID, Version: 2}, {Id: bigID, Version: 1},
	}})
	require.NoError(t, err)
	assert.Empty(t, delta.GetChanged())
	assert.Equal(t, []string{bigID}, delta.GetDeletedIds())
}

func TestRun_InsecureEndToEnd(t *testing.T) {
	addr, stop := startServer(t, []string{"--insecure"}, memoryStores)

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(pb.MaxMessageSize), grpc.MaxCallSendMsgSize(pb.MaxMessageSize)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	scenario(t, conn)

	require.NoError(t, stop(), "плавная остановка по отмене контекста")
}

func TestRun_TLSEndToEnd(t *testing.T) {
	certFile, keyFile, pool := writeSelfSignedCert(t)

	// startServer очищает окружение, поэтому пути к TLS задаются через файл конфигурации.
	cfg := writeConfigFile(t, fmt.Sprintf(`{"tls_cert": %q, "tls_key": %q}`, certFile, keyFile))
	addr, stop := startServer(t, []string{"-c", cfg}, memoryStores)

	creds := credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(pb.MaxMessageSize), grpc.MaxCallSendMsgSize(pb.MaxMessageSize)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	scenario(t, conn)

	t.Run("клиент без TLS не может работать с сервером", func(t *testing.T) {
		plain, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		t.Cleanup(func() { _ = plain.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err = pb.NewAuthServiceClient(plain).Login(ctx, &pb.LoginRequest{Login: "alice", Password: "s3cretpass"})
		require.Error(t, err)
		assert.NotEqual(t, codes.OK, status.Code(err))
		assert.NotEqual(t, codes.Unauthenticated, status.Code(err), "до обработчика запрос дойти не должен")
	})

	t.Run("клиент не доверяет чужому сертификату", func(t *testing.T) {
		untrusted := credentials.NewTLS(&tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS13})
		bad, err := grpc.NewClient(addr, grpc.WithTransportCredentials(untrusted))
		require.NoError(t, err)
		t.Cleanup(func() { _ = bad.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err = pb.NewAuthServiceClient(bad).Login(ctx, &pb.LoginRequest{Login: "alice", Password: "s3cretpass"})
		assert.Equal(t, codes.Unavailable, status.Code(err))
	})

	require.NoError(t, stop())
}

func TestRun_StartupErrors(t *testing.T) {
	t.Run("справка не считается ошибкой", func(t *testing.T) {
		cleanEnv(t)
		require.NoError(t, run(context.Background(), []string{"--help"}, memoryStores))
	})

	t.Run("не заданы обязательные настройки", func(t *testing.T) {
		cleanEnv(t)
		err := run(context.Background(), nil, memoryStores)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TOKEN_KEY")
	})

	t.Run("адрес занят", func(t *testing.T) {
		cleanEnv(t)

		busy, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = busy.Close() })

		t.Setenv("ADDRESS", busy.Addr().String())
		t.Setenv("DATABASE_DSN", "postgres://unused")
		t.Setenv("TOKEN_KEY", testTokenKey)

		err = run(context.Background(), []string{"--insecure"}, memoryStores)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "не удалось занять адрес")
	})

	t.Run("некорректный уровень логирования", func(t *testing.T) {
		cleanEnv(t)
		t.Setenv("ADDRESS", freeAddr(t))
		t.Setenv("DATABASE_DSN", "postgres://unused")
		t.Setenv("TOKEN_KEY", testTokenKey)
		t.Setenv("LOG_LEVEL", "громко")

		require.Error(t, run(context.Background(), []string{"--insecure"}, memoryStores))
	})

	t.Run("сертификат не существует", func(t *testing.T) {
		cleanEnv(t)
		t.Setenv("ADDRESS", freeAddr(t))
		t.Setenv("DATABASE_DSN", "postgres://unused")
		t.Setenv("TOKEN_KEY", testTokenKey)
		t.Setenv("TLS_CERT", filepath.Join(t.TempDir(), "no.pem"))
		t.Setenv("TLS_KEY", filepath.Join(t.TempDir(), "no.key"))

		err := run(context.Background(), nil, memoryStores)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "сертификат")
	})

	t.Run("ошибка запуска хранилища прерывает старт", func(t *testing.T) {
		cleanEnv(t)
		t.Setenv("ADDRESS", freeAddr(t))
		t.Setenv("DATABASE_DSN", "postgres://unused")
		t.Setenv("TOKEN_KEY", testTokenKey)

		failing := func(lc fx.Lifecycle) stores {
			lc.Append(fx.Hook{OnStart: func(context.Context) error { return errTestStorage }})

			return memoryStores()
		}

		err := run(context.Background(), []string{"--insecure"}, failing)
		require.ErrorIs(t, err, errTestStorage)
	})
}

// errTestStorage - ошибка, которой имитируется сбой запуска хранилища.
var errTestStorage = fmt.Errorf("база недоступна")

func TestProvideStorage_PostgresUnreachableFailsStart(t *testing.T) {
	cleanEnv(t)
	t.Setenv("ADDRESS", freeAddr(t))
	t.Setenv("DATABASE_DSN", "postgres://user:pass@127.0.0.1:1/db?sslmode=disable&connect_timeout=1")
	t.Setenv("TOKEN_KEY", testTokenKey)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := run(ctx, []string{"--insecure"}, provideStorage)
	require.Error(t, err, "при недоступной базе сервер не должен стартовать")
	assert.Contains(t, err.Error(), "база данных недоступна")
}

func TestExecute_HelpPrintsBuildInfo(t *testing.T) {
	cleanEnv(t)

	oldVersion, oldDate, oldCommit := buildVersion, buildDate, buildCommit
	buildVersion, buildDate, buildCommit = "1.2.3", "2026-02-03", "abc"
	t.Cleanup(func() { buildVersion, buildDate, buildCommit = oldVersion, oldDate, oldCommit })

	stdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = stdout })

	execErr := execute([]string{"--help"})

	require.NoError(t, w.Close())
	os.Stdout = stdout

	var out bytes.Buffer
	_, err = out.ReadFrom(r)
	require.NoError(t, err)

	require.NoError(t, execErr)
	assert.Contains(t, out.String(), "Build version: 1.2.3")
	assert.Contains(t, out.String(), "Build date: 2026-02-03")
	assert.Contains(t, out.String(), "Build commit: abc")
}

func TestLoadTLS(t *testing.T) {
	certFile, keyFile, _ := writeSelfSignedCert(t)
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("не сертификат"), 0o600))

	tests := []struct {
		name    string
		cert    string
		key     string
		wantErr bool
	}{
		{name: "корректная пара", cert: certFile, key: keyFile},
		{name: "файл сертификата не существует", cert: filepath.Join(t.TempDir(), "x"), key: keyFile, wantErr: true},
		{name: "файл ключа не существует", cert: certFile, key: filepath.Join(t.TempDir(), "x"), wantErr: true},
		{name: "мусор вместо сертификата", cert: garbage, key: keyFile, wantErr: true},
		{name: "ключ не от этого сертификата", cert: certFile, key: otherKey(t), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := loadTLS(tt.cert, tt.key)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, creds)

				return
			}

			require.NoError(t, err)
			assert.NotNil(t, creds)
		})
	}
}

// writeSelfSignedCert создаёт самоподписанный сертификат для localhost и
// 127.0.0.1, записывает сертификат и ключ в PEM-файлы и возвращает пути к ним
// и пул доверенных сертификатов для клиента.
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
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

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool = x509.NewCertPool()
	pool.AddCert(cert)

	return certFile, keyFile, pool
}

// otherKey записывает в файл закрытый ключ, не подходящий к сертификату из writeSelfSignedCert.
func otherKey(t *testing.T) string {
	t.Helper()

	_, keyFile, _ := writeSelfSignedCert(t)

	return keyFile
}
