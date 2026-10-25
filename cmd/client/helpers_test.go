package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/e-l-l-a-r/gophkeeper/internal/auth"
	"github.com/e-l-l-a-r/gophkeeper/internal/client"
	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
	"github.com/e-l-l-a-r/gophkeeper/internal/logger"
	"github.com/e-l-l-a-r/gophkeeper/internal/model"
	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
	"github.com/e-l-l-a-r/gophkeeper/internal/service"
	"github.com/e-l-l-a-r/gophkeeper/internal/storage"
)

// testIterations - число итераций PBKDF2 в тестах: достаточно мало для скорости.
const testIterations = 3

var testNow = time.Date(2026, 9, 10, 11, 12, 13, 0, time.UTC)

// scriptedPrompt - подставной терминал: отдаёт заранее заготовленные ответы
// по очереди и запоминает приглашения. Нехватка ответов - ошибка теста.
type scriptedPrompt struct {
	// secretErr возвращается из Secret вместо ответа (например, errNotTerminal).
	secretErr error
	lines     []string
	secrets   []string
	asked     []string
}

var _ prompter = (*scriptedPrompt)(nil)

func (p *scriptedPrompt) Line(prompt string) (string, error) {
	p.asked = append(p.asked, prompt)
	if len(p.lines) == 0 {
		return "", errors.New("тест: не хватает ответа на запрос " + prompt)
	}

	answer := p.lines[0]
	p.lines = p.lines[1:]

	return answer, nil
}

func (p *scriptedPrompt) Secret(prompt string) (string, error) {
	p.asked = append(p.asked, prompt)
	if p.secretErr != nil {
		return "", p.secretErr
	}
	if len(p.secrets) == 0 {
		return "", errors.New("тест: не хватает секрета на запрос " + prompt)
	}

	answer := p.secrets[0]
	p.secrets = p.secrets[1:]

	return answer, nil
}

// testEnv - окружение теста: общий сервер, каталог состояния и вывод команд.
type testEnv struct {
	t      *testing.T
	server *testServer
	out    *bytes.Buffer
	errOut *bytes.Buffer
	dir    string
	// unavailable включает имитацию недоступного сервера.
	unavailable bool
}

// testServer - настоящие сервисы GophKeeper без сети: AuthService и
// SecretsService поверх хранилища в памяти. Вызовы идут напрямую, но через те
// же проверки, валидацию и коды ошибок, что и на настоящем сервере.
type testServer struct {
	auth    *service.AuthService
	secrets *service.SecretsService
	tokens  *auth.TokenManager
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	store := storage.NewMemory()
	log := logger.Nop()

	hasher, err := auth.NewPasswordHasher(3)
	require.NoError(t, err)
	tokens, err := auth.NewTokenManager(bytes.Repeat([]byte{1}, auth.MinTokenKeySize), time.Hour)
	require.NoError(t, err)
	authSvc, err := service.NewAuthService(store, hasher, tokens, log)
	require.NoError(t, err)

	return &testServer{auth: authSvc, secrets: service.NewSecretsService(store, log), tokens: tokens}
}

// testConn - connection поверх testServer. Токен проверяется так же, как это
// делает интерцептор сервера.
type testConn struct {
	srv   *testServer
	env   *testEnv
	token string
}

var _ connection = (*testConn)(nil)

func (c *testConn) SetToken(token string) { c.token = token }
func (c *testConn) Close() error          { return nil }

// userCtx проверяет токен и возвращает контекст с идентификатором пользователя.
func (c *testConn) userCtx(ctx context.Context) (context.Context, error) {
	if c.env.unavailable {
		return nil, client.ErrUnavailable
	}

	userID, err := c.srv.tokens.Parse(c.token)
	if err != nil {
		return nil, client.ErrUnauthenticated
	}

	return auth.ContextWithUserID(ctx, userID), nil
}

func (c *testConn) Register(ctx context.Context, login, password string, salt []byte) (client.AuthResult, error) {
	if c.env.unavailable {
		return client.AuthResult{}, client.ErrUnavailable
	}

	resp, err := c.srv.auth.Register(ctx, &pb.RegisterRequest{Login: login, Password: password, KdfSalt: salt})
	if err != nil {
		return client.AuthResult{}, mapAuthError(err)
	}

	return authResult(resp), nil
}

func (c *testConn) Login(ctx context.Context, login, password string) (client.AuthResult, error) {
	if c.env.unavailable {
		return client.AuthResult{}, client.ErrUnavailable
	}

	resp, err := c.srv.auth.Login(ctx, &pb.LoginRequest{Login: login, Password: password})
	if err != nil {
		return client.AuthResult{}, mapAuthError(err)
	}

	return authResult(resp), nil
}

func authResult(resp *pb.AuthResponse) client.AuthResult {
	return client.AuthResult{
		ExpiresAt: resp.GetExpiresAt().AsTime(),
		Token:     resp.GetToken(),
		KDFSalt:   resp.GetKdfSalt(),
	}
}

// mapAuthError переводит коды сервиса аутентификации в ошибки пакета client
// так же, как это делает client.Conn.
func mapAuthError(err error) error {
	msg := err.Error()

	switch {
	case strings.Contains(msg, "AlreadyExists"):
		return client.ErrLoginTaken
	case strings.Contains(msg, "Unauthenticated"):
		return client.ErrInvalidCredentials
	default:
		return err
	}
}

func (c *testConn) Create(ctx context.Context, id string, kind model.Kind, payload []byte) (client.Secret, error) {
	uctx, err := c.userCtx(ctx)
	if err != nil {
		return client.Secret{}, err
	}

	resp, err := c.srv.secrets.Create(uctx, &pb.CreateSecretRequest{Id: id, Type: pb.SecretType(kind), EncryptedPayload: payload})
	if err != nil {
		return client.Secret{}, secretsError(err)
	}

	return toSecret(resp), nil
}

func (c *testConn) Get(ctx context.Context, id string) (client.Secret, error) {
	uctx, err := c.userCtx(ctx)
	if err != nil {
		return client.Secret{}, err
	}

	resp, err := c.srv.secrets.Get(uctx, &pb.GetSecretRequest{Id: id})
	if err != nil {
		return client.Secret{}, secretsError(err)
	}

	return toSecret(resp), nil
}

func (c *testConn) Update(ctx context.Context, id string, kind model.Kind, payload []byte, version int64) (client.Secret, error) {
	uctx, err := c.userCtx(ctx)
	if err != nil {
		return client.Secret{}, err
	}

	resp, err := c.srv.secrets.Update(uctx, &pb.UpdateSecretRequest{
		Id: id, Type: pb.SecretType(kind), EncryptedPayload: payload, ExpectedVersion: version,
	})
	if err != nil {
		return client.Secret{}, secretsError(err)
	}

	return toSecret(resp), nil
}

func (c *testConn) Delete(ctx context.Context, id string, version int64) error {
	uctx, err := c.userCtx(ctx)
	if err != nil {
		return err
	}

	if _, err = c.srv.secrets.Delete(uctx, &pb.DeleteSecretRequest{Id: id, ExpectedVersion: version}); err != nil {
		return secretsError(err)
	}

	return nil
}

func (c *testConn) Sync(ctx context.Context, known []client.Known) ([]client.Secret, []string, error) {
	uctx, err := c.userCtx(ctx)
	if err != nil {
		return nil, nil, err
	}

	req := &pb.SyncRequest{}
	for _, k := range known {
		req.Known = append(req.Known, &pb.SecretVersion{Id: k.ID, Version: k.Version})
	}

	resp, err := c.srv.secrets.Sync(uctx, req)
	if err != nil {
		return nil, nil, secretsError(err)
	}

	changed := make([]client.Secret, 0, len(resp.GetChanged()))
	for _, s := range resp.GetChanged() {
		changed = append(changed, toSecret(s))
	}

	return changed, resp.GetDeletedIds(), nil
}

func toSecret(s *pb.Secret) client.Secret {
	return client.Secret{
		UpdatedAt: s.GetUpdatedAt().AsTime(),
		ID:        s.GetId(),
		Payload:   s.GetEncryptedPayload(),
		Version:   s.GetVersion(),
		Kind:      model.Kind(s.GetType()),
	}
}

// secretsError переводит коды SecretsService в ошибки пакета client так же,
// как это делает client.Conn.
func secretsError(err error) error {
	msg := err.Error()

	switch {
	case strings.Contains(msg, "NotFound"):
		return client.ErrNotFound
	case strings.Contains(msg, "AlreadyExists"):
		return client.ErrAlreadyExists
	case strings.Contains(msg, "Aborted"):
		return client.ErrVersionConflict
	case strings.Contains(msg, "Unauthenticated"):
		return client.ErrUnauthenticated
	default:
		return err
	}
}

// newEnv создаёт окружение теста со своим каталогом состояния.
func newEnv(t *testing.T, srv *testServer) *testEnv {
	t.Helper()

	return &testEnv{
		t:      t,
		server: srv,
		dir:    filepath.Join(t.TempDir(), "state"),
		out:    &bytes.Buffer{},
		errOut: &bytes.Buffer{},
	}
}

// application создаёт приложение с подставным терминалом.
func (e *testEnv) application(p prompter) *app {
	return &app{
		prompt: p,
		dial: func(string, client.DialOptions) (connection, error) {
			if e.unavailable {
				return nil, client.ErrUnavailable
			}

			return &testConn{srv: e.server, env: e}, nil
		},
		now:        func() time.Time { return testNow },
		stdout:     e.out,
		stderr:     e.errOut,
		iterations: testIterations,
		build:      buildInfo{version: "1.2.3", date: "2026-02-03", commit: "abc"},
	}
}

// do выполняет команду с флагами общей настройки (каталог состояния и
// небезопасный режим, чтобы не требовать сертификатов) и возвращает ошибку.
func (e *testEnv) do(p prompter, args ...string) error {
	e.t.Helper()
	e.out.Reset()
	e.errOut.Reset()

	full := make([]string, 0, len(args)+4)
	full = append(full, args[0])
	full = append(full, "--dir", e.dir, "--insecure")
	full = append(full, args[1:]...)

	return e.application(p).run(context.Background(), full)
}

// mustDo выполняет команду и требует успеха.
func (e *testEnv) mustDo(p prompter, args ...string) string {
	e.t.Helper()
	require.NoError(e.t, e.do(p, args...), "stderr: %s", e.errOut.String())

	return e.out.String()
}

// register регистрирует пользователя alice с паролем входа s3cretpass.
func (e *testEnv) register() {
	e.t.Helper()

	e.mustDo(&scriptedPrompt{lines: []string{"alice"}, secrets: []string{"s3cretpass", "s3cretpass"}}, "register")
}

// writeFile создаёт файл с содержимым data и возвращает его путь.
func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	return path
}

// cache открывает кеш пользователя alice из каталога состояния окружения.
func (e *testEnv) cache() *localstore.Cache {
	e.t.Helper()

	store, err := localstore.Open(e.dir)
	require.NoError(e.t, err)
	sess, err := store.LoadSession()
	require.NoError(e.t, err)
	cache, err := store.OpenCache(sess.Server, sess.Login)
	require.NoError(e.t, err)

	return cache
}

// envVars - все переменные окружения, которые читает клиент.
var envVars = []string{
	"GOPHKEEPER_SERVER", "GOPHKEEPER_CA_FILE", "GOPHKEEPER_INSECURE", "GOPHKEEPER_DIR", "GOPHKEEPER_CONFIG",
}

// cleanEnv удаляет переменные окружения клиента и восстанавливает их по
// завершении теста. t.Setenv с пустым значением не подходит: переменная
// остаётся заданной.
func cleanEnv(t *testing.T) {
	t.Helper()

	for _, name := range envVars {
		t.Setenv(name, "") // регистрирует восстановление исходного значения
		require.NoError(t, os.Unsetenv(name))
	}
}
