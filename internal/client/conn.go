package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/e-l-l-a-r/gophkeeper/internal/model"
	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
)

// DialOptions - параметры подключения к серверу.
type DialOptions struct {
	// CAFile - путь к PEM-файлу с сертификатом (или центром сертификации),
	// которому клиент доверяет. Пустое значение означает системные корневые
	// сертификаты. Нужен для сервера с самоподписанным сертификатом.
	CAFile string
	// Insecure отключает TLS. Только для локальной отладки: токен доступа и
	// пароль входа передаются по сети в открытом виде.
	Insecure bool
}

// AuthResult - результат регистрации или входа.
type AuthResult struct {
	// ExpiresAt - момент истечения токена доступа.
	ExpiresAt time.Time
	// Token - токен доступа; секрет.
	Token string
	// KDFSalt - соль вывода ключа шифрования, хранящаяся на сервере.
	KDFSalt []byte
}

// Conn - соединение с сервером GophKeeper. Реализует Remote. После
// Register или Login токен доступа подставляется во все запросы автоматически.
// Безопасен для одновременного использования из нескольких горутин.
type Conn struct {
	cc      *grpc.ClientConn
	auth    pb.AuthServiceClient
	secrets pb.SecretsServiceClient
	token   string
	mu      sync.RWMutex
}

var _ Remote = (*Conn)(nil)

// Dial создаёт соединение с сервером по адресу addr (host:port). Соединение
// устанавливается лениво, при первом запросе. Размер сообщений ограничен
// pb.MaxMessageSize: по умолчанию gRPC не пропустил бы запись крупнее 4 МиБ.
func Dial(addr string, opts DialOptions) (*Conn, error) {
	creds, err := transportCredentials(opts)
	if err != nil {
		return nil, err
	}

	return dial(addr, creds)
}

// dial создаёт соединение с учётными данными creds и дополнительными
// параметрами extra (в тестах - подмена сетевого соединения).
func dial(target string, creds credentials.TransportCredentials, extra ...grpc.DialOption) (*Conn, error) {
	c := &Conn{}

	options := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		// Без этого при первом обращении gRPC ищет TXT-запись с профилем
		// сервиса в DNS, и подключение к localhost задерживается на секунды.
		grpc.WithDisableServiceConfig(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(pb.MaxMessageSize),
			grpc.MaxCallSendMsgSize(pb.MaxMessageSize),
		),
		grpc.WithChainUnaryInterceptor(c.tokenInterceptor),
	}
	options = append(options, extra...)

	cc, err := grpc.NewClient(target, options...)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать соединение с %q: %w", target, err)
	}

	c.cc = cc
	c.auth = pb.NewAuthServiceClient(cc)
	c.secrets = pb.NewSecretsServiceClient(cc)

	return c, nil
}

// transportCredentials создаёт учётные данные транспорта по параметрам opts.
func transportCredentials(opts DialOptions) (credentials.TransportCredentials, error) {
	if opts.Insecure {
		return insecure.NewCredentials(), nil
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS13}

	if opts.CAFile != "" {
		pemData, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("не удалось прочитать файл сертификата %q: %w", opts.CAFile, err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("в файле %q нет сертификатов в формате PEM", opts.CAFile)
		}
		cfg.RootCAs = pool
	}

	return credentials.NewTLS(cfg), nil
}

// Close закрывает соединение.
func (c *Conn) Close() error {
	if err := c.cc.Close(); err != nil {
		return fmt.Errorf("не удалось закрыть соединение: %w", err)
	}

	return nil
}

// SetToken задаёт токен доступа для следующих запросов, например сохранённый
// с прошлого входа. Register и Login вызывают его сами.
func (c *Conn) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.token = token
}

// currentToken возвращает текущий токен доступа.
func (c *Conn) currentToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.token
}

// tokenInterceptor добавляет токен доступа в метаданные запросов. Токен не
// отправляется методам аутентификации: им он не нужен.
func (c *Conn) tokenInterceptor(
	ctx context.Context,
	method string,
	req, reply any,
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	isAuthMethod := method == pb.AuthService_Register_FullMethodName || method == pb.AuthService_Login_FullMethodName

	if token := c.currentToken(); token != "" && !isAuthMethod {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	}

	return invoker(ctx, method, req, reply, cc, opts...)
}

// Register регистрирует пользователя. salt - соль вывода ключа шифрования
// (crypto.NewSalt), которую сервер сохранит и отдаст другим клиентам владельца.
// При успехе токен доступа сохраняется в соединении.
func (c *Conn) Register(ctx context.Context, login, password string, salt []byte) (AuthResult, error) {
	resp, err := c.auth.Register(ctx, &pb.RegisterRequest{Login: login, Password: password, KdfSalt: salt})
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			return AuthResult{}, ErrLoginTaken
		}

		return AuthResult{}, mapError(err)
	}

	return c.authResult(resp), nil
}

// Login выполняет вход. При успехе токен доступа сохраняется в соединении.
func (c *Conn) Login(ctx context.Context, login, password string) (AuthResult, error) {
	resp, err := c.auth.Login(ctx, &pb.LoginRequest{Login: login, Password: password})
	if err != nil {
		if status.Code(err) == codes.Unauthenticated {
			return AuthResult{}, ErrInvalidCredentials
		}

		return AuthResult{}, mapError(err)
	}

	return c.authResult(resp), nil
}

// authResult сохраняет токен из ответа и преобразует ответ в AuthResult.
func (c *Conn) authResult(resp *pb.AuthResponse) AuthResult {
	c.SetToken(resp.GetToken())

	return AuthResult{
		ExpiresAt: resp.GetExpiresAt().AsTime(),
		Token:     resp.GetToken(),
		KDFSalt:   resp.GetKdfSalt(),
	}
}

// Create создаёт запись на сервере. Реализует Remote.
func (c *Conn) Create(ctx context.Context, id string, kind model.Kind, payload []byte) (Secret, error) {
	resp, err := c.secrets.Create(ctx, &pb.CreateSecretRequest{
		Id: id, Type: pb.SecretType(kind), EncryptedPayload: payload,
	})
	if err != nil {
		return Secret{}, mapError(err)
	}

	return secretFromProto(resp)
}

// Get возвращает запись с сервера. Реализует Remote.
func (c *Conn) Get(ctx context.Context, id string) (Secret, error) {
	resp, err := c.secrets.Get(ctx, &pb.GetSecretRequest{Id: id})
	if err != nil {
		return Secret{}, mapError(err)
	}

	return secretFromProto(resp)
}

// Update изменяет запись на сервере. Реализует Remote.
func (c *Conn) Update(ctx context.Context, id string, kind model.Kind, payload []byte, expectedVersion int64) (Secret, error) {
	resp, err := c.secrets.Update(ctx, &pb.UpdateSecretRequest{
		Id: id, Type: pb.SecretType(kind), EncryptedPayload: payload, ExpectedVersion: expectedVersion,
	})
	if err != nil {
		return Secret{}, mapError(err)
	}

	return secretFromProto(resp)
}

// Delete удаляет запись на сервере. Реализует Remote.
func (c *Conn) Delete(ctx context.Context, id string, expectedVersion int64) error {
	_, err := c.secrets.Delete(ctx, &pb.DeleteSecretRequest{Id: id, ExpectedVersion: expectedVersion})

	return mapError(err)
}

// Sync запрашивает у сервера дельту синхронизации. Реализует Remote.
func (c *Conn) Sync(ctx context.Context, known []Known) ([]Secret, []string, error) {
	req := &pb.SyncRequest{Known: make([]*pb.SecretVersion, 0, len(known))}
	for _, k := range known {
		req.Known = append(req.Known, &pb.SecretVersion{Id: k.ID, Version: k.Version})
	}

	resp, err := c.secrets.Sync(ctx, req)
	if err != nil {
		return nil, nil, mapError(err)
	}

	changed := make([]Secret, 0, len(resp.GetChanged()))
	for _, s := range resp.GetChanged() {
		secret, convErr := secretFromProto(s)
		if convErr != nil {
			return nil, nil, convErr
		}
		changed = append(changed, secret)
	}

	return changed, resp.GetDeletedIds(), nil
}

// secretFromProto преобразует запись протокола в Secret. Тип записи
// проверяется до сужения до model.Kind, чтобы значение вне диапазона не
// превратилось в допустимое.
func secretFromProto(s *pb.Secret) (Secret, error) {
	t := s.GetType()
	if t < pb.SecretType_SECRET_TYPE_LOGIN_PASSWORD || t > pb.SecretType_SECRET_TYPE_CARD {
		return Secret{}, fmt.Errorf("сервер вернул запись %q неизвестного типа %d", s.GetId(), int32(t))
	}

	return Secret{
		UpdatedAt: s.GetUpdatedAt().AsTime(),
		ID:        s.GetId(),
		Payload:   s.GetEncryptedPayload(),
		Version:   s.GetVersion(),
		Kind:      model.Kind(t),
	}, nil
}

// mapError переводит ошибку gRPC в ошибки пакета. Ошибки, не относящиеся к
// gRPC, возвращаются как есть.
func mapError(err error) error {
	if err == nil {
		return nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	switch st.Code() {
	case codes.NotFound:
		return ErrNotFound
	case codes.AlreadyExists:
		return ErrAlreadyExists
	case codes.Aborted:
		return ErrVersionConflict
	case codes.Unauthenticated:
		return ErrUnauthenticated
	case codes.Unavailable:
		return fmt.Errorf("%w: %s", ErrUnavailable, st.Message())
	case codes.InvalidArgument:
		return fmt.Errorf("%w: %s", ErrRejected, st.Message())
	case codes.Canceled:
		return context.Canceled
	case codes.DeadlineExceeded:
		return context.DeadlineExceeded
	default:
		return errors.New("сервер вернул ошибку " + st.Code().String() + ": " + st.Message())
	}
}
