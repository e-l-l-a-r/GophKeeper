package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"go.uber.org/fx"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/e-l-l-a-r/gophkeeper/internal/auth"
	"github.com/e-l-l-a-r/gophkeeper/internal/logger"
	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
	"github.com/e-l-l-a-r/gophkeeper/internal/service"
	"github.com/e-l-l-a-r/gophkeeper/internal/storage"
)

const (
	// serverShutdownTimeout - время на плавную остановку gRPC-сервера, после
	// которого оставшиеся соединения закрываются принудительно.
	serverShutdownTimeout = 5 * time.Second
	// dbPingTimeout - время ожидания ответа базы данных при старте.
	dbPingTimeout = 10 * time.Second
)

// serverErrors - канал, по которому gRPC-сервер сообщает об ошибке Serve,
// возникшей после успешного старта.
type serverErrors chan error

// stores - хранилища, необходимые сервисам. Один провайдер даёт оба
// интерфейса, чтобы в тестах их можно было заменить реализацией в памяти.
type stores struct {
	fx.Out

	Users   storage.UserStorage
	Secrets storage.SecretStorage
}

// provideLogger создаёт логгер по итоговой конфигурации.
func provideLogger(conf Config) (*logger.Logger, error) {
	return logger.New(conf.LogLevel)
}

// provideStorage создаёт хранилище на PostgreSQL. При старте приложение
// проверяет доступность базы и применяет миграции, при остановке закрывает
// подключение. Хук хранилища регистрируется раньше хука сервера, поэтому при
// остановке подключение закрывается уже после остановки сервера.
func provideStorage(lc fx.Lifecycle, conf Config, log *logger.Logger) (stores, error) {
	pg, err := storage.NewPostgres(conf.DatabaseDSN)
	if err != nil {
		return stores{}, err
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			pingCtx, cancel := context.WithTimeout(ctx, dbPingTimeout)
			defer cancel()

			if err := pg.Ping(pingCtx); err != nil {
				return errors.Join(err, pg.Close())
			}

			log.Info("применяю миграции базы данных")
			if err := pg.Migrate(); err != nil {
				return errors.Join(err, pg.Close())
			}

			return nil
		},
		OnStop: func(context.Context) error {
			return pg.Close()
		},
	})

	return stores{Users: pg, Secrets: pg}, nil
}

// provideTokenManager создаёт менеджер токенов доступа.
func provideTokenManager(conf Config) (*auth.TokenManager, error) {
	return auth.NewTokenManager([]byte(conf.TokenKey), conf.TokenTTL)
}

// provideHasher создаёт хешер паролей со стойким числом итераций PBKDF2.
func provideHasher() (*auth.PasswordHasher, error) {
	return auth.NewPasswordHasher(auth.DefaultPBKDF2Iterations)
}

// provideAuthService создаёт сервис регистрации и входа.
func provideAuthService(
	users storage.UserStorage,
	hasher *auth.PasswordHasher,
	tokens *auth.TokenManager,
	log *logger.Logger,
) (*service.AuthService, error) {
	return service.NewAuthService(users, hasher, tokens, log)
}

// provideSecretsService создаёт сервис записей.
func provideSecretsService(secrets storage.SecretStorage, log *logger.Logger) *service.SecretsService {
	return service.NewSecretsService(secrets, log)
}

// provideListener занимает сетевой адрес сервера. Адрес занимается при сборке
// приложения, поэтому ошибка привязки (адрес занят, некорректный адрес)
// прерывает запуск до старта остальных компонентов.
func provideListener(lc fx.Lifecycle, conf Config) (net.Listener, error) {
	var lcfg net.ListenConfig

	ln, err := lcfg.Listen(context.Background(), "tcp", conf.Address)
	if err != nil {
		return nil, fmt.Errorf("не удалось занять адрес %q: %w", conf.Address, err)
	}

	lc.Append(fx.Hook{OnStop: func(context.Context) error {
		// Остановка gRPC-сервера уже закрыла слушатель; повторное закрытие не ошибка.
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}

		return nil
	}})

	return ln, nil
}

// provideGRPCServer создаёт gRPC-сервер с сервисами AuthService и
// SecretsService, интерцептором авторизации и TLS (если он не отключён).
// Сервер запускается в OnStart; ошибка Serve после старта передаётся в errs.
func provideGRPCServer(
	lc fx.Lifecycle,
	conf Config,
	log *logger.Logger,
	ln net.Listener,
	tokens *auth.TokenManager,
	authSvc *service.AuthService,
	secretsSvc *service.SecretsService,
	errs serverErrors,
) (*grpc.Server, error) {
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(pb.MaxMessageSize),
		grpc.ChainUnaryInterceptor(auth.UnaryInterceptor(tokens,
			pb.AuthService_Register_FullMethodName,
			pb.AuthService_Login_FullMethodName,
		)),
	}

	if !conf.Insecure {
		creds, err := loadTLS(conf.TLSCert, conf.TLSKey)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.Creds(creds))
	}

	server := grpc.NewServer(opts...)
	pb.RegisterAuthServiceServer(server, authSvc)
	pb.RegisterSecretsServiceServer(server, secretsSvc)

	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			if conf.Insecure {
				log.Warn("TLS отключён: данные передаются по сети в открытом виде, используйте только для отладки")
			}
			log.Info("gRPC-сервер запущен",
				zap.String("адрес", ln.Addr().String()), zap.Bool("tls", !conf.Insecure))

			go func() {
				if err := server.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
					errs <- err
				}
			}()

			return nil
		},
		OnStop: func(context.Context) error {
			log.Info("останавливаю gRPC-сервер")

			stopped := make(chan struct{})
			go func() {
				server.GracefulStop()
				close(stopped)
			}()

			select {
			case <-stopped:
			case <-time.After(serverShutdownTimeout):
				server.Stop()
			}

			return nil
		},
	})

	return server, nil
}

// loadTLS загружает пару сертификат/ключ и создаёт серверные учётные данные
// TLS не ниже версии 1.3.
func loadTLS(certFile, keyFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить сертификат и ключ TLS: %w", err)
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}), nil
}
