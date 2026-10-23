// Server запускает gRPC-сервер менеджера паролей GophKeeper: регистрацию и
// аутентификацию пользователей, хранение зашифрованных записей в PostgreSQL и
// их синхронизацию между клиентами. Сервер не видит данные в открытом виде:
// записи шифруются на клиенте.
//
// Настройки задаются переменными окружения, флагами командной строки или
// файлом конфигурации в формате JSON. Приоритет источников: окружение, флаг,
// файл, значение по умолчанию.
//
// Флаги и переменные окружения:
//   - --address, -a / ADDRESS - адрес и порт сервера; по умолчанию localhost:8443.
//   - --log-level, -l / LOG_LEVEL - уровень логирования: debug, info, warn или
//     error; по умолчанию info.
//   - --token-ttl / TOKEN_TTL - срок действия токена доступа; по умолчанию 24h.
//   - --insecure / INSECURE - отключить TLS; только для локальной отладки.
//   - --config, -c / CONFIG - путь к файлу конфигурации в формате JSON.
//
// Секреты задаются только переменными окружения или файлом конфигурации (флагов
// для них нет, так как значения флагов видны в списке процессов):
//   - DATABASE_DSN (database_dsn) - строка подключения к PostgreSQL; обязательна.
//   - TOKEN_KEY (token_key) - ключ подписи токенов не короче 32 символов;
//     обязателен, значения по умолчанию нет. Пример: openssl rand -hex 32.
//   - TLS_CERT (tls_cert) и TLS_KEY (tls_key) - пути к сертификату и закрытому
//     ключу TLS в формате PEM; обязательны, пока не указан --insecure.
//
// При старте сервер проверяет доступность базы данных и применяет миграции.
// По сигналам SIGINT, SIGTERM и SIGQUIT сервер плавно завершает работу.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"go.uber.org/fx"
	"google.golang.org/grpc"

	"github.com/e-l-l-a-r/gophkeeper/internal/logger"
)

// appStopTimeout - общее время на остановку всех компонентов приложения.
const appStopTimeout = 30 * time.Second

// Сведения о сборке; задаются при сборке через -ldflags "-X main.buildVersion=...".
var (
	buildVersion string
	buildDate    string
	buildCommit  string
)

// newApp собирает граф зависимостей приложения. Провайдер хранилища
// storageProvider передаётся снаружи: сервер использует provideStorage
// (PostgreSQL), а тесты - хранилище в памяти.
func newApp(args []string, errs *serverErrors, storageProvider any) *fx.App {
	return fx.New(
		fx.NopLogger,
		fx.StopTimeout(appStopTimeout),
		fx.Provide(
			func() (Config, error) { return getConfig(args, os.Stderr) },
			func() serverErrors { return make(serverErrors, 1) },
			provideLogger,
			storageProvider,
			provideTokenManager,
			provideHasher,
			provideAuthService,
			provideSecretsService,
			provideListener,
			provideGRPCServer,
		),
		fx.Populate(errs),
		fx.Invoke(func(*grpc.Server) {}),
	)
}

func main() {
	if err := execute(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// execute выводит сведения о сборке и запускает сервер, который работает до
// сигнала завершения.
func execute(args []string) error {
	if err := logger.PrintBuildInfo(os.Stdout, buildVersion, buildDate, buildCommit); err != nil {
		return err
	}

	// Подписываемся на сигналы до запуска компонентов, чтобы не потерять сигнал,
	// пришедший во время старта.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer stop()

	return run(ctx, args, provideStorage)
}

// run запускает приложение и работает, пока не отменён ctx или сервер не
// сообщит об ошибке. Затем останавливает компоненты в порядке, обратном запуску:
// сначала gRPC-сервер, затем закрывается подключение к базе данных.
func run(ctx context.Context, args []string, storageProvider any) error {
	var errs serverErrors

	app := newApp(args, &errs, storageProvider)
	if err := app.Err(); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil
		}

		return err
	}

	if err := app.Start(ctx); err != nil {
		return err
	}

	var runErr error
	select {
	case runErr = <-errs:
	case <-ctx.Done():
	}

	// Останавливаем компоненты, даже если сервер завершился с ошибкой.
	stopCtx, cancel := context.WithTimeout(context.Background(), appStopTimeout)
	defer cancel()

	if err := app.Stop(stopCtx); err != nil {
		runErr = errors.Join(runErr, err)
	}

	return runErr
}
