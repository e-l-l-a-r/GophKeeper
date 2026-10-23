package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/spf13/pflag"

	"github.com/e-l-l-a-r/gophkeeper/internal/auth"
	"github.com/e-l-l-a-r/gophkeeper/internal/config"
)

const (
	// defaultAddress - адрес gRPC-сервера по умолчанию.
	defaultAddress = "localhost:8443"
	// defaultLogLevel - уровень логирования по умолчанию.
	defaultLogLevel = "info"
	// defaultTokenTTL - срок действия токена доступа по умолчанию.
	defaultTokenTTL = 24 * time.Hour
)

// envConfig - настройки, прочитанные из переменных окружения. Указатели
// позволяют отличить незаданную переменную (nil) от заданной нулевым значением.
type envConfig struct {
	TokenTTL    *time.Duration `env:"TOKEN_TTL"`
	Insecure    *bool          `env:"INSECURE"`
	Address     string         `env:"ADDRESS"`
	LogLevel    string         `env:"LOG_LEVEL"`
	DatabaseDSN string         `env:"DATABASE_DSN"`
	TokenKey    string         `env:"TOKEN_KEY"`
	TLSCert     string         `env:"TLS_CERT"`
	TLSKey      string         `env:"TLS_KEY"`
	ConfigPath  string         `env:"CONFIG"`
}

// Config - итоговые настройки сервера после разрешения приоритета окружения,
// флагов и файла конфигурации.
//
// Config содержит секреты (DatabaseDSN, TokenKey): не выводите его в лог целиком.
type Config struct {
	Address     string
	LogLevel    string
	DatabaseDSN string
	TokenKey    string
	TLSCert     string
	TLSKey      string
	ConfigPath  string
	TokenTTL    time.Duration
	Insecure    bool
}

// getConfig собирает настройки и проверяет их корректность. Сообщения об
// ошибках разбора аргументов и справка выводятся в output.
func getConfig(args []string, output io.Writer) (Config, error) {
	conf, err := parseConfig(args, output)
	if err != nil {
		return Config{}, err
	}

	if err := conf.validate(); err != nil {
		return Config{}, err
	}

	return conf, nil
}

// parseConfig собирает настройки из окружения, аргументов args и файла
// конфигурации. Приоритет: окружение, флаг, файл, значение по умолчанию.
//
// Секреты (строка подключения к базе, ключ подписи токенов, пути к ключам и
// сертификатам TLS) задаются только через окружение или файл конфигурации:
// значения флагов видны в списке процессов.
func parseConfig(args []string, output io.Writer) (Config, error) {
	var envConf envConfig
	if err := env.Parse(&envConf); err != nil {
		return Config{}, fmt.Errorf("не удалось разобрать переменные окружения: %w", err)
	}

	fs := pflag.NewFlagSet("server", pflag.ContinueOnError)
	fs.SetOutput(output)

	flagAddress := fs.StringP("address", "a", defaultAddress, "адрес и порт gRPC-сервера")
	flagLogLevel := fs.StringP("log-level", "l", defaultLogLevel, "уровень логирования: debug, info, warn, error")
	flagTokenTTL := fs.Duration("token-ttl", defaultTokenTTL, "срок действия токена доступа")
	flagInsecure := fs.Bool("insecure", false, "отключить TLS (только для локальной отладки)")
	flagConfig := fs.StringP("config", "c", "", "путь к файлу конфигурации в формате JSON")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Сервер GophKeeper.\nИспользование: %s [флаги]\n\n%s\n"+
			"Секреты задаются только переменными окружения или файлом конфигурации:\n"+
			"  DATABASE_DSN, TOKEN_KEY, TLS_CERT, TLS_KEY\n", fs.Name(), fs.FlagUsages())
	}

	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("не удалось разобрать аргументы: %w", err)
	}

	configPath := envConf.ConfigPath
	if configPath == "" {
		configPath = *flagConfig
	}

	var fileConf config.Server
	if err := config.Load(configPath, &fileConf); err != nil {
		return Config{}, err
	}

	return Config{
		ConfigPath: configPath,
		Address: config.ResolveString(envConf.Address,
			fs.Changed("address"), *flagAddress, fileConf.Address),
		LogLevel: config.ResolveString(envConf.LogLevel,
			fs.Changed("log-level"), *flagLogLevel, fileConf.LogLevel),
		DatabaseDSN: config.ResolveString(envConf.DatabaseDSN, false, "", fileConf.DatabaseDSN),
		TokenKey:    config.ResolveString(envConf.TokenKey, false, "", fileConf.TokenKey),
		TLSCert:     config.ResolveString(envConf.TLSCert, false, "", fileConf.TLSCert),
		TLSKey:      config.ResolveString(envConf.TLSKey, false, "", fileConf.TLSKey),
		TokenTTL: config.ResolveDuration(envConf.TokenTTL,
			fs.Changed("token-ttl"), *flagTokenTTL, fileConf.TokenTTL),
		Insecure: config.ResolveBool(envConf.Insecure,
			fs.Changed("insecure"), *flagInsecure, fileConf.Insecure),
	}, nil
}

// validate проверяет, что заданы все обязательные настройки и что они
// допустимы. Сервер без ключа подписи токенов или без TLS не стартует.
func (c Config) validate() error {
	var errs []error

	if c.Address == "" {
		errs = append(errs, errors.New("не задан адрес сервера"))
	}
	if c.DatabaseDSN == "" {
		errs = append(errs, errors.New("не задана строка подключения к базе (DATABASE_DSN)"))
	}
	if len(c.TokenKey) < auth.MinTokenKeySize {
		errs = append(errs, fmt.Errorf(
			"ключ подписи токенов (TOKEN_KEY) должен быть не короче %d символов, например: openssl rand -hex 32",
			auth.MinTokenKeySize))
	}
	if c.TokenTTL <= 0 {
		errs = append(errs, errors.New("срок действия токена должен быть положительным"))
	}
	if !c.Insecure && (c.TLSCert == "" || c.TLSKey == "") {
		errs = append(errs, errors.New(
			"не заданы сертификат и ключ TLS (TLS_CERT, TLS_KEY); для локальной отладки используйте --insecure"))
	}

	return errors.Join(errs...)
}
