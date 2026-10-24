package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/spf13/pflag"

	"github.com/e-l-l-a-r/gophkeeper/internal/config"
	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
)

const (
	// defaultServer - адрес сервера по умолчанию.
	defaultServer = "localhost:8443"
	// defaultTimeout - ограничение времени сетевых операций по умолчанию.
	defaultTimeout = time.Minute
)

// envConfig - настройки, прочитанные из переменных окружения. Указатель у
// Insecure позволяет отличить незаданную переменную от заданной значением false.
type envConfig struct {
	Insecure   *bool  `env:"GOPHKEEPER_INSECURE"`
	Server     string `env:"GOPHKEEPER_SERVER"`
	CAFile     string `env:"GOPHKEEPER_CA_FILE"`
	Dir        string `env:"GOPHKEEPER_DIR"`
	ConfigPath string `env:"GOPHKEEPER_CONFIG"`
}

// globals - общие настройки всех команд после разрешения приоритета источников.
type globals struct {
	server   string
	caFile   string
	dir      string
	timeout  time.Duration
	insecure bool
}

// globalFlags - значения общих флагов до разрешения приоритета.
type globalFlags struct {
	server   *string
	caFile   *string
	dir      *string
	config   *string
	timeout  *time.Duration
	insecure *bool
}

// addGlobalFlags добавляет в fs общие флаги команд.
func addGlobalFlags(fs *pflag.FlagSet) globalFlags {
	return globalFlags{
		server: fs.StringP("server", "s", defaultServer, "адрес сервера (host:port)"),
		caFile: fs.String("ca-file", "", "PEM-файл с доверенным сертификатом сервера"),
		dir:    fs.String("dir", "", "каталог состояния клиента (по умолчанию в каталоге настроек пользователя)"),
		config: fs.StringP("config", "c", "", "JSON-файл с настройками клиента"),
		timeout: fs.Duration("timeout", defaultTimeout,
			"ограничение времени сетевых операций"),
		insecure: fs.Bool("insecure", false, "отключить TLS (только для локальной отладки)"),
	}
}

// resolveGlobals собирает общие настройки из окружения, флагов fs и файла
// конфигурации. Приоритет: окружение, флаг, файл, значение по умолчанию.
func resolveGlobals(fs *pflag.FlagSet, flags globalFlags) (globals, error) {
	var envConf envConfig
	if err := env.Parse(&envConf); err != nil {
		return globals{}, fmt.Errorf("не удалось разобрать переменные окружения: %w", err)
	}

	configPath := envConf.ConfigPath
	if configPath == "" {
		configPath = *flags.config
	}

	var file config.Client
	if err := config.Load(configPath, &file); err != nil {
		return globals{}, err
	}

	g := globals{
		server: config.ResolveString(envConf.Server,
			fs.Changed("server"), *flags.server, file.Server),
		caFile: config.ResolveString(envConf.CAFile,
			fs.Changed("ca-file"), *flags.caFile, file.CAFile),
		dir: config.ResolveString(envConf.Dir,
			fs.Changed("dir"), *flags.dir, file.Dir),
		timeout: *flags.timeout,
		insecure: config.ResolveBool(envConf.Insecure,
			fs.Changed("insecure"), *flags.insecure, file.Insecure),
	}

	if g.dir == "" {
		dir, err := localstore.DefaultDir()
		if err != nil {
			return globals{}, err
		}
		g.dir = dir
	}

	return g, g.validate()
}

// validate проверяет допустимость общих настроек.
func (g globals) validate() error {
	var errs []error

	if g.server == "" {
		errs = append(errs, errors.New("не задан адрес сервера"))
	}
	if g.timeout <= 0 {
		errs = append(errs, errors.New("ограничение времени --timeout должно быть положительным"))
	}

	return errors.Join(errs...)
}
