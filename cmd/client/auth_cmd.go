package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/e-l-l-a-r/gophkeeper/internal/client"
	"github.com/e-l-l-a-r/gophkeeper/internal/crypto"
	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
)

// parseNoArgs разбирает флаги команды без позиционных аргументов и возвращает
// общие настройки. Для --help возвращает pflag.ErrHelp.
func (a *app) parseNoArgs(name, usage string, args []string) (globals, error) {
	fs := a.flagSet(name)
	flags := addGlobalFlags(fs)
	fs.Usage = func() { a.commandUsage(fs, usage) }

	if err := fs.Parse(args); err != nil {
		return globals{}, err
	}
	if fs.NArg() != 0 {
		return globals{}, fmt.Errorf("команда %s не принимает аргументов, получено: %s",
			name, strings.Join(fs.Args(), " "))
	}

	return resolveGlobals(fs, flags)
}

// commandUsage выводит справку по команде: описание usage и список флагов.
func (a *app) commandUsage(fs interface{ FlagUsages() string }, usage string) {
	_, _ = fmt.Fprintf(a.stderr, "%s\n\nФлаги:\n%s", usage, fs.FlagUsages())
}

// cmdRegister регистрирует пользователя: запрашивает логин и пароль входа,
// создаёт соль ключа шифрования и сохраняет сессию.
func (a *app) cmdRegister(ctx context.Context, args []string) error {
	g, err := a.parseNoArgs("register",
		"Использование: gophkeeper register\n\n"+
			"Регистрирует нового пользователя. Пароль входа и мастер-пароль - разные секреты:\n"+
			"пароль входа знает сервер, мастер-пароль шифрует записи и сервер его не знает.", args)
	if err != nil {
		return err
	}

	login, err := a.prompt.Line("Логин: ")
	if err != nil {
		return err
	}
	login = strings.TrimSpace(login)

	password, err := a.prompt.Secret("Пароль входа: ")
	if err != nil {
		return err
	}
	again, err := a.prompt.Secret("Повторите пароль входа: ")
	if err != nil {
		return err
	}
	if password != again {
		return errors.New("пароли не совпадают")
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}

	s, err := openStore(g)
	if err != nil {
		return err
	}

	conn, err := a.dial(g.server, client.DialOptions{CAFile: g.caFile, Insecure: g.insecure})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	callCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	res, err := conn.Register(callCtx, login, password, salt)
	if err != nil {
		return explainAuth(err)
	}

	if err := s.store.SaveSession(localstore.Session{
		ExpiresAt: res.ExpiresAt, Server: g.server, Login: login, Token: res.Token, KDFSalt: res.KDFSalt,
	}); err != nil {
		return err
	}

	return a.printf("Пользователь %q зарегистрирован.\n"+
		"Запомните мастер-пароль, который вы будете вводить при работе с записями: восстановить его нельзя.\n", login)
}

// cmdLogin выполняет вход: запрашивает логин и пароль входа и сохраняет сессию
// с солью ключа шифрования, которую выдал сервер.
func (a *app) cmdLogin(ctx context.Context, args []string) error {
	g, err := a.parseNoArgs("login",
		"Использование: gophkeeper login\n\nВыполняет вход на сервере. Локальные записи сохраняются.", args)
	if err != nil {
		return err
	}

	login, err := a.prompt.Line("Логин: ")
	if err != nil {
		return err
	}
	login = strings.TrimSpace(login)

	password, err := a.prompt.Secret("Пароль входа: ")
	if err != nil {
		return err
	}

	s, err := openStore(g)
	if err != nil {
		return err
	}

	conn, err := a.dial(g.server, client.DialOptions{CAFile: g.caFile, Insecure: g.insecure})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	callCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	res, err := conn.Login(callCtx, login, password)
	if err != nil {
		return explainAuth(err)
	}

	if err := s.store.SaveSession(localstore.Session{
		ExpiresAt: res.ExpiresAt, Server: g.server, Login: login, Token: res.Token, KDFSalt: res.KDFSalt,
	}); err != nil {
		return err
	}

	return a.printf("Вход выполнен: %s\n", login)
}

// cmdLogout удаляет сохранённую сессию. Кеш записей остаётся на диске.
func (a *app) cmdLogout(_ context.Context, args []string) error {
	g, err := a.parseNoArgs("logout",
		"Использование: gophkeeper logout\n\nЗавершает сессию. Локальные записи и несинхронизированные изменения сохраняются.", args)
	if err != nil {
		return err
	}

	s, err := openStore(g)
	if err != nil {
		return err
	}

	if err := s.store.ClearSession(); err != nil {
		return err
	}

	return a.printf("Сессия завершена.\n")
}

// explainAuth добавляет к ошибкам регистрации и входа понятные пояснения.
func explainAuth(err error) error {
	switch {
	case errors.Is(err, client.ErrLoginTaken):
		return errors.New("такой логин уже занят")
	case errors.Is(err, client.ErrInvalidCredentials):
		return errors.New("неверный логин или пароль")
	case errors.Is(err, client.ErrUnavailable):
		return fmt.Errorf("сервер недоступен (проверьте адрес и сертификат): %w", err)
	default:
		return err
	}
}
