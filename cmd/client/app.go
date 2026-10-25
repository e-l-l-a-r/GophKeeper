package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/e-l-l-a-r/gophkeeper/internal/client"
	"github.com/e-l-l-a-r/gophkeeper/internal/crypto"
	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
	"github.com/e-l-l-a-r/gophkeeper/internal/logger"
)

// buildInfo - сведения о сборке исполняемого файла.
type buildInfo struct {
	version string
	date    string
	commit  string
}

// app - приложение командной строки. Все внешние зависимости (ввод, вывод,
// терминал, сеть, время) передаются явно, поэтому команды тестируются без
// терминала и сервера.
type app struct {
	prompt prompter
	dial   dialFunc
	now    func() time.Time
	stdout io.Writer
	stderr io.Writer
	build  buildInfo
	// iterations - число итераций PBKDF2 для ключа шифрования новых записей.
	iterations int
}

// command - подкоманда: имя, краткое описание и обработчик.
type command struct {
	run   func(a *app, ctx context.Context, args []string) error
	name  string
	short string
}

// commands - все подкоманды в порядке вывода в справке.
func commands() []command {
	return []command{
		{name: "register", short: "зарегистрироваться на сервере", run: (*app).cmdRegister},
		{name: "login", short: "войти на сервере", run: (*app).cmdLogin},
		{name: "logout", short: "завершить сессию (локальные записи сохраняются)", run: (*app).cmdLogout},
		{name: "add", short: "добавить запись: login, text, binary или card", run: (*app).cmdAdd},
		{name: "get", short: "показать запись", run: (*app).cmdGet},
		{name: "list", short: "показать список записей", run: (*app).cmdList},
		{name: "edit", short: "изменить запись", run: (*app).cmdEdit},
		{name: "delete", short: "удалить запись", run: (*app).cmdDelete},
		{name: "sync", short: "синхронизировать записи с сервером", run: (*app).cmdSync},
		{name: "resolve", short: "разрешить конфликт синхронизации", run: (*app).cmdResolve},
	}
}

// run разбирает имя команды из args и выполняет её. Справка и версия не
// требуют настроек и сети.
func (a *app) run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		a.usage(a.stderr)

		return errors.New("не указана команда")
	}

	name, rest := args[0], args[1:]

	switch name {
	case "help", "-h", "--help":
		a.usage(a.stdout)

		return nil
	case "version", "--version", "-v":
		return logger.PrintBuildInfo(a.stdout, a.build.version, a.build.date, a.build.commit)
	}

	for _, cmd := range commands() {
		if cmd.name == name {
			err := cmd.run(a, ctx, rest)
			if errors.Is(err, pflag.ErrHelp) {
				return nil
			}

			return err
		}
	}

	a.usage(a.stderr)

	return fmt.Errorf("неизвестная команда %q", name)
}

// usage выводит общую справку.
func (a *app) usage(w io.Writer) {
	var b strings.Builder

	b.WriteString("GophKeeper - менеджер паролей.\n\nИспользование:\n  gophkeeper <команда> [флаги] [аргументы]\n\nКоманды:\n")

	for _, cmd := range commands() {
		fmt.Fprintf(&b, "  %-10s %s\n", cmd.name, cmd.short)
	}

	b.WriteString("  version    показать версию и дату сборки\n  help       показать эту справку\n\n")
	b.WriteString("Справка по команде: gophkeeper <команда> --help\n")

	_, _ = io.WriteString(w, b.String())
}

// flagSet создаёт набор флагов команды name: ошибки разбора возвращаются,
// справка и сообщения выводятся в stderr.
func (a *app) flagSet(name string) *pflag.FlagSet {
	fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
	fs.SetOutput(a.stderr)

	return fs
}

// session - всё, что нужно команде для работы: состояние на диске, кеш
// записей и клиент.
type session struct {
	store *localstore.Store
	// cache - кеш записей текущего пользователя; nil, если вход не выполнен.
	cache *localstore.Cache
	// sess - сохранённая сессия; нулевая, если вход не выполнен.
	sess localstore.Session
	g    globals
}

// openStore открывает каталог состояния клиента.
func openStore(g globals) (*session, error) {
	store, err := localstore.Open(g.dir)
	if err != nil {
		return nil, err
	}

	return &session{store: store, g: g}, nil
}

// loadSession загружает сохранённую сессию и кеш её пользователя. Без входа
// возвращает localstore.ErrNoSession.
func loadSession(g globals) (*session, error) {
	s, err := openStore(g)
	if err != nil {
		return nil, err
	}

	s.sess, err = s.store.LoadSession()
	if err != nil {
		return nil, err
	}

	s.cache, err = s.store.OpenCache(s.sess.Server, s.sess.Login)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// keyring запрашивает мастер-пароль и выводит из него ключи шифрования.
// Мастер-пароль нигде не сохраняется. При confirm пароль запрашивается дважды
// для защиты от опечатки: при первой записи проверить пароль нечем.
func (a *app) keyring(sess localstore.Session, confirm bool) (*crypto.Keyring, error) {
	password, err := a.prompt.Secret("Мастер-пароль: ")
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, errors.New("мастер-пароль не может быть пустым")
	}

	if confirm {
		again, err := a.prompt.Secret("Повторите мастер-пароль: ")
		if err != nil {
			return nil, err
		}
		if again != password {
			return nil, errors.New("мастер-пароли не совпадают")
		}
	}

	return crypto.NewKeyring(password, sess.KDFSalt, a.iterations)
}

// hasEntries сообщает, есть ли в кеше записи, по которым можно проверить
// мастер-пароль. Если их нет, мастер-пароль при добавлении запрашивается
// дважды.
func hasEntries(cache *localstore.Cache) bool {
	for _, rec := range cache.Records() {
		if rec.Pending != localstore.PendingDelete && len(rec.Payload) > 0 {
			return true
		}
	}

	return false
}

// remoteSession - соединение с сервером с токеном сохранённой сессии.
type remoteSession struct {
	conn   connection
	cancel context.CancelFunc
}

// close закрывает соединение и освобождает ресурсы контекста.
func (r *remoteSession) close() {
	r.cancel()
	_ = r.conn.Close()
}

// connect подключается к серверу сохранённой сессии. Токен, срок действия
// которого истёк, не используется: возвращается ошибка с просьбой войти заново.
func (a *app) connect(ctx context.Context, s *session) (*remoteSession, context.Context, error) {
	if s.sess.Expired(a.now()) {
		return nil, nil, fmt.Errorf("срок действия сессии истёк: выполните gophkeeper login")
	}

	conn, err := a.dial(s.sess.Server, client.DialOptions{CAFile: s.g.caFile, Insecure: s.g.insecure})
	if err != nil {
		return nil, nil, err
	}

	conn.SetToken(s.sess.Token)

	ctx, cancel := context.WithTimeout(ctx, s.g.timeout)

	return &remoteSession{conn: conn, cancel: cancel}, ctx, nil
}

// printf пишет в stdout; ошибка записи в stdout возвращается вызывающему.
func (a *app) printf(format string, args ...any) error {
	_, err := fmt.Fprintf(a.stdout, format, args...)

	return err
}

// explain превращает ошибки клиента в понятные сообщения для пользователя.
func explain(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, localstore.ErrNoSession):
		return errors.New("вы не вошли: выполните gophkeeper login или gophkeeper register")
	case errors.Is(err, client.ErrUnauthenticated):
		return errors.New("сессия недействительна или истекла: выполните gophkeeper login")
	case errors.Is(err, crypto.ErrDecrypt):
		return fmt.Errorf("неверный мастер-пароль или повреждённые данные: %w", err)
	default:
		return err
	}
}
