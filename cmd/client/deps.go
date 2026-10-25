package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/e-l-l-a-r/gophkeeper/internal/client"
	"github.com/e-l-l-a-r/gophkeeper/internal/model"
)

// errNotTerminal возвращается при попытке запросить секрет, когда ввод идёт не
// из терминала: секреты вводятся только интерактивно.
var errNotTerminal = errors.New("секрет можно ввести только интерактивно в терминале: " +
	"пароли не принимаются из флагов, переменных окружения и перенаправленного ввода")

// prompter запрашивает ввод у пользователя.
type prompter interface {
	// Line выводит приглашение и читает строку с отображением на экране.
	Line(prompt string) (string, error)
	// Secret выводит приглашение и читает секрет без отображения на экране.
	Secret(prompt string) (string, error)
}

// terminalPrompter запрашивает ввод в терминале. Приглашения выводятся в out
// (stderr), чтобы не смешиваться с результатом команды в stdout.
type terminalPrompter struct {
	in     *os.File
	reader *bufio.Reader
	out    io.Writer
}

var _ prompter = (*terminalPrompter)(nil)

// Line читает строку из общего буфера стандартного ввода без завершающего
// перевода строки.
func (p *terminalPrompter) Line(prompt string) (string, error) {
	if _, err := fmt.Fprint(p.out, prompt); err != nil {
		return "", err
	}

	line, err := p.reader.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", fmt.Errorf("не удалось прочитать ввод: %w", err)
	}

	return strings.TrimRight(line, "\r\n"), nil
}

// Secret читает секрет без отображения. Если ввод идёт не из терминала,
// возвращает errNotTerminal.
func (p *terminalPrompter) Secret(prompt string) (string, error) {
	fd := int(p.in.Fd())
	if !term.IsTerminal(fd) {
		return "", errNotTerminal
	}

	if _, err := fmt.Fprint(p.out, prompt); err != nil {
		return "", err
	}

	secret, err := term.ReadPassword(fd)
	// Терминал не отображает Enter при скрытом вводе: переводим строку сами.
	_, _ = fmt.Fprintln(p.out)
	if err != nil {
		return "", fmt.Errorf("не удалось прочитать секрет: %w", err)
	}

	return string(secret), nil
}

// connection - соединение с сервером, которое нужно командам клиента.
type connection interface {
	client.Remote
	// Register регистрирует пользователя и запоминает выданный токен.
	Register(ctx context.Context, login, password string, salt []byte) (client.AuthResult, error)
	// Login выполняет вход и запоминает выданный токен.
	Login(ctx context.Context, login, password string) (client.AuthResult, error)
	// SetToken задаёт токен доступа сохранённой сессии.
	SetToken(token string)
	// Close закрывает соединение.
	Close() error
}

// dialFunc создаёт соединение с сервером.
type dialFunc func(addr string, opts client.DialOptions) (connection, error)

// dialServer создаёт настоящее gRPC-соединение.
func dialServer(addr string, opts client.DialOptions) (connection, error) {
	conn, err := client.Dial(addr, opts)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// offlineRemote - заглушка сервера для локальных операций клиента (Add, Edit,
// Get, List, Remove): они к серверу не обращаются, а любая попытка обращения
// заканчивается ошибкой, а не паникой.
type offlineRemote struct{}

var _ client.Remote = offlineRemote{}

func (offlineRemote) Create(context.Context, string, model.Kind, []byte) (client.Secret, error) {
	return client.Secret{}, client.ErrUnavailable
}

func (offlineRemote) Get(context.Context, string) (client.Secret, error) {
	return client.Secret{}, client.ErrUnavailable
}

func (offlineRemote) Update(context.Context, string, model.Kind, []byte, int64) (client.Secret, error) {
	return client.Secret{}, client.ErrUnavailable
}

func (offlineRemote) Delete(context.Context, string, int64) error {
	return client.ErrUnavailable
}

func (offlineRemote) Sync(context.Context, []client.Known) ([]client.Secret, []string, error) {
	return nil, nil, client.ErrUnavailable
}
