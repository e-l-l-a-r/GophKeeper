// Client - консольный клиент менеджера паролей GophKeeper для Linux, macOS и
// Windows. Записи (логины и пароли, текст, бинарные данные, банковские карты)
// шифруются на устройстве мастер-паролем и хранятся на сервере только в виде
// шифротекста.
//
// Использование:
//
//	gophkeeper <команда> [флаги] [аргументы]
//
// Команды:
//
//	register   зарегистрироваться на сервере
//	login      войти на сервере
//	logout     завершить сессию (локальные записи сохраняются)
//	add        добавить запись: login, text, binary или card
//	get        показать запись
//	list       показать список записей
//	edit       изменить запись
//	delete     удалить запись
//	sync       синхронизировать записи с сервером
//	resolve    разрешить конфликт синхронизации
//	version    показать версию и дату сборки
//	help       показать справку
//
// Справка по команде: gophkeeper <команда> --help.
//
// Общие флаги всех команд, кроме version и help, и соответствующие
// переменные окружения (приоритет: окружение, флаг, файл конфигурации,
// значение по умолчанию):
//   - --server, -s / GOPHKEEPER_SERVER - адрес сервера; по умолчанию localhost:8443.
//   - --ca-file / GOPHKEEPER_CA_FILE - PEM-файл с доверенным сертификатом
//     сервера (нужен для самоподписанного сертификата).
//   - --insecure / GOPHKEEPER_INSECURE - отключить TLS; только для отладки.
//   - --dir / GOPHKEEPER_DIR - каталог состояния клиента; по умолчанию
//     gophkeeper в пользовательском каталоге настроек.
//   - --config, -c / GOPHKEEPER_CONFIG - JSON-файл с настройками server,
//     ca_file, dir и insecure.
//   - --timeout - ограничение времени сетевых операций; по умолчанию 1m.
//
// Секреты никогда не передаются флагами и переменными окружения, потому что
// их видно в списке процессов: пароль входа, мастер-пароль, пароли записей,
// номер карты и CVV вводятся интерактивно без отображения на экране. Если ввод
// происходит не в терминале, команда завершается с ошибкой.
//
// Мастер-пароль не сохраняется на диск и запрашивается при каждой команде,
// которой нужно расшифровывать записи (add, get, list, edit). Восстановить его
// нельзя: без него записи не прочитать.
//
// Команды add, edit, delete и resolve после локального изменения пытаются
// синхронизироваться с сервером; флаг --no-sync отключает это. Если сервер
// недоступен, изменение остаётся локальным и отправляется командой sync.
package main

import (
	"bufio"
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/e-l-l-a-r/gophkeeper/internal/crypto"
)

// Сведения о сборке; задаются при сборке через -ldflags "-X main.buildVersion=...".
var (
	buildVersion string
	buildDate    string
	buildCommit  string
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("ошибка: ")

	if err := execute(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// execute собирает приложение из настоящих терминала и сети и выполняет
// команду args. Ctrl+C и SIGTERM отменяют выполняемую сетевую операцию.
func execute(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stdin := bufio.NewReader(os.Stdin)

	a := &app{
		stdout: os.Stdout,
		stderr: os.Stderr,
		prompt: &terminalPrompter{in: os.Stdin, reader: stdin, out: os.Stderr},
		dial:   dialServer,
		now:    time.Now,
		build: buildInfo{
			version: buildVersion,
			date:    buildDate,
			commit:  buildCommit,
		},
		iterations: crypto.DefaultIterations,
	}

	return a.run(ctx, args)
}
