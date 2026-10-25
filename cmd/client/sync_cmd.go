package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/e-l-l-a-r/gophkeeper/internal/client"
)

// syncAfter синхронизируется с сервером после локального изменения, если
// не указан --no-sync. Недоступность сервера и просроченная сессия не считаются
// ошибкой команды: изменение уже сохранено локально и уйдёт командой sync.
func (a *app) syncAfter(ctx context.Context, s *session, noSync bool) error {
	if noSync {
		return nil
	}

	remote, callCtx, err := a.connect(ctx, s)
	if err != nil {
		return a.printf("Изменение сохранено локально, на сервер не отправлено: %v\n", err)
	}
	defer remote.close()

	res, err := client.New(remote.conn, s.cache, nil).Sync(callCtx)
	switch {
	case err == nil, errors.Is(err, client.ErrConflict):
		return a.reportSync(res, err)
	case errors.Is(err, client.ErrUnavailable), errors.Is(err, client.ErrUnauthenticated),
		errors.Is(err, context.DeadlineExceeded):
		return a.printf("Изменение сохранено локально, на сервер не отправлено: %v\n", explain(err))
	default:
		return explain(err)
	}
}

// cmdSync синхронизирует записи с сервером и сообщает о конфликтах.
func (a *app) cmdSync(ctx context.Context, args []string) error {
	g, err := a.parseNoArgs("sync",
		"Использование: gophkeeper sync\n\n"+
			"Отправляет локальные изменения на сервер и получает изменения с других устройств.\n"+
			"Мастер-пароль не нужен: записи не расшифровываются.", args)
	if err != nil {
		return err
	}

	s, err := loadSession(g)
	if err != nil {
		return explain(err)
	}

	remote, callCtx, err := a.connect(ctx, s)
	if err != nil {
		return err
	}
	defer remote.close()

	res, err := client.New(remote.conn, s.cache, nil).Sync(callCtx)
	if err != nil && !errors.Is(err, client.ErrConflict) {
		return explain(err)
	}

	return a.reportSync(res, err)
}

// reportSync выводит итог синхронизации. Конфликты выводятся списком, а
// команда завершается с ошибкой, чтобы скрипты могли их заметить.
func (a *app) reportSync(res client.SyncResult, syncErr error) error {
	if err := a.printf("Отправлено: %d, получено: %d, удалено локально: %d\n",
		res.Pushed, res.Pulled, res.Removed); err != nil {
		return err
	}

	if len(res.Conflicts) == 0 {
		return nil
	}

	if err := a.printf("Конфликты (%d):\n", len(res.Conflicts)); err != nil {
		return err
	}

	for _, c := range res.Conflicts {
		if err := a.printf("  %s  %s\n", c.ID, describeConflict(c)); err != nil {
			return err
		}
	}

	if err := a.printf("Разрешите конфликт: gophkeeper resolve <id> --keep local|server\n"); err != nil {
		return err
	}

	return syncErr
}

// describeConflict объясняет причину конфликта человеческим языком.
func describeConflict(c client.Conflict) string {
	switch c.Reason {
	case client.ConflictVersion:
		return "запись изменена на сервере другим устройством"
	case client.ConflictDeleted:
		return "запись удалена на сервере, а здесь изменена"
	case client.ConflictExists:
		return "идентификатор новой записи уже занят"
	default:
		return string(c.Reason)
	}
}

// cmdResolve разрешает конфликт синхронизации по записи.
func (a *app) cmdResolve(ctx context.Context, args []string) error {
	fs := a.flagSet("resolve")
	flags := addGlobalFlags(fs)
	keep := fs.String("keep", "", "чью версию оставить: local (локальную) или server (серверную)")
	noSync := fs.Bool("no-sync", false, "не синхронизироваться с сервером после решения")
	fs.Usage = func() {
		a.commandUsage(fs, "Использование: gophkeeper resolve <id> --keep local|server [флаги]\n\n"+
			"local  - оставить локальное изменение: оно будет отправлено на сервер поверх серверной версии.\n"+
			"server - отбросить локальное изменение и принять версию сервера.")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("укажите идентификатор записи")
	}

	decision, err := parseKeep(*keep)
	if err != nil {
		return err
	}

	g, err := resolveGlobals(fs, flags)
	if err != nil {
		return err
	}

	s, err := loadSession(g)
	if err != nil {
		return explain(err)
	}

	remote, callCtx, err := a.connect(ctx, s)
	if err != nil {
		return err
	}

	err = client.New(remote.conn, s.cache, nil).Resolve(callCtx, fs.Arg(0), decision)
	remote.close()

	switch {
	case errors.Is(err, client.ErrNoPending):
		return errors.New("у этой записи нет несинхронизированных изменений")
	case errors.Is(err, client.ErrNotFound):
		return errors.New("запись не найдена в локальном кеше")
	case err != nil:
		return explain(err)
	}

	if err = a.printf("Конфликт разрешён: %s\n", strings.ToLower(strings.TrimSpace(fs.Arg(0)))); err != nil {
		return err
	}

	return a.syncAfter(ctx, s, *noSync)
}

// parseKeep разбирает значение флага --keep.
func parseKeep(value string) (client.Keep, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "local":
		return client.KeepLocal, nil
	case "server":
		return client.KeepServer, nil
	case "":
		return 0, errors.New("укажите, чью версию оставить: --keep local или --keep server")
	default:
		return 0, fmt.Errorf("неизвестное значение --keep %q: допустимы local и server", value)
	}
}
