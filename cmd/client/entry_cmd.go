package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/e-l-l-a-r/gophkeeper/internal/client"
	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
	"github.com/e-l-l-a-r/gophkeeper/internal/model"
)

// maskedSecret - то, что выводится вместо секретного значения без --show-secrets.
const maskedSecret = "****"

// cmdAdd добавляет запись указанного типа.
func (a *app) cmdAdd(ctx context.Context, args []string) error {
	fs := a.flagSet("add")
	flags := addGlobalFlags(fs)
	noSync := fs.Bool("no-sync", false, "не синхронизироваться с сервером после добавления")
	name := fs.StringP("name", "n", "", "название записи (иначе будет запрошено)")
	meta := fs.StringP("meta", "m", "", "метаинформация записи (сайт, банк и т. п.)")
	file := fs.StringP("file", "f", "", "для binary: файл с данными")
	fs.Usage = func() {
		a.commandUsage(fs, "Использование: gophkeeper add <login|text|binary|card> [флаги]\n\n"+
			"Секретные поля (пароль, текст, номер карты, CVV) вводятся интерактивно.\n"+
			"Для binary данные читаются из файла: --file путь.")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("укажите тип записи: login, text, binary или card")
	}

	kind, err := model.ParseKind(fs.Arg(0))
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

	entry := model.Entry{Kind: kind, Meta: *meta}

	// Опечатка при первой записи необратима: проверить мастер-пароль нечем.
	keys, err := a.keyring(s.sess, !hasEntries(s.cache))
	if err != nil {
		return err
	}

	entry.Name = *name
	if err = a.fillEntry(&entry, *file); err != nil {
		return err
	}

	c := client.New(offlineRemote{}, s.cache, keys)

	id, err := c.Add(entry)
	if err != nil {
		return explain(err)
	}

	if err = a.printf("Запись добавлена: %s\n", id); err != nil {
		return err
	}

	return a.syncAfter(ctx, s, *noSync)
}

// cmdGet показывает запись. Секретные поля скрыты, пока не указан --show-secrets.
func (a *app) cmdGet(_ context.Context, args []string) error {
	fs := a.flagSet("get")
	flags := addGlobalFlags(fs)
	show := fs.Bool("show-secrets", false, "показать пароль, CVV и текст (по умолчанию скрыты)")
	output := fs.StringP("output", "o", "", "для binary: записать данные в файл")
	fs.Usage = func() {
		a.commandUsage(fs, "Использование: gophkeeper get <id> [флаги]\n\n"+
			"Без --show-secrets пароль, CVV и текст заменяются на ****.\n"+
			"Бинарные данные не печатаются на экран: сохраните их в файл через --output.")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("укажите идентификатор записи")
	}

	g, err := resolveGlobals(fs, flags)
	if err != nil {
		return err
	}

	s, err := loadSession(g)
	if err != nil {
		return explain(err)
	}

	keys, err := a.keyring(s.sess, false)
	if err != nil {
		return err
	}

	entry, err := client.New(offlineRemote{}, s.cache, keys).Get(fs.Arg(0))
	if err != nil {
		return explain(err)
	}

	if entry.Kind == model.KindBinary && *output != "" {
		if err = writeNewFile(*output, entry.Data); err != nil {
			return err
		}
	}

	return a.printEntry(entry, *show, *output)
}

// cmdList показывает список записей без секретных данных.
func (a *app) cmdList(_ context.Context, args []string) error {
	g, err := a.parseNoArgs("list",
		"Использование: gophkeeper list\n\n"+
			"Показывает идентификатор, тип, название и метаинформацию записей.\n"+
			"Знак * означает несинхронизированное изменение.", args)
	if err != nil {
		return err
	}

	s, err := loadSession(g)
	if err != nil {
		return explain(err)
	}

	keys, err := a.keyring(s.sess, false)
	if err != nil {
		return err
	}

	list, err := client.New(offlineRemote{}, s.cache, keys).List()
	if err != nil {
		return explain(err)
	}

	if len(list) == 0 {
		return a.printf("Записей нет.\n")
	}

	for _, item := range list {
		meta := ""
		if item.Meta != "" {
			meta = "  [" + oneLine(item.Meta) + "]"
		}

		if err = a.printf("%s %s  %-6s %s%s\n",
			pendingMark(item.Pending), item.ID, item.Kind, oneLine(item.Name), meta); err != nil {
			return err
		}
	}

	return nil
}

// cmdEdit заменяет содержимое записи. Поля запрашиваются заново, текущие
// значения не отображаются; название и метаинформацию можно оставить прежними.
func (a *app) cmdEdit(ctx context.Context, args []string) error {
	fs := a.flagSet("edit")
	flags := addGlobalFlags(fs)
	noSync := fs.Bool("no-sync", false, "не синхронизироваться с сервером после изменения")
	name := fs.StringP("name", "n", "", "новое название (иначе останется прежнее)")
	meta := fs.StringP("meta", "m", "", "новая метаинформация (иначе останется прежняя)")
	file := fs.StringP("file", "f", "", "для binary: файл с новыми данными")
	fs.Usage = func() {
		a.commandUsage(fs, "Использование: gophkeeper edit <id> [флаги]\n\n"+
			"Тип записи сохраняется. Секретные поля вводятся заново интерактивно.")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("укажите идентификатор записи")
	}

	g, err := resolveGlobals(fs, flags)
	if err != nil {
		return err
	}

	s, err := loadSession(g)
	if err != nil {
		return explain(err)
	}

	keys, err := a.keyring(s.sess, false)
	if err != nil {
		return err
	}

	c := client.New(offlineRemote{}, s.cache, keys)

	current, err := c.Get(fs.Arg(0))
	if err != nil {
		return explain(err)
	}

	updated := model.Entry{ID: current.ID, Kind: current.Kind, Name: current.Name, Meta: current.Meta}
	if fs.Changed("name") {
		updated.Name = *name
	}
	if fs.Changed("meta") {
		updated.Meta = *meta
	}

	if err = a.fillEntry(&updated, *file); err != nil {
		return err
	}

	if err = c.Edit(updated); err != nil {
		return explain(err)
	}

	if err = a.printf("Запись изменена: %s\n", updated.ID); err != nil {
		return err
	}

	return a.syncAfter(ctx, s, *noSync)
}

// cmdDelete удаляет запись.
func (a *app) cmdDelete(ctx context.Context, args []string) error {
	fs := a.flagSet("delete")
	flags := addGlobalFlags(fs)
	noSync := fs.Bool("no-sync", false, "не синхронизироваться с сервером после удаления")
	yes := fs.BoolP("yes", "y", false, "не запрашивать подтверждение")
	fs.Usage = func() {
		a.commandUsage(fs, "Использование: gophkeeper delete <id> [флаги]\n\nУдаляет запись. Мастер-пароль не требуется.")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("укажите идентификатор записи")
	}

	g, err := resolveGlobals(fs, flags)
	if err != nil {
		return err
	}

	s, err := loadSession(g)
	if err != nil {
		return explain(err)
	}

	if !*yes {
		answer, askErr := a.prompt.Line(fmt.Sprintf("Удалить запись %s? [y/N]: ", fs.Arg(0)))
		if askErr != nil {
			return askErr
		}
		if !isYes(answer) {
			return a.printf("Отменено.\n")
		}
	}

	// Удаление мастер-ключа не требует: запись только помечается удалённой.
	if err = client.New(offlineRemote{}, s.cache, nil).Remove(fs.Arg(0)); err != nil {
		return explain(err)
	}

	if err = a.printf("Запись удалена: %s\n", strings.ToLower(strings.TrimSpace(fs.Arg(0)))); err != nil {
		return err
	}

	return a.syncAfter(ctx, s, *noSync)
}

// fillEntry запрашивает у пользователя поля записи entry.Kind. Если название
// entry.Name пусто, оно запрашивается. Секретные поля запрашиваются без
// отображения на экране.
func (a *app) fillEntry(entry *model.Entry, file string) error {
	if entry.Name == "" {
		name, err := a.prompt.Line("Название: ")
		if err != nil {
			return err
		}
		entry.Name = name
	}

	switch entry.Kind {
	case model.KindLoginPassword:
		return a.fillLogin(entry)
	case model.KindText:
		return a.fillText(entry)
	case model.KindBinary:
		return fillBinary(entry, file)
	case model.KindCard:
		return a.fillCard(entry)
	default:
		return fmt.Errorf("неизвестный тип записи %s", entry.Kind)
	}
}

// fillLogin запрашивает логин (видимый) и пароль (скрытый) с подтверждением.
func (a *app) fillLogin(entry *model.Entry) error {
	login, err := a.prompt.Line("Логин: ")
	if err != nil {
		return err
	}

	password, err := a.secretTwice("Пароль: ")
	if err != nil {
		return err
	}

	entry.Login, entry.Password = login, password

	return nil
}

// fillText запрашивает текст записи одной строкой без отображения на экране.
// Многострочный текст сохраняется как binary из файла.
func (a *app) fillText(entry *model.Entry) error {
	text, err := a.prompt.Secret("Текст (одной строкой; для многострочного используйте binary и --file): ")
	if err != nil {
		return err
	}

	entry.Text = text

	return nil
}

// fillBinary читает бинарные данные из файла file.
func fillBinary(entry *model.Entry, file string) error {
	if file == "" {
		return errors.New("для записи типа binary укажите файл с данными: --file путь")
	}

	info, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("не удалось прочитать файл %q: %w", file, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%q - каталог, а не файл", file)
	}
	if info.Size() > model.MaxBinarySize {
		return fmt.Errorf("файл %q больше допустимых %d байт", file, model.MaxBinarySize)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("не удалось прочитать файл %q: %w", file, err)
	}

	entry.Data = data

	return nil
}

// fillCard запрашивает данные карты: номер и CVV скрыто, остальное видимо.
func (a *app) fillCard(entry *model.Entry) error {
	number, err := a.prompt.Secret("Номер карты: ")
	if err != nil {
		return err
	}

	holder, err := a.prompt.Line("Владелец: ")
	if err != nil {
		return err
	}

	expiry, err := a.prompt.Line("Срок действия (ММ/ГГ): ")
	if err != nil {
		return err
	}

	cvv, err := a.prompt.Secret("CVV: ")
	if err != nil {
		return err
	}

	entry.Card = &model.Card{Number: number, Holder: holder, Expiry: expiry, CVV: cvv}

	return nil
}

// secretTwice запрашивает секрет дважды и сверяет ввод: опечатка в пароле,
// которого не видно на экране, делает запись бесполезной.
func (a *app) secretTwice(prompt string) (string, error) {
	first, err := a.prompt.Secret(prompt)
	if err != nil {
		return "", err
	}

	again, err := a.prompt.Secret("Повторите: ")
	if err != nil {
		return "", err
	}
	if first != again {
		return "", errors.New("введённые значения не совпадают")
	}

	return first, nil
}

// printEntry выводит запись. Без show секретные поля заменяются на ****.
func (a *app) printEntry(entry model.Entry, show bool, outputFile string) error {
	secret := func(value string) string {
		if show {
			return value
		}

		return maskedSecret
	}

	lines := []string{
		fmt.Sprintf("ID:        %s", entry.ID),
		fmt.Sprintf("Тип:       %s", entry.Kind),
		fmt.Sprintf("Название:  %s", entry.Name),
	}

	if entry.Meta != "" {
		lines = append(lines, fmt.Sprintf("Мета:      %s", entry.Meta))
	}

	switch entry.Kind {
	case model.KindLoginPassword:
		lines = append(lines,
			fmt.Sprintf("Логин:     %s", entry.Login),
			fmt.Sprintf("Пароль:    %s", secret(entry.Password)))
	case model.KindText:
		lines = append(lines, fmt.Sprintf("Текст:     %s", secret(entry.Text)))
	case model.KindBinary:
		lines = append(lines, fmt.Sprintf("Данные:    %d байт", len(entry.Data)))
		if outputFile != "" {
			lines = append(lines, fmt.Sprintf("Файл:      %s", outputFile))
		} else {
			lines = append(lines, "           (сохраните в файл: --output путь)")
		}
	case model.KindCard:
		if entry.Card != nil {
			lines = append(lines,
				fmt.Sprintf("Номер:     %s", cardNumber(entry.Card.Number, show)),
				fmt.Sprintf("Владелец:  %s", entry.Card.Holder),
				fmt.Sprintf("Срок:      %s", entry.Card.Expiry),
				fmt.Sprintf("CVV:       %s", secret(entry.Card.CVV)))
		}
	}

	return a.printf("%s\n", strings.Join(lines, "\n"))
}

// cardNumber возвращает номер карты. Без show остаются только последние
// четыре цифры, как на чеках.
func cardNumber(number string, show bool) string {
	if show {
		return number
	}

	if len(number) <= 4 {
		return maskedSecret
	}

	return strings.Repeat("*", len(number)-4) + number[len(number)-4:]
}

// pendingMark возвращает знак несинхронизированного изменения для списка.
func pendingMark(p localstore.Pending) string {
	if p == localstore.PendingNone {
		return " "
	}

	return "*"
}

// oneLine заменяет переводы строк пробелами и обрезает слишком длинный текст,
// чтобы запись занимала одну строку списка.
func oneLine(s string) string {
	const limit = 60

	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= limit {
		return s
	}

	runes := []rune(s)

	return string(runes[:limit-1]) + "…"
}

// isYes сообщает, что answer - утвердительный ответ.
func isYes(answer string) bool {
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes", "д", "да":
		return true
	default:
		return false
	}
}

// writeNewFile записывает data в новый файл path с правами 0600. Существующий
// файл не перезаписывается: расшифрованные данные не должны затирать чужие.
func writeNewFile(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("файл %q уже существует: укажите другой путь", path)
		}

		return fmt.Errorf("не удалось создать файл %q: %w", path, err)
	}

	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("не удалось закрыть файл %q: %w", path, closeErr)
		}
	}()

	if _, err = f.Write(data); err != nil {
		_ = os.Remove(path)

		return fmt.Errorf("не удалось записать файл %q: %w", path, err)
	}

	return nil
}
