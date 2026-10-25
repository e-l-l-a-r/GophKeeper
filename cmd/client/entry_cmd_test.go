package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/e-l-l-a-r/gophkeeper/internal/client"
	"github.com/e-l-l-a-r/gophkeeper/internal/crypto"
	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
	"github.com/e-l-l-a-r/gophkeeper/internal/model"
)

const (
	cardNumberPlain = "4111111111111111"
	cardCVV         = "987"
)

// addLogin добавляет запись «логин и пароль» и возвращает её идентификатор.
// Мастер-пароль запрашивается дважды, пока в кеше нет записей, поэтому
// помощник сам смотрит на состояние кеша.
func addLogin(t *testing.T, e *testEnv, name string, extra ...string) string {
	t.Helper()

	secrets := []string{"master"}
	if !hasEntries(e.cache()) {
		secrets = append(secrets, "master")
	}
	secrets = append(secrets, "pw-"+name, "pw-"+name)

	args := append([]string{"add", "login", "--no-sync"}, extra...)
	out := e.mustDo(&scriptedPrompt{lines: []string{name, "user-" + name}, secrets: secrets}, args...)

	return strings.TrimSpace(strings.TrimPrefix(out, "Запись добавлена: "))
}

func TestAdd_Login(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	p := &scriptedPrompt{lines: []string{"почта", "me@example.com"}, secrets: []string{"master", "master", "p@ss", "p@ss"}}
	out := e.mustDo(p, "add", "login", "--no-sync", "-m", "mail.example.com")
	id := strings.TrimSpace(strings.TrimPrefix(out, "Запись добавлена: "))
	require.Regexp(t, `^[0-9a-f]{8}-`, id)

	rec, ok := e.cache().Get(id)
	require.True(t, ok)
	assert.Equal(t, localstore.PendingCreate, rec.Pending)
	assert.NotContains(t, string(rec.Payload), "p@ss", "в кеше только шифротекст")
	assert.NotContains(t, string(rec.Payload), "почта")

	require.Equal(t, []string{"Мастер-пароль: ", "Повторите мастер-пароль: ", "Пароль: ", "Повторите: "},
		secretPrompts(p.asked), "на первой записи мастер-пароль запрашивается дважды")
}

// secretPrompts возвращает приглашения, относящиеся к секретам.
func secretPrompts(asked []string) []string {
	var out []string

	for _, a := range asked {
		switch {
		case strings.Contains(a, "ароль"), strings.Contains(a, "Повторите"), strings.Contains(a, "CVV"),
			strings.Contains(a, "Номер"), strings.Contains(a, "Текст"):
			out = append(out, a)
		}
	}

	return out
}

func TestAdd_MasterPasswordAskedOnceWhenEntriesExist(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()
	addLogin(t, e, "первая")

	p := &scriptedPrompt{lines: []string{"вторая", "u"}, secrets: []string{"master", "x", "x"}}
	e.mustDo(p, "add", "login", "--no-sync")

	assert.Equal(t, []string{"Мастер-пароль: ", "Пароль: ", "Повторите: "}, secretPrompts(p.asked))
}

func TestAdd_MasterPasswordMismatchOnFirstEntry(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	err := e.do(&scriptedPrompt{lines: []string{"n", "u"}, secrets: []string{"master", "mastre"}}, "add", "login", "--no-sync")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "мастер-пароли не совпадают")
	assert.Empty(t, e.cache().Records())
}

func TestAdd_EmptyMasterPassword(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	err := e.do(&scriptedPrompt{secrets: []string{""}}, "add", "login", "--no-sync")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "не может быть пустым")
}

func TestAdd_WrongMasterPasswordIsRejected(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()
	addLogin(t, e, "первая")

	err := e.do(&scriptedPrompt{lines: []string{"вторая", "u"}, secrets: []string{"mastre", "x", "x"}}, "add", "login", "--no-sync")
	require.ErrorIs(t, err, crypto.ErrDecrypt)
	assert.Len(t, e.cache().Records(), 1, "запись, зашифрованная неверным мастер-паролем, не создаётся")
}

func TestAdd_PasswordConfirmationMismatch(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	err := e.do(&scriptedPrompt{lines: []string{"n", "u"}, secrets: []string{"master", "master", "one", "two"}}, "add", "login", "--no-sync")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "не совпадают")
	assert.Empty(t, e.cache().Records())
}

func TestAdd_NameFromFlagIsNotAsked(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	p := &scriptedPrompt{lines: []string{"u"}, secrets: []string{"master", "master", "pw", "pw"}}
	e.mustDo(p, "add", "login", "--no-sync", "-n", "из флага")

	assert.NotContains(t, p.asked, "Название: ")

	list := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "list")
	assert.Contains(t, list, "из флага")
}

func TestAdd_Text(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	out := e.mustDo(&scriptedPrompt{lines: []string{"заметка"}, secrets: []string{"master", "master", "строка текста"}}, "add", "text", "--no-sync")
	id := strings.TrimSpace(strings.TrimPrefix(out, "Запись добавлена: "))

	got := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id, "--show-secrets")
	assert.Contains(t, got, "строка текста")
}

func TestAdd_Binary(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	data := []byte{0x00, 0xff, 0x10, 0x80, 'x'}
	src := writeFile(t, "in.bin", data)

	out := e.mustDo(&scriptedPrompt{lines: []string{"бинарник"}, secrets: []string{"master", "master"}}, "add", "binary", "--no-sync", "-f", src)
	id := strings.TrimSpace(strings.TrimPrefix(out, "Запись добавлена: "))

	dst := filepath.Join(t.TempDir(), "out.bin")
	shown := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id, "-o", dst)
	assert.Contains(t, shown, "5 байт")
	assert.Contains(t, shown, dst)

	restored, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, restored), "данные восстановлены без искажений")

	info, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	t.Run("существующий файл не перезаписывается", func(t *testing.T) {
		err := e.do(&scriptedPrompt{secrets: []string{"master"}}, "get", id, "-o", dst)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "уже существует")

		kept, readErr := os.ReadFile(dst)
		require.NoError(t, readErr)
		assert.True(t, bytes.Equal(data, kept))
	})

	t.Run("без --output данные не печатаются", func(t *testing.T) {
		out := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id, "--show-secrets")
		assert.Contains(t, out, "--output")
		assert.NotContains(t, out, string(data))
	})
}

func TestAdd_BinaryErrors(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	dir := t.TempDir()
	huge := filepath.Join(dir, "huge.bin")
	f, err := os.Create(huge)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(model.MaxBinarySize+1))
	require.NoError(t, f.Close())

	tests := []struct {
		name     string
		contains string
		args     []string
	}{
		{name: "файл не указан", args: []string{"add", "binary", "--no-sync"}, contains: "--file"},
		{name: "файл не существует", args: []string{"add", "binary", "--no-sync", "-f", filepath.Join(dir, "no")}, contains: "не удалось прочитать"},
		{name: "каталог вместо файла", args: []string{"add", "binary", "--no-sync", "-f", dir}, contains: "каталог"},
		{name: "файл слишком большой", args: []string{"add", "binary", "--no-sync", "-f", huge}, contains: "больше допустимых"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.do(&scriptedPrompt{lines: []string{"n"}, secrets: []string{"master", "master"}}, tt.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.contains)
		})
	}
}

func TestAdd_Card(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	p := &scriptedPrompt{
		lines:   []string{"зарплатная", "IVAN IVANOV", "7/2030"},
		secrets: []string{"master", "master", "4111 1111 1111 1111", cardCVV},
	}
	out := e.mustDo(p, "add", "card", "--no-sync")
	id := strings.TrimSpace(strings.TrimPrefix(out, "Запись добавлена: "))

	assert.Equal(t, []string{"Мастер-пароль: ", "Повторите мастер-пароль: ", "Номер карты: ", "CVV: "}, secretPrompts(p.asked),
		"номер карты и CVV вводятся скрыто")

	t.Run("секреты скрыты по умолчанию", func(t *testing.T) {
		got := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id)

		assert.Contains(t, got, "************1111", "видны только последние 4 цифры номера")
		assert.NotContains(t, got, cardNumberPlain)
		assert.NotContains(t, got, cardCVV)
		assert.Contains(t, got, "IVAN IVANOV")
		assert.Contains(t, got, "07/30", "срок приведён к виду ММ/ГГ")
	})

	t.Run("секреты видны с --show-secrets", func(t *testing.T) {
		got := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id, "--show-secrets")

		assert.Contains(t, got, cardNumberPlain)
		assert.Contains(t, got, cardCVV)
	})
}

func TestAdd_InvalidCard(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	err := e.do(&scriptedPrompt{
		lines:   []string{"карта", "A", "07/30"},
		secrets: []string{"master", "master", "4111111111111112", "123"},
	}, "add", "card", "--no-sync")

	require.ErrorIs(t, err, model.ErrInvalid)
	assert.NotContains(t, err.Error(), "4111111111111112", "номер не попадает в сообщение об ошибке")
	assert.Empty(t, e.cache().Records())
}

func TestAdd_Errors(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	tests := []struct {
		name     string
		contains string
		args     []string
	}{
		{name: "тип не указан", args: []string{"add"}, contains: "укажите тип"},
		{name: "неизвестный тип", args: []string{"add", "note"}, contains: "неизвестный тип"},
		{name: "два типа", args: []string{"add", "login", "text"}, contains: "укажите тип"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.do(&scriptedPrompt{}, tt.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.contains)
		})
	}
}

func TestGet_HidesSecretsByDefault(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()
	id := addLogin(t, e, "почта", "-m", "mail.example.com")

	hidden := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id)
	assert.Contains(t, hidden, "user-почта")
	assert.Contains(t, hidden, "mail.example.com")
	assert.Contains(t, hidden, maskedSecret)
	assert.NotContains(t, hidden, "pw-почта")

	shown := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id, "--show-secrets")
	assert.Contains(t, shown, "pw-почта")
	assert.NotContains(t, shown, maskedSecret)

	upper := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", strings.ToUpper(id))
	assert.Contains(t, upper, id, "идентификатор в верхнем регистре тоже находится")
}

func TestGet_Errors(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()
	id := addLogin(t, e, "почта")

	t.Run("записи нет", func(t *testing.T) {
		err := e.do(&scriptedPrompt{secrets: []string{"master"}}, "get", "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11")
		require.ErrorIs(t, err, client.ErrNotFound)
	})

	t.Run("неверный мастер-пароль", func(t *testing.T) {
		err := e.do(&scriptedPrompt{secrets: []string{"wrong"}}, "get", id)
		require.ErrorIs(t, err, crypto.ErrDecrypt)
		assert.Contains(t, err.Error(), "мастер-пароль")
	})

	t.Run("идентификатор не указан", func(t *testing.T) {
		err := e.do(&scriptedPrompt{}, "get")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "идентификатор")
	})
}

func TestList(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	empty := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "list")
	assert.Contains(t, empty, "Записей нет")

	addLogin(t, e, "Банк", "-m", "bank.example.com")
	addLogin(t, e, "альфа")

	out := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "list")
	assert.Contains(t, out, "[bank.example.com]")
	assert.Contains(t, out, "login")

	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "альфа", "сортировка по названию без учёта регистра")
	assert.True(t, strings.HasPrefix(lines[0], "*"), "несинхронизированные записи помечены звёздочкой")

	assert.NotContains(t, out, "pw-", "в списке нет секретных данных")
}

func TestList_SyncedRecordsHaveNoMark(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()
	e.mustDo(&scriptedPrompt{lines: []string{"n", "u"}, secrets: []string{"master", "master", "p", "p"}}, "add", "login")

	out := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "list")
	assert.False(t, strings.HasPrefix(out, "*"))
}

func TestList_WrongMasterPassword(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()
	addLogin(t, e, "n")

	err := e.do(&scriptedPrompt{secrets: []string{"wrong"}}, "list")
	require.ErrorIs(t, err, crypto.ErrDecrypt)
}

func TestEdit(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()
	id := addLogin(t, e, "старое", "-m", "старая мета")

	t.Run("название и мета остаются прежними", func(t *testing.T) {
		e.mustDo(&scriptedPrompt{lines: []string{"новый-логин"}, secrets: []string{"master", "new-pw", "new-pw"}}, "edit", id, "--no-sync")

		got := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id, "--show-secrets")
		assert.Contains(t, got, "старое")
		assert.Contains(t, got, "старая мета")
		assert.Contains(t, got, "новый-логин")
		assert.Contains(t, got, "new-pw")
	})

	t.Run("название и мета из флагов", func(t *testing.T) {
		e.mustDo(&scriptedPrompt{lines: []string{"л"}, secrets: []string{"master", "p", "p"}},
			"edit", id, "--no-sync", "-n", "новое", "-m", "")

		got := e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id)
		assert.Contains(t, got, "новое")
		assert.NotContains(t, got, "старая мета", "пустая --meta очищает метаинформацию")
	})

	t.Run("записи нет", func(t *testing.T) {
		err := e.do(&scriptedPrompt{secrets: []string{"master"}}, "edit", "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11", "--no-sync")
		require.ErrorIs(t, err, client.ErrNotFound)
	})

	t.Run("неверный мастер-пароль", func(t *testing.T) {
		err := e.do(&scriptedPrompt{secrets: []string{"wrong"}}, "edit", id, "--no-sync")
		require.ErrorIs(t, err, crypto.ErrDecrypt)
	})

	t.Run("идентификатор не указан", func(t *testing.T) {
		require.Error(t, e.do(&scriptedPrompt{}, "edit"))
	})
}

func TestDelete(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	t.Run("с подтверждением", func(t *testing.T) {
		id := addLogin(t, e, "удаляемая")

		out := e.mustDo(&scriptedPrompt{lines: []string{"y"}}, "delete", id, "--no-sync")
		assert.Contains(t, out, "Запись удалена")

		_, ok := e.cache().Get(id)
		assert.False(t, ok, "запись, не попавшая на сервер, исчезает сразу")
	})

	t.Run("отказ от удаления", func(t *testing.T) {
		id := addLogin(t, e, "оставляемая")

		out := e.mustDo(&scriptedPrompt{lines: []string{"нет"}}, "delete", id, "--no-sync")
		assert.Contains(t, out, "Отменено")

		_, ok := e.cache().Get(id)
		assert.True(t, ok)
	})

	t.Run("пустой ответ означает отказ", func(t *testing.T) {
		id := addLogin(t, e, "третья")

		out := e.mustDo(&scriptedPrompt{lines: []string{""}}, "delete", id, "--no-sync")
		assert.Contains(t, out, "Отменено")
	})

	t.Run("--yes без вопроса, мастер-пароль не нужен", func(t *testing.T) {
		id := addLogin(t, e, "четвёртая")

		p := &scriptedPrompt{}
		e.mustDo(p, "delete", id, "-y", "--no-sync")
		assert.Empty(t, p.asked, "удаление ничего не спрашивает при --yes")
	})

	t.Run("записи нет", func(t *testing.T) {
		err := e.do(&scriptedPrompt{}, "delete", "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11", "-y", "--no-sync")
		require.ErrorIs(t, err, client.ErrNotFound)
	})

	t.Run("идентификатор не указан", func(t *testing.T) {
		require.Error(t, e.do(&scriptedPrompt{}, "delete"))
	})
}

func TestDelete_ConfirmationAnswers(t *testing.T) {
	for answer, want := range map[string]bool{
		"y": true, "Y": true, "yes": true, "да": true, "Да": true, " да ": true,
		"": false, "n": false, "no": false, "нет": false, "yy": false, "ok": false,
	} {
		assert.Equal(t, want, isYes(answer), "ответ %q", answer)
	}
}

func TestSyncCommand(t *testing.T) {
	srv := newTestServer(t)
	laptop := newEnv(t, srv)
	laptop.register()
	id := addLogin(t, laptop, "общая")

	out := laptop.mustDo(nil, "sync")
	assert.Contains(t, out, "Отправлено: 1")

	phone := newEnv(t, srv)
	phone.mustDo(&scriptedPrompt{lines: []string{"alice"}, secrets: []string{"s3cretpass"}}, "login")

	out = phone.mustDo(nil, "sync")
	assert.Contains(t, out, "получено: 1")

	got := phone.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id, "--show-secrets")
	assert.Contains(t, got, "pw-общая", "запись доступна на втором устройстве с тем же мастер-паролем")

	again := phone.mustDo(nil, "sync")
	assert.Contains(t, again, "Отправлено: 0, получено: 0")
}

func TestSyncCommand_ServerUnavailable(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()
	e.unavailable = true

	err := e.do(nil, "sync")
	require.ErrorIs(t, err, client.ErrUnavailable)
}

func TestSyncAfterChange(t *testing.T) {
	srv := newTestServer(t)
	e := newEnv(t, srv)
	e.register()

	out := e.mustDo(&scriptedPrompt{lines: []string{"n", "u"}, secrets: []string{"master", "master", "p", "p"}}, "add", "login")
	assert.Contains(t, out, "Отправлено: 1", "после добавления выполняется синхронизация")

	assert.Equal(t, localstore.PendingNone, e.cache().Records()[0].Pending)
}

func TestSyncAfterChange_ServerUnavailableKeepsChangeLocal(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()
	e.unavailable = true

	out := e.mustDo(&scriptedPrompt{lines: []string{"n", "u"}, secrets: []string{"master", "master", "p", "p"}}, "add", "login")
	assert.Contains(t, out, "сохранено локально")

	recs := e.cache().Records()
	require.Len(t, recs, 1)
	assert.Equal(t, localstore.PendingCreate, recs[0].Pending)

	e.unavailable = false
	assert.Contains(t, e.mustDo(nil, "sync"), "Отправлено: 1", "позже изменение отправляется командой sync")
}

func TestSyncAfterChange_ExpiredSessionKeepsChangeLocal(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	store := mustStore(t, e)
	sess, err := store.LoadSession()
	require.NoError(t, err)
	sess.ExpiresAt = testNow.Add(-time.Hour)
	require.NoError(t, store.SaveSession(sess))

	out := e.mustDo(&scriptedPrompt{lines: []string{"n", "u"}, secrets: []string{"master", "master", "p", "p"}}, "add", "login")
	assert.Contains(t, out, "сохранено локально")
	assert.Contains(t, out, "истёк")
}

func TestSyncAfterChange_InvalidTokenKeepsChangeLocal(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	store := mustStore(t, e)
	sess, err := store.LoadSession()
	require.NoError(t, err)
	sess.Token = "garbage"
	require.NoError(t, store.SaveSession(sess))

	out := e.mustDo(&scriptedPrompt{lines: []string{"n", "u"}, secrets: []string{"master", "master", "p", "p"}}, "add", "login")
	assert.Contains(t, out, "сохранено локально")
	assert.Contains(t, out, "login")
}

func TestConflictAndResolve(t *testing.T) {
	srv := newTestServer(t)
	laptop := newEnv(t, srv)
	laptop.register()
	id := addLogin(t, laptop, "спорная")
	laptop.mustDo(nil, "sync")

	phone := newEnv(t, srv)
	phone.mustDo(&scriptedPrompt{lines: []string{"alice"}, secrets: []string{"s3cretpass"}}, "login")
	phone.mustDo(nil, "sync")

	laptop.mustDo(&scriptedPrompt{lines: []string{"l"}, secrets: []string{"master", "from-laptop", "from-laptop"}}, "edit", id)
	phone.mustDo(&scriptedPrompt{lines: []string{"p"}, secrets: []string{"master", "from-phone", "from-phone"}}, "edit", id, "--no-sync")

	t.Run("sync сообщает о конфликте и завершается ошибкой", func(t *testing.T) {
		err := phone.do(nil, "sync")
		require.ErrorIs(t, err, client.ErrConflict)

		out := phone.out.String()
		assert.Contains(t, out, "Конфликты (1)")
		assert.Contains(t, out, id)
		assert.Contains(t, out, "изменена на сервере")
		assert.Contains(t, out, "resolve")
	})

	t.Run("локальная правка не потеряна", func(t *testing.T) {
		got := phone.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id, "--show-secrets")
		assert.Contains(t, got, "from-phone")
	})

	t.Run("resolve требует решения", func(t *testing.T) {
		for _, args := range [][]string{
			{"resolve", id},
			{"resolve", id, "--keep", "оба"},
			{"resolve", "--keep", "local"},
		} {
			require.Error(t, phone.do(nil, args...), "%v", args)
		}
	})

	t.Run("оставить серверную версию", func(t *testing.T) {
		out := phone.mustDo(nil, "resolve", id, "--keep", "server")
		assert.Contains(t, out, "Конфликт разрешён")

		got := phone.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id, "--show-secrets")
		assert.Contains(t, got, "from-laptop")
		assert.NotContains(t, got, "from-phone")
	})

	t.Run("повторное решение", func(t *testing.T) {
		err := phone.do(nil, "resolve", id, "--keep", "server")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "нет несинхронизированных изменений")
	})

	t.Run("неизвестная запись", func(t *testing.T) {
		err := phone.do(nil, "resolve", "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11", "--keep", "local")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "не найдена")
	})
}

func TestResolve_KeepLocal(t *testing.T) {
	srv := newTestServer(t)
	laptop := newEnv(t, srv)
	laptop.register()
	id := addLogin(t, laptop, "спорная")
	laptop.mustDo(nil, "sync")

	phone := newEnv(t, srv)
	phone.mustDo(&scriptedPrompt{lines: []string{"alice"}, secrets: []string{"s3cretpass"}}, "login")
	phone.mustDo(nil, "sync")

	laptop.mustDo(&scriptedPrompt{lines: []string{"l"}, secrets: []string{"master", "from-laptop", "from-laptop"}}, "edit", id)
	phone.mustDo(&scriptedPrompt{lines: []string{"p"}, secrets: []string{"master", "from-phone", "from-phone"}}, "edit", id, "--no-sync")
	require.ErrorIs(t, phone.do(nil, "sync"), client.ErrConflict)

	out := phone.mustDo(nil, "resolve", id, "--keep", "LOCAL")
	assert.Contains(t, out, "Конфликт разрешён")
	assert.Contains(t, out, "Отправлено: 1", "после решения локальная правка отправляется на сервер")

	laptop.mustDo(nil, "sync")
	got := laptop.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "get", id, "--show-secrets")
	assert.Contains(t, got, "from-phone", "победила локальная правка телефона")
}

func TestParseKeep(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    client.Keep
		wantErr bool
	}{
		{name: "local", input: "local", want: client.KeepLocal},
		{name: "server", input: " Server ", want: client.KeepServer},
		{name: "пусто", wantErr: true},
		{name: "неизвестное", input: "both", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKeep(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDescribeConflict(t *testing.T) {
	assert.Contains(t, describeConflict(client.Conflict{Reason: client.ConflictVersion}), "изменена на сервере")
	assert.Contains(t, describeConflict(client.Conflict{Reason: client.ConflictDeleted}), "удалена на сервере")
	assert.Contains(t, describeConflict(client.Conflict{Reason: client.ConflictExists}), "занят")
	assert.Equal(t, "другое", describeConflict(client.Conflict{Reason: "другое"}))
}

func TestCardNumber(t *testing.T) {
	assert.Equal(t, "4111111111111111", cardNumber("4111111111111111", true))
	assert.Equal(t, "************1111", cardNumber("4111111111111111", false))
	assert.Equal(t, "***********0005", cardNumber("378282246310005", false))
	assert.Equal(t, maskedSecret, cardNumber("1234", false))
	assert.Equal(t, maskedSecret, cardNumber("", false))
}

func TestOneLine(t *testing.T) {
	assert.Equal(t, "a b c", oneLine("a\n b\t c"))
	assert.Equal(t, "короткая", oneLine("  короткая  "))

	long := oneLine(strings.Repeat("я", 100))
	assert.Equal(t, 60, len([]rune(long)))
	assert.True(t, strings.HasSuffix(long, "…"))
}

func TestPendingMark(t *testing.T) {
	assert.Equal(t, " ", pendingMark(localstore.PendingNone))
	for _, p := range []localstore.Pending{localstore.PendingCreate, localstore.PendingUpdate, localstore.PendingDelete} {
		assert.Equal(t, "*", pendingMark(p))
	}
}

func TestWriteNewFile(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, writeNewFile(filepath.Join(dir, "a"), []byte("x")))

	err := writeNewFile(filepath.Join(dir, "a"), []byte("y"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "уже существует")

	err = writeNewFile(filepath.Join(dir, "no", "such", "a"), []byte("x"))
	require.Error(t, err)
}

func TestSessionOfDifferentUserDoesNotSeeCache(t *testing.T) {
	srv := newTestServer(t)
	e := newEnv(t, srv)
	e.register()
	addLogin(t, e, "алисина")

	e.mustDo(nil, "logout")
	e.mustDo(&scriptedPrompt{lines: []string{"bob"}, secrets: []string{"s3cretpass", "s3cretpass"}}, "register")

	out := e.mustDo(&scriptedPrompt{secrets: []string{"other-master"}}, "list")
	assert.Contains(t, out, "Записей нет", "у другого пользователя другой кеш")

	e.mustDo(nil, "logout")
	e.mustDo(&scriptedPrompt{lines: []string{"alice"}, secrets: []string{"s3cretpass"}}, "login")

	assert.Contains(t, e.mustDo(&scriptedPrompt{secrets: []string{"master"}}, "list"), "алисина",
		"записи вернулись после повторного входа")
}

func TestExecuteWiring(t *testing.T) {
	// Проверяем, что настоящая сборка приложения не падает на справке и версии.
	t.Setenv("GOPHKEEPER_DIR", t.TempDir())

	require.NoError(t, execute([]string{"help"}))
	require.NoError(t, execute([]string{"version"}))
	require.Error(t, execute([]string{"unknown"}))
}
