// Package localstore хранит локальное состояние клиента GophKeeper в каталоге
// пользователя: сессию (токен доступа и соль вывода ключа) и кеш записей.
//
// Мастер-пароль на диск не записывается никогда. Записи в кеше лежат в том же
// зашифрованном виде, в каком их хранит сервер, поэтому утечка каталога не
// раскрывает содержимое записей. Токен доступа при этом хранится открыто, а
// значит, каталог нужно защищать правами доступа: каталог создаётся с правами
// 0700, файлы - с правами 0600.
package localstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// appDirName - имя каталога приложения внутри пользовательского каталога настроек.
	appDirName = "gophkeeper"

	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600

	sessionFileName = "session.json"
)

// ErrNoSession возвращается, если вход ещё не выполнен.
var ErrNoSession = errors.New("нет активной сессии: выполните вход")

// Store - каталог локального состояния клиента.
type Store struct {
	dir string
}

// DefaultDir возвращает каталог по умолчанию: подкаталог gophkeeper
// пользовательского каталога настроек операционной системы (os.UserConfigDir).
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("не удалось определить каталог настроек пользователя: %w", err)
	}

	return filepath.Join(base, appDirName), nil
}

// Open открывает хранилище в каталоге dir. Отсутствующий каталог создаётся с
// правами 0700; права уже существующего каталога не меняются.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("не задан каталог локального хранилища")
	}

	_, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err = os.MkdirAll(dir, dirMode); err != nil {
			return nil, fmt.Errorf("не удалось создать каталог %q: %w", dir, err)
		}
		// Маска прав процесса (umask) могла сузить права; приводим их к ожидаемым.
		if err = os.Chmod(dir, dirMode); err != nil {
			return nil, fmt.Errorf("не удалось выставить права на каталог %q: %w", dir, err)
		}
	case err != nil:
		return nil, fmt.Errorf("не удалось проверить каталог %q: %w", dir, err)
	}

	return &Store{dir: dir}, nil
}

// Dir возвращает путь к каталогу хранилища.
func (s *Store) Dir() string {
	return s.dir
}

// Session - сведения о выполненном входе.
type Session struct {
	// ExpiresAt - момент истечения токена доступа.
	ExpiresAt time.Time `json:"expires_at"`
	// Server - адрес сервера, на котором выполнен вход.
	Server string `json:"server"`
	// Login - логин пользователя.
	Login string `json:"login"`
	// Token - токен доступа; секрет, хранится в файле с правами 0600.
	Token string `json:"token"`
	// KDFSalt - соль вывода ключа шифрования, выданная сервером.
	KDFSalt []byte `json:"kdf_salt"`
}

// Expired сообщает, что срок действия токена истёк к моменту now.
func (s Session) Expired(now time.Time) bool {
	return !now.Before(s.ExpiresAt)
}

// SaveSession сохраняет сессию, заменяя предыдущую.
func (s *Store) SaveSession(sess Session) error {
	if sess.Token == "" || sess.Server == "" || sess.Login == "" {
		return errors.New("сессия должна содержать сервер, логин и токен")
	}

	return writeJSON(filepath.Join(s.dir, sessionFileName), sess)
}

// LoadSession читает сохранённую сессию. Возвращает ErrNoSession, если вход не выполнен.
func (s *Store) LoadSession() (Session, error) {
	var sess Session

	err := readJSON(filepath.Join(s.dir, sessionFileName), &sess)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return Session{}, ErrNoSession
	case err != nil:
		return Session{}, err
	case sess.Token == "":
		return Session{}, fmt.Errorf("файл сессии повреждён: нет токена")
	}

	return sess, nil
}

// ClearSession удаляет сохранённую сессию. Отсутствие сессии ошибкой не считается.
// Кеш записей сохраняется: он понадобится при следующем входе.
func (s *Store) ClearSession() error {
	err := os.Remove(filepath.Join(s.dir, sessionFileName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("не удалось удалить сессию: %w", err)
	}

	return nil
}

// cacheFileName возвращает имя файла кеша для пары «сервер, логин». Кеши разных
// пользователей и серверов лежат в разных файлах, поэтому смена пользователя
// не уничтожает несинхронизированные изменения предыдущего.
func cacheFileName(server, login string) string {
	sum := sha256.Sum256([]byte(server + "\x00" + login))

	return "cache-" + hex.EncodeToString(sum[:8]) + ".json"
}

// readJSON читает файл path и разбирает его как JSON в v.
func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("не удалось прочитать %q: %w", path, err)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("файл %q повреждён: %w", path, err)
	}

	return nil
}

// writeJSON сериализует v в JSON и атомарно записывает в файл path.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("не удалось сериализовать данные: %w", err)
	}

	return writeFileAtomic(path, data)
}

// writeFileAtomic записывает data в файл path с правами 0600 так, что при
// сбое на любом шаге прежнее содержимое файла остаётся нетронутым: данные
// пишутся во временный файл рядом с целевым, сбрасываются на диск и
// переименовываются поверх него.
func writeFileAtomic(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("не удалось создать временный файл: %w", err)
	}

	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err = tmp.Chmod(fileMode); err != nil {
		return fmt.Errorf("не удалось выставить права на файл: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("не удалось записать файл: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("не удалось сбросить файл на диск: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("не удалось закрыть файл: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("не удалось заменить файл %q: %w", path, err)
	}

	return nil
}
