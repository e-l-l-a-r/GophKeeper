package localstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/e-l-l-a-r/gophkeeper/internal/model"
)

// cacheFormat - версия формата файла кеша.
const cacheFormat = 1

// Pending - несинхронизированное локальное изменение записи.
type Pending string

const (
	// PendingNone - запись совпадает с серверной версией.
	PendingNone Pending = ""
	// PendingCreate - запись создана локально и ещё не отправлена на сервер.
	PendingCreate Pending = "create"
	// PendingUpdate - запись изменена локально.
	PendingUpdate Pending = "update"
	// PendingDelete - запись удалена локально; на сервере она ещё существует.
	PendingDelete Pending = "delete"
)

// Record - запись в кеше. Содержимое Payload зашифровано мастер-ключом и
// записано в том же виде, в каком его хранит сервер.
type Record struct {
	// UpdatedAt - время последнего изменения: по данным сервера для
	// синхронизированных записей и по часам клиента для локальных изменений.
	UpdatedAt time.Time `json:"updated_at"`
	// ID - идентификатор записи (UUID).
	ID string `json:"id"`
	// Pending - несинхронизированное локальное изменение.
	Pending Pending `json:"pending,omitempty"`
	// Payload - зашифрованное содержимое записи.
	Payload []byte `json:"payload"`
	// Version - версия записи на сервере, на которой основано локальное
	// состояние; 0 для записи, которая ещё не отправлялась на сервер.
	Version int64 `json:"version"`
	// Kind - тип записи.
	Kind model.Kind `json:"kind"`
}

// cacheFile - содержимое файла кеша на диске.
type cacheFile struct {
	Server  string   `json:"server"`
	Login   string   `json:"login"`
	Records []Record `json:"records"`
	Format  int      `json:"format"`
}

// Cache - локальный кеш записей одного пользователя на одном сервере.
// Изменения накапливаются в памяти и сбрасываются на диск вызовом Save.
// Безопасен для использования из нескольких горутин одного процесса;
// одновременная работа нескольких процессов с одним кешем не поддерживается.
type Cache struct {
	records map[string]Record
	path    string
	server  string
	login   string
	mu      sync.Mutex
}

// OpenCache открывает кеш пользователя login на сервере server. Если файла
// кеша ещё нет, возвращается пустой кеш.
func (s *Store) OpenCache(server, login string) (*Cache, error) {
	c := &Cache{
		path:    filepath.Join(s.dir, cacheFileName(server, login)),
		server:  server,
		login:   login,
		records: make(map[string]Record),
	}

	var file cacheFile

	err := readJSON(c.path, &file)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return c, nil
	case err != nil:
		return nil, err
	case file.Format != cacheFormat:
		return nil, fmt.Errorf("файл кеша %q имеет неподдерживаемый формат %d", c.path, file.Format)
	}

	for _, rec := range file.Records {
		if rec.ID == "" {
			return nil, fmt.Errorf("файл кеша %q повреждён: запись без идентификатора", c.path)
		}
		c.records[rec.ID] = rec
	}

	return c, nil
}

// Get возвращает запись по идентификатору. Срезы возвращённой записи
// разделяются с кешем и не должны изменяться.
func (c *Cache) Get(id string) (Record, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	rec, ok := c.records[id]

	return rec, ok
}

// Put добавляет запись или заменяет запись с тем же идентификатором. На диск
// запись попадёт после Save.
func (c *Cache) Put(rec Record) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.records[rec.ID] = rec
}

// Delete удаляет запись из кеша. На диске она исчезнет после Save.
func (c *Cache) Delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.records, id)
}

// Records возвращает все записи кеша в порядке возрастания идентификатора.
func (c *Cache) Records() []Record {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.sortedLocked()
}

// Save атомарно записывает кеш на диск с правами 0600. Прежнее содержимое
// файла остаётся нетронутым, если запись не удалась.
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return writeJSON(c.path, cacheFile{
		Server:  c.server,
		Login:   c.login,
		Records: c.sortedLocked(),
		Format:  cacheFormat,
	})
}

// sortedLocked возвращает записи, отсортированные по идентификатору. Вызывается
// под захваченным c.mu; для пустого кеша возвращает пустой, а не nil срез,
// чтобы в JSON получился [], а не null.
func (c *Cache) sortedLocked() []Record {
	records := make([]Record, 0, len(c.records))
	for _, rec := range c.records {
		records = append(records, rec)
	}

	slices.SortFunc(records, func(a, b Record) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		default:
			return 0
		}
	})

	return records
}
