package client

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/e-l-l-a-r/gophkeeper/internal/crypto"
	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
	"github.com/e-l-l-a-r/gophkeeper/internal/model"
	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
)

// Client работает с записями пользователя: добавляет, изменяет, удаляет и
// читает их в локальном кеше и синхронизирует кеш с сервером (Sync).
//
// Client не безопасен для одновременного использования из нескольких горутин.
type Client struct {
	remote   Remote
	cache    *localstore.Cache
	keys     *crypto.Keyring
	now      func() time.Time
	verified bool
}

// Summary - краткие сведения о записи для списка. Секретных данных не содержит.
type Summary struct {
	// UpdatedAt - время последнего изменения.
	UpdatedAt time.Time
	// ID - идентификатор записи.
	ID string
	// Name - название записи.
	Name string
	// Meta - метаинформация записи.
	Meta string
	// Pending - несинхронизированное локальное изменение (пусто, если запись синхронизирована).
	Pending localstore.Pending
	// Kind - тип записи.
	Kind model.Kind
}

// ErrNoKeys возвращается операциями, которым нужен мастер-ключ (Add, Edit,
// Get, List), если клиент создан без связки ключей.
var ErrNoKeys = errors.New("мастер-ключ не задан")

// New создаёт клиента, работающего с сервером remote, кешем cache и
// мастер-ключами keys. Операции, которые не расшифровывают записи (Remove,
// Sync, Resolve), работают и с keys == nil: мастер-пароль им не нужен. Add,
// Edit, Get и List без ключей возвращают ErrNoKeys.
func New(remote Remote, cache *localstore.Cache, keys *crypto.Keyring) *Client {
	return &Client{remote: remote, cache: cache, keys: keys, now: time.Now}
}

// Add проверяет и шифрует запись, сохраняет её в локальном кеше как новую
// несинхронизированную и возвращает присвоенный ей идентификатор. Поле
// entry.ID игнорируется. На сервер запись попадёт при следующем Sync.
func (c *Client) Add(entry model.Entry) (string, error) {
	if err := c.verifyKey(); err != nil {
		return "", err
	}

	id, err := model.NewID()
	if err != nil {
		return "", err
	}
	entry.ID = id

	payload, err := c.seal(entry)
	if err != nil {
		return "", err
	}

	c.cache.Put(localstore.Record{
		UpdatedAt: c.now(),
		ID:        id,
		Pending:   localstore.PendingCreate,
		Payload:   payload,
		Kind:      entry.Kind,
	})

	if err := c.cache.Save(); err != nil {
		return "", err
	}

	return id, nil
}

// Edit заменяет запись с идентификатором entry.ID новым содержимым и помечает
// изменение как несинхронизированное. Возвращает ErrNotFound, если записи нет
// или она удалена.
func (c *Client) Edit(entry model.Entry) error {
	id := normalizeID(entry.ID)

	rec, ok := c.cache.Get(id)
	if !ok || rec.Pending == localstore.PendingDelete {
		return ErrNotFound
	}

	if err := c.verifyKey(); err != nil {
		return err
	}

	entry.ID = id

	payload, err := c.seal(entry)
	if err != nil {
		return err
	}

	rec.Payload = payload
	rec.Kind = entry.Kind
	rec.UpdatedAt = c.now()
	if rec.Pending == localstore.PendingNone {
		rec.Pending = localstore.PendingUpdate
	}

	c.cache.Put(rec)

	return c.cache.Save()
}

// Remove удаляет запись. Запись, которая ещё не попадала на сервер, исчезает
// сразу; остальные помечаются удалёнными и удаляются на сервере при следующем
// Sync. Возвращает ErrNotFound, если записи нет или она уже удалена.
func (c *Client) Remove(id string) error {
	id = normalizeID(id)

	rec, ok := c.cache.Get(id)
	if !ok || rec.Pending == localstore.PendingDelete {
		return ErrNotFound
	}

	if rec.Pending == localstore.PendingCreate {
		c.cache.Delete(id)
	} else {
		rec.Pending = localstore.PendingDelete
		rec.Payload = nil // содержимое удалённой записи локально не храним
		rec.UpdatedAt = c.now()
		c.cache.Put(rec)
	}

	return c.cache.Save()
}

// Get возвращает расшифрованную запись. Возвращает ErrNotFound, если записи
// нет или она удалена, и ошибку, оборачивающую crypto.ErrDecrypt, если
// мастер-пароль не подходит.
func (c *Client) Get(id string) (model.Entry, error) {
	rec, ok := c.cache.Get(normalizeID(id))
	if !ok || rec.Pending == localstore.PendingDelete {
		return model.Entry{}, ErrNotFound
	}

	return c.open(rec)
}

// List возвращает краткие сведения обо всех неудалённых записях, отсортированные
// по названию без учёта регистра. Для получения названий записи расшифровываются.
func (c *Client) List() ([]Summary, error) {
	records := c.cache.Records()
	summaries := make([]Summary, 0, len(records))

	for _, rec := range records {
		if rec.Pending == localstore.PendingDelete {
			continue
		}

		entry, err := c.open(rec)
		if err != nil {
			return nil, err
		}

		summaries = append(summaries, Summary{
			UpdatedAt: rec.UpdatedAt,
			ID:        rec.ID,
			Name:      entry.Name,
			Meta:      entry.Meta,
			Pending:   rec.Pending,
			Kind:      rec.Kind,
		})
	}

	slices.SortFunc(summaries, func(a, b Summary) int {
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}

		return strings.Compare(a.ID, b.ID)
	})

	return summaries, nil
}

// seal проверяет, сериализует и шифрует запись. Возвращает ошибку, если
// зашифрованная запись не уместится в лимит сервера.
func (c *Client) seal(entry model.Entry) ([]byte, error) {
	if c.keys == nil {
		return nil, ErrNoKeys
	}

	data, err := entry.Marshal()
	if err != nil {
		return nil, err
	}

	payload, err := c.keys.Encrypt(data)
	if err != nil {
		return nil, err
	}

	if len(payload) > pb.MaxPayloadSize {
		return nil, fmt.Errorf("%w: после шифрования запись занимает %d байт, максимум %d",
			model.ErrInvalid, len(payload), pb.MaxPayloadSize)
	}

	return payload, nil
}

// open расшифровывает запись кеша.
func (c *Client) open(rec localstore.Record) (model.Entry, error) {
	if c.keys == nil {
		return model.Entry{}, ErrNoKeys
	}

	data, err := c.keys.Decrypt(rec.Payload)
	if err != nil {
		return model.Entry{}, fmt.Errorf("запись %s: %w", rec.ID, err)
	}

	return model.Unmarshal(rec.ID, rec.Kind, data)
}

// verifyKey проверяет, что мастер-ключ подходит к уже имеющимся записям, и
// запоминает результат. Это защита от записи данных, зашифрованных ключом из
// ошибочно введённого мастер-пароля: сервер проверить пароль не может. Если в
// кеше нет записей с содержимым, проверять нечем и проверка пропускается.
func (c *Client) verifyKey() error {
	if c.keys == nil {
		return ErrNoKeys
	}
	if c.verified {
		return nil
	}

	var probe *localstore.Record

	for _, rec := range c.cache.Records() {
		if rec.Pending == localstore.PendingDelete || len(rec.Payload) == 0 {
			continue
		}
		// Проверяем на самой маленькой записи: расшифровка не должна быть дорогой.
		if probe == nil || len(rec.Payload) < len(probe.Payload) {
			probe = &rec
		}
	}

	if probe == nil {
		return nil
	}

	if _, err := c.keys.Decrypt(probe.Payload); err != nil {
		if errors.Is(err, crypto.ErrDecrypt) {
			return fmt.Errorf("мастер-пароль не подходит к сохранённым записям: %w", err)
		}

		return err
	}

	c.verified = true

	return nil
}

// normalizeID приводит идентификатор записи к виду, в котором его хранят
// сервер и кеш: нижний регистр без пробелов по краям.
func normalizeID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}
