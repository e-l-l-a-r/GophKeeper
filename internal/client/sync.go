package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
	"github.com/e-l-l-a-r/gophkeeper/internal/model"
)

// ErrConflict возвращается из Sync, если после синхронизации остались
// конфликтующие записи. Остальные записи при этом синхронизированы.
var ErrConflict = errors.New("есть конфликты синхронизации")

// ErrNoPending возвращается из Resolve для записи без несинхронизированных изменений.
var ErrNoPending = errors.New("у записи нет несинхронизированных изменений")

// ConflictReason - причина конфликта синхронизации.
type ConflictReason string

const (
	// ConflictVersion - запись изменена на сервере другим клиентом.
	ConflictVersion ConflictReason = "version"
	// ConflictDeleted - запись удалена на сервере, а здесь изменена.
	ConflictDeleted ConflictReason = "deleted"
	// ConflictExists - идентификатор новой записи уже занят другой записью.
	ConflictExists ConflictReason = "exists"
)

// Conflict - запись, которую не удалось синхронизировать из-за конфликта.
type Conflict struct {
	// ID - идентификатор записи.
	ID string
	// Reason - причина конфликта.
	Reason ConflictReason
	// Pending - локальное изменение, вызвавшее конфликт.
	Pending localstore.Pending
	// Kind - тип записи.
	Kind model.Kind
}

// SyncResult - итог синхронизации.
type SyncResult struct {
	// Conflicts - записи с конфликтами; решаются через Client.Resolve.
	Conflicts []Conflict
	// Pushed - число локальных изменений, принятых сервером.
	Pushed int
	// Pulled - число записей, полученных или обновлённых с сервера.
	Pulled int
	// Removed - число записей, удалённых локально, потому что их удалили на сервере.
	Removed int
}

// Keep - решение по конфликтующей записи.
type Keep int

const (
	// KeepLocal оставляет локальное изменение: оно будет отправлено на сервер при
	// следующем Sync поверх текущей серверной версии. Если запись удалена на
	// сервере, локальная версия сохраняется как новая запись с новым идентификатором.
	KeepLocal Keep = iota + 1
	// KeepServer отбрасывает локальное изменение и принимает версию сервера.
	KeepServer
)

// Sync синхронизирует локальный кеш с сервером в два шага. Сначала на сервер
// отправляются локальные изменения (создание, изменение, удаление), затем с
// сервера по дельте версий забираются чужие изменения.
//
// Ничего не перезаписывается молча: запись, изменённая на сервере другим
// клиентом, остаётся в кеше как есть и попадает в SyncResult.Conflicts. В этом
// случае Sync выполняет всю остальную работу и возвращает результат вместе с
// ошибкой, оборачивающей ErrConflict.
//
// При сетевой ошибке Sync прерывается; уже отправленные изменения сохранены в
// кеше, поэтому повторный вызов продолжит с места сбоя. Отправка идемпотентна:
// если сервер принял запись, но ответ потерялся, повтор распознаёт это и не
// считает конфликтом.
func (c *Client) Sync(ctx context.Context) (SyncResult, error) {
	var result SyncResult

	err := c.push(ctx, &result)
	if err == nil {
		err = c.pull(ctx, &result)
	}

	if saveErr := c.cache.Save(); saveErr != nil {
		err = errors.Join(err, saveErr)
	}

	if err == nil && len(result.Conflicts) > 0 {
		err = fmt.Errorf("%w: записей %d", ErrConflict, len(result.Conflicts))
	}

	return result, err
}

// push отправляет на сервер все локальные изменения.
func (c *Client) push(ctx context.Context, result *SyncResult) error {
	for _, rec := range c.cache.Records() {
		if rec.Pending == localstore.PendingNone {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		reason, err := c.pushOne(ctx, rec)
		if err != nil {
			return fmt.Errorf("не удалось отправить запись %s: %w", rec.ID, err)
		}

		if reason != "" {
			result.Conflicts = append(result.Conflicts, Conflict{
				ID: rec.ID, Reason: reason, Pending: rec.Pending, Kind: rec.Kind,
			})

			continue
		}

		result.Pushed++
	}

	return nil
}

// pushOne отправляет одно локальное изменение. Непустая причина означает
// конфликт: запись в кеше не изменена. Ошибка означает сбой, при котором
// синхронизацию нужно прервать.
func (c *Client) pushOne(ctx context.Context, rec localstore.Record) (ConflictReason, error) {
	if rec.Pending != localstore.PendingCreate && rec.Version < 1 {
		return "", fmt.Errorf("запись повреждена: у синхронизированной записи нет версии")
	}

	switch rec.Pending {
	case localstore.PendingCreate:
		return c.pushCreate(ctx, rec)
	case localstore.PendingUpdate:
		return c.pushUpdate(ctx, rec)
	case localstore.PendingDelete:
		return c.pushDelete(ctx, rec)
	default:
		return "", fmt.Errorf("неизвестное состояние записи %q", rec.Pending)
	}
}

// pushCreate отправляет новую запись.
func (c *Client) pushCreate(ctx context.Context, rec localstore.Record) (ConflictReason, error) {
	secret, err := c.remote.Create(ctx, rec.ID, rec.Kind, rec.Payload)

	switch {
	case err == nil:
		c.applyPushed(rec, secret)

		return "", nil
	case errors.Is(err, ErrAlreadyExists):
		// Либо прошлая отправка дошла, а ответ потерялся, либо идентификатор занят.
		return c.adoptIfSame(ctx, rec, ConflictExists, ConflictExists)
	default:
		return "", err
	}
}

// pushUpdate отправляет изменение записи.
func (c *Client) pushUpdate(ctx context.Context, rec localstore.Record) (ConflictReason, error) {
	secret, err := c.remote.Update(ctx, rec.ID, rec.Kind, rec.Payload, rec.Version)

	switch {
	case err == nil:
		c.applyPushed(rec, secret)

		return "", nil
	case errors.Is(err, ErrNotFound):
		return ConflictDeleted, nil
	case errors.Is(err, ErrVersionConflict):
		// Либо прошлая отправка дошла, а ответ потерялся, либо запись изменил другой клиент.
		return c.adoptIfSame(ctx, rec, ConflictDeleted, ConflictVersion)
	default:
		return "", err
	}
}

// pushDelete отправляет удаление записи.
func (c *Client) pushDelete(ctx context.Context, rec localstore.Record) (ConflictReason, error) {
	err := c.remote.Delete(ctx, rec.ID, rec.Version)

	switch {
	case err == nil, errors.Is(err, ErrNotFound):
		// Запись уже удалена (в том числе нашей прошлой отправкой): цель достигнута.
		c.cache.Delete(rec.ID)

		return "", nil
	case errors.Is(err, ErrVersionConflict):
		return ConflictVersion, nil
	default:
		return "", err
	}
}

// adoptIfSame сверяет серверную запись с локальной. Если содержимое и тип
// совпадают, считает изменение уже принятым сервером и принимает серверную
// версию; иначе возвращает причину конфликта. ifGone - причина, если записи на
// сервере нет (удалена), ifDiffers - если содержимое отличается.
func (c *Client) adoptIfSame(ctx context.Context, rec localstore.Record, ifGone, ifDiffers ConflictReason) (ConflictReason, error) {
	secret, err := c.remote.Get(ctx, rec.ID)

	switch {
	case errors.Is(err, ErrNotFound):
		return ifGone, nil
	case err != nil:
		return "", err
	case secret.Kind == rec.Kind && bytes.Equal(secret.Payload, rec.Payload):
		c.applyPushed(rec, secret)

		return "", nil
	default:
		return ifDiffers, nil
	}
}

// applyPushed отмечает запись синхронизированной с версией secret.
func (c *Client) applyPushed(rec localstore.Record, secret Secret) {
	rec.Version = secret.Version
	rec.UpdatedAt = secret.UpdatedAt
	rec.Pending = localstore.PendingNone

	c.cache.Put(rec)
}

// pull получает с сервера дельту и применяет её. Записи с несинхронизированными
// локальными изменениями не трогаются: это конфликты, о которых сообщил push.
func (c *Client) pull(ctx context.Context, result *SyncResult) error {
	var known []Known

	for _, rec := range c.cache.Records() {
		if rec.Version > 0 {
			known = append(known, Known{ID: rec.ID, Version: rec.Version})
		}
	}

	changed, deleted, err := c.remote.Sync(ctx, known)
	if err != nil {
		return fmt.Errorf("не удалось получить изменения с сервера: %w", err)
	}

	for _, secret := range changed {
		if rec, ok := c.cache.Get(secret.ID); ok && rec.Pending != localstore.PendingNone {
			continue
		}

		c.cache.Put(localstore.Record{
			UpdatedAt: secret.UpdatedAt,
			ID:        secret.ID,
			Payload:   secret.Payload,
			Version:   secret.Version,
			Kind:      secret.Kind,
		})
		result.Pulled++
	}

	for _, id := range deleted {
		if rec, ok := c.cache.Get(id); !ok || rec.Pending != localstore.PendingNone {
			continue
		}

		c.cache.Delete(id)
		result.Removed++
	}

	return nil
}

// Resolve разрешает конфликт по записи id в пользу keep. Возвращает
// ErrNotFound, если записи нет в кеше, и ErrNoPending, если у неё нет
// несинхронизированных изменений. После KeepLocal выполните Sync, чтобы
// отправить изменение на сервер.
func (c *Client) Resolve(ctx context.Context, id string, keep Keep) error {
	if keep != KeepLocal && keep != KeepServer {
		return fmt.Errorf("неизвестное решение %d", keep)
	}

	id = normalizeID(id)

	rec, ok := c.cache.Get(id)
	if !ok {
		return ErrNotFound
	}
	if rec.Pending == localstore.PendingNone {
		return ErrNoPending
	}

	secret, err := c.remote.Get(ctx, id)
	gone := errors.Is(err, ErrNotFound)
	if err != nil && !gone {
		return err
	}

	if keep == KeepServer {
		c.keepServer(id, secret, gone)
	} else if err = c.keepLocal(rec, secret, gone); err != nil {
		return err
	}

	return c.cache.Save()
}

// keepServer принимает серверную версию записи; если на сервере её нет,
// удаляет запись из кеша.
func (c *Client) keepServer(id string, secret Secret, gone bool) {
	if gone {
		c.cache.Delete(id)

		return
	}

	c.cache.Put(localstore.Record{
		UpdatedAt: secret.UpdatedAt,
		ID:        id,
		Payload:   secret.Payload,
		Version:   secret.Version,
		Kind:      secret.Kind,
	})
}

// keepLocal сохраняет локальное изменение, перенося его на текущую версию
// сервера. Если запись на сервере удалена, локальное содержимое становится
// новой записью: удалённый идентификатор повторно использовать нельзя.
func (c *Client) keepLocal(rec localstore.Record, secret Secret, gone bool) error {
	switch {
	case !gone:
		rec.Version = secret.Version
		if rec.Pending == localstore.PendingCreate {
			rec.Pending = localstore.PendingUpdate
		}
		c.cache.Put(rec)
	case rec.Pending == localstore.PendingDelete:
		// Запись удалена и там, и здесь.
		c.cache.Delete(rec.ID)
	default:
		newID, err := model.NewID()
		if err != nil {
			return err
		}

		c.cache.Delete(rec.ID)
		c.cache.Put(localstore.Record{
			UpdatedAt: c.now(),
			ID:        newID,
			Pending:   localstore.PendingCreate,
			Payload:   rec.Payload,
			Kind:      rec.Kind,
		})
	}

	return nil
}
