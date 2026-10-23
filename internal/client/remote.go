// Package client реализует ядро клиента GophKeeper: gRPC-соединение с
// сервером (Conn), локальную работу с зашифрованными записями (Client) и
// синхронизацию с сервером по дельте версий (Client.Sync).
//
// Клиент работает автономно: Add, Edit и Remove изменяют только локальный
// кеш и помечают запись как несинхронизированную. Sync отправляет такие
// изменения на сервер и получает чужие. Содержимое записей шифруется
// мастер-ключом до отправки, сервер видит только шифротекст.
//
// Конфликты: если запись изменена на сервере другим клиентом, Sync ничего не
// перезаписывает ни на сервере, ни локально. Он сообщает о конфликте
// (SyncResult.Conflicts, ошибка ErrConflict), а пользователь решает судьбу
// записи через Client.Resolve.
//
// Мастер-пароль нельзя проверить на сервере: он нигде не хранится. Поэтому
// перед первым добавлением записей на новом устройстве выполните Sync:
// Client.Add и Client.Edit сверяют ключ с уже существующей записью и
// отказываются работать с неверным мастер-паролем. Без существующих записей
// сверить не с чем.
package client

import (
	"context"
	"errors"
	"time"

	"github.com/e-l-l-a-r/gophkeeper/internal/model"
)

var (
	// ErrNotFound возвращается, если записи нет (на сервере, в кеше) или она удалена.
	ErrNotFound = errors.New("запись не найдена")
	// ErrAlreadyExists возвращается, если запись с таким идентификатором уже есть на сервере.
	ErrAlreadyExists = errors.New("запись уже существует")
	// ErrVersionConflict возвращается, если версия записи на сервере не совпала с ожидаемой.
	ErrVersionConflict = errors.New("версия записи на сервере изменилась")
	// ErrUnauthenticated возвращается, если токен доступа отсутствует, недействителен или истёк.
	ErrUnauthenticated = errors.New("требуется вход: токен недействителен или истёк")
	// ErrUnavailable возвращается, если сервер недоступен.
	ErrUnavailable = errors.New("сервер недоступен")
	// ErrRejected возвращается, если сервер отклонил запрос как некорректный.
	ErrRejected = errors.New("сервер отклонил запрос")
	// ErrLoginTaken возвращается при регистрации с уже занятым логином.
	ErrLoginTaken = errors.New("логин уже занят")
	// ErrInvalidCredentials возвращается при входе с неверным логином или паролем.
	ErrInvalidCredentials = errors.New("неверный логин или пароль")
)

// Secret - зашифрованная запись, как её хранит сервер.
type Secret struct {
	// UpdatedAt - время последнего изменения на сервере.
	UpdatedAt time.Time
	// ID - идентификатор записи (UUID).
	ID string
	// Payload - зашифрованное содержимое записи.
	Payload []byte
	// Version - версия записи на сервере.
	Version int64
	// Kind - тип записи.
	Kind model.Kind
}

// Known - пара идентификатор/версия записи, известной клиенту.
type Known struct {
	// ID - идентификатор записи.
	ID string
	// Version - версия записи на клиенте.
	Version int64
}

// Remote - операции с сервером, которые нужны клиенту. Реализация на gRPC -
// Conn; интерфейс позволяет подменять сервер в тестах. Реализации возвращают
// ошибки, которые распознаются через errors.Is с ErrNotFound, ErrAlreadyExists,
// ErrVersionConflict, ErrUnauthenticated и ErrUnavailable.
type Remote interface {
	// Create создаёт запись и возвращает её с версией 1.
	Create(ctx context.Context, id string, kind model.Kind, payload []byte) (Secret, error)
	// Get возвращает неудалённую запись.
	Get(ctx context.Context, id string) (Secret, error)
	// Update заменяет содержимое записи, если её версия равна expectedVersion.
	Update(ctx context.Context, id string, kind model.Kind, payload []byte, expectedVersion int64) (Secret, error)
	// Delete удаляет запись, если её версия равна expectedVersion.
	Delete(ctx context.Context, id string, expectedVersion int64) error
	// Sync возвращает дельту: записи, которых нет у клиента или которые на
	// сервере новее, и идентификаторы известных клиенту записей, удалённых на сервере.
	Sync(ctx context.Context, known []Known) (changed []Secret, deleted []string, err error)
}
