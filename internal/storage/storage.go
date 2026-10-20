// Package storage определяет интерфейсы хранилища сервера GophKeeper
// (пользователи и зашифрованные записи) и содержит две реализации:
// на PostgreSQL (Postgres) и в памяти (Memory). Реализация в памяти
// предназначена для тестов других пакетов.
//
// Хранилище не знает о шифровании и аутентификации: оно хранит пароли только
// в виде готовых хешей, а содержимое записей - в виде готового шифротекста.
package storage

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrUserExists возвращается при создании пользователя с занятым логином.
	ErrUserExists = errors.New("пользователь уже существует")
	// ErrUserNotFound возвращается, если пользователя с таким логином нет.
	ErrUserNotFound = errors.New("пользователь не найден")
	// ErrSecretExists возвращается при создании записи с уже занятым
	// идентификатором, в том числе если запись была удалена.
	ErrSecretExists = errors.New("запись уже существует")
	// ErrSecretNotFound возвращается, если записи нет или она удалена.
	ErrSecretNotFound = errors.New("запись не найдена")
	// ErrVersionConflict возвращается, если ожидаемая версия записи не
	// совпадает с текущей версией в хранилище (оптимистичная блокировка).
	ErrVersionConflict = errors.New("конфликт версий записи")
)

// User - пользователь системы.
type User struct {
	// CreatedAt - время регистрации; заполняется хранилищем.
	CreatedAt time.Time
	// Login - уникальный логин.
	Login string
	// PasswordHash - хеш пароля.
	PasswordHash []byte
	// PasswordSalt - соль, с которой получен PasswordHash.
	PasswordSalt []byte
	// KDFSalt - соль вывода ключа шифрования на клиенте.
	KDFSalt []byte
	// ID - идентификатор пользователя; заполняется хранилищем.
	ID int64
}

// Secret - зашифрованная запись пользователя.
type Secret struct {
	// UpdatedAt - время последнего изменения; заполняется хранилищем.
	UpdatedAt time.Time
	// ID - идентификатор записи (UUID), заданный клиентом.
	ID string
	// EncryptedPayload - шифротекст содержимого записи. У удалённой записи пуст.
	EncryptedPayload []byte
	// Version - версия записи; хранилище увеличивает её при каждом изменении.
	Version int64
	// Type - тип записи (значение SecretType из протокола).
	Type int16
	// Deleted - признак удалённой записи («надгробие»).
	Deleted bool
}

// UserStorage - хранилище пользователей.
type UserStorage interface {
	// CreateUser сохраняет нового пользователя и возвращает его с
	// заполненными ID и CreatedAt. Возвращает ErrUserExists, если логин занят.
	CreateUser(ctx context.Context, user User) (User, error)
	// UserByLogin возвращает пользователя по логину или ErrUserNotFound.
	UserByLogin(ctx context.Context, login string) (User, error)
}

// SecretStorage - хранилище записей. Все методы работают только с записями
// указанного пользователя: чужие записи для него не существуют.
type SecretStorage interface {
	// CreateSecret сохраняет новую запись с версией 1 и возвращает её с
	// заполненными Version и UpdatedAt. Возвращает ErrSecretExists, если запись
	// с таким идентификатором уже есть (в том числе удалённая).
	CreateSecret(ctx context.Context, userID int64, secret Secret) (Secret, error)
	// GetSecret возвращает неудалённую запись или ErrSecretNotFound.
	GetSecret(ctx context.Context, userID int64, id string) (Secret, error)
	// UpdateSecret заменяет тип и шифротекст записи, если её текущая версия
	// равна expectedVersion, и увеличивает версию. Возвращает ErrSecretNotFound,
	// если записи нет или она удалена, и ErrVersionConflict при несовпадении версии.
	UpdateSecret(ctx context.Context, userID int64, secret Secret, expectedVersion int64) (Secret, error)
	// DeleteSecret помечает запись удалённой, очищает шифротекст и увеличивает
	// версию, если текущая версия равна expectedVersion. Ошибки те же, что у UpdateSecret.
	DeleteSecret(ctx context.Context, userID int64, id string, expectedVersion int64) error
	// ListSecrets возвращает все записи пользователя, включая удалённые
	// («надгробия»), в порядке изменения. Используется для расчёта дельты синхронизации.
	ListSecrets(ctx context.Context, userID int64) ([]Secret, error)
}
