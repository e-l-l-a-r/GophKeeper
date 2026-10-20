package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // драйвер "pgx" для database/sql

	"github.com/e-l-l-a-r/gophkeeper/migrations"
)

const (
	queryCreateUser = `INSERT INTO users (login, password_hash, password_salt, kdf_salt)
VALUES ($1, $2, $3, $4)
RETURNING id, created_at`

	queryUserByLogin = `SELECT id, login, password_hash, password_salt, kdf_salt, created_at
FROM users
WHERE login = $1`

	queryCreateSecret = `INSERT INTO secrets (user_id, id, type, encrypted_payload)
VALUES ($1, $2, $3, $4)
RETURNING version, updated_at`

	queryGetSecret = `SELECT id, type, encrypted_payload, version, updated_at
FROM secrets
WHERE user_id = $1 AND id = $2 AND NOT deleted`

	queryUpdateSecret = `UPDATE secrets
SET type = $3, encrypted_payload = $4, version = version + 1, updated_at = NOW()
WHERE user_id = $1 AND id = $2 AND version = $5 AND NOT deleted
RETURNING version, updated_at`

	queryDeleteSecret = `UPDATE secrets
SET deleted = TRUE, encrypted_payload = ''::bytea, version = version + 1, updated_at = NOW()
WHERE user_id = $1 AND id = $2 AND version = $3 AND NOT deleted
RETURNING version`

	querySecretState = `SELECT deleted FROM secrets WHERE user_id = $1 AND id = $2`

	queryListSecrets = `SELECT id, type, encrypted_payload, version, updated_at, deleted
FROM secrets
WHERE user_id = $1
ORDER BY updated_at, id`
)

// Postgres - хранилище пользователей и записей в PostgreSQL. Реализует
// UserStorage и SecretStorage.
type Postgres struct {
	db *sql.DB
}

var (
	_ UserStorage   = (*Postgres)(nil)
	_ SecretStorage = (*Postgres)(nil)
)

// NewPostgres открывает подключение к PostgreSQL по строке подключения dsn.
// Само подключение устанавливается лениво: для проверки доступности базы
// вызовите Ping, для создания таблиц - Migrate.
func NewPostgres(dsn string) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть подключение к базе данных: %w", err)
	}

	return NewPostgresFromDB(db), nil
}

// NewPostgresFromDB создаёт хранилище поверх готового подключения db.
// Владение подключением переходит хранилищу: Close закроет db.
func NewPostgresFromDB(db *sql.DB) *Postgres {
	return &Postgres{db: db}
}

// Ping проверяет доступность базы данных.
func (p *Postgres) Ping(ctx context.Context) error {
	if err := p.db.PingContext(ctx); err != nil {
		return fmt.Errorf("база данных недоступна: %w", err)
	}

	return nil
}

// Close закрывает подключение к базе данных.
func (p *Postgres) Close() error {
	if err := p.db.Close(); err != nil {
		return fmt.Errorf("не удалось закрыть подключение к базе данных: %w", err)
	}

	return nil
}

// Migrate применяет к базе данных все ещё не применённые миграции из пакета
// migrations. Повторный вызов без новых миграций ошибкой не считается.
func (p *Postgres) Migrate() error {
	source, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("не удалось открыть источник миграций: %w", err)
	}

	driver, err := migratepg.WithInstance(p.db, &migratepg.Config{})
	if err != nil {
		return fmt.Errorf("не удалось создать драйвер миграций: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return fmt.Errorf("не удалось создать мигратор: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("не удалось применить миграции: %w", err)
	}

	return nil
}

// CreateUser сохраняет нового пользователя. Реализует UserStorage.
func (p *Postgres) CreateUser(ctx context.Context, user User) (User, error) {
	err := p.db.QueryRowContext(ctx, queryCreateUser,
		user.Login, user.PasswordHash, user.PasswordSalt, user.KDFSalt,
	).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrUserExists
		}

		return User{}, fmt.Errorf("не удалось создать пользователя: %w", err)
	}

	return user, nil
}

// UserByLogin возвращает пользователя по логину. Реализует UserStorage.
func (p *Postgres) UserByLogin(ctx context.Context, login string) (User, error) {
	var user User
	err := p.db.QueryRowContext(ctx, queryUserByLogin, login).Scan(
		&user.ID, &user.Login, &user.PasswordHash, &user.PasswordSalt, &user.KDFSalt, &user.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("не удалось получить пользователя: %w", err)
	}

	return user, nil
}

// CreateSecret сохраняет новую запись. Реализует SecretStorage.
func (p *Postgres) CreateSecret(ctx context.Context, userID int64, secret Secret) (Secret, error) {
	err := p.db.QueryRowContext(ctx, queryCreateSecret,
		userID, secret.ID, secret.Type, nonNil(secret.EncryptedPayload),
	).Scan(&secret.Version, &secret.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Secret{}, ErrSecretExists
		}

		return Secret{}, fmt.Errorf("не удалось создать запись: %w", err)
	}

	secret.Deleted = false

	return secret, nil
}

// GetSecret возвращает неудалённую запись. Реализует SecretStorage.
func (p *Postgres) GetSecret(ctx context.Context, userID int64, id string) (Secret, error) {
	var secret Secret
	err := p.db.QueryRowContext(ctx, queryGetSecret, userID, id).Scan(
		&secret.ID, &secret.Type, &secret.EncryptedPayload, &secret.Version, &secret.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, ErrSecretNotFound
	}
	if err != nil {
		return Secret{}, fmt.Errorf("не удалось получить запись: %w", err)
	}

	return secret, nil
}

// UpdateSecret заменяет содержимое записи при совпадении версии.
// Реализует SecretStorage.
func (p *Postgres) UpdateSecret(ctx context.Context, userID int64, secret Secret, expectedVersion int64) (Secret, error) {
	err := p.db.QueryRowContext(ctx, queryUpdateSecret,
		userID, secret.ID, secret.Type, nonNil(secret.EncryptedPayload), expectedVersion,
	).Scan(&secret.Version, &secret.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, p.explainMiss(ctx, userID, secret.ID)
	}
	if err != nil {
		return Secret{}, fmt.Errorf("не удалось изменить запись: %w", err)
	}

	secret.Deleted = false

	return secret, nil
}

// DeleteSecret помечает запись удалённой при совпадении версии.
// Реализует SecretStorage.
func (p *Postgres) DeleteSecret(ctx context.Context, userID int64, id string, expectedVersion int64) error {
	var version int64
	err := p.db.QueryRowContext(ctx, queryDeleteSecret, userID, id, expectedVersion).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return p.explainMiss(ctx, userID, id)
	}
	if err != nil {
		return fmt.Errorf("не удалось удалить запись: %w", err)
	}

	return nil
}

// ListSecrets возвращает все записи пользователя, включая удалённые.
// Реализует SecretStorage.
func (p *Postgres) ListSecrets(ctx context.Context, userID int64) ([]Secret, error) {
	rows, err := p.db.QueryContext(ctx, queryListSecrets, userID)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить список записей: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var secrets []Secret
	for rows.Next() {
		var secret Secret
		if err := rows.Scan(
			&secret.ID, &secret.Type, &secret.EncryptedPayload, &secret.Version, &secret.UpdatedAt, &secret.Deleted,
		); err != nil {
			return nil, fmt.Errorf("не удалось прочитать запись: %w", err)
		}
		secrets = append(secrets, secret)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("не удалось прочитать список записей: %w", err)
	}

	return secrets, nil
}

// explainMiss определяет причину, по которой условный UPDATE не затронул
// ни одной строки: запись отсутствует или удалена (ErrSecretNotFound) либо
// существует, но её версия отличается от ожидаемой (ErrVersionConflict).
func (p *Postgres) explainMiss(ctx context.Context, userID int64, id string) error {
	var deleted bool
	err := p.db.QueryRowContext(ctx, querySecretState, userID, id).Scan(&deleted)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrSecretNotFound
	case err != nil:
		return fmt.Errorf("не удалось определить состояние записи: %w", err)
	case deleted:
		return ErrSecretNotFound
	default:
		return ErrVersionConflict
	}
}

// nonNil заменяет nil-срез пустым: драйвер передаёт nil как NULL, а столбец
// encrypted_payload объявлен NOT NULL.
func nonNil(data []byte) []byte {
	if data == nil {
		return []byte{}
	}

	return data
}

// isUniqueViolation сообщает, что err - нарушение уникальности PostgreSQL.
func isUniqueViolation(err error) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)

	return ok && pgErr.Code == pgerrcode.UniqueViolation
}
