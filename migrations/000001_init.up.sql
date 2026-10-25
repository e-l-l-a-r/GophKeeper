-- Миграция: пользователи.
-- Пароль хранится только в виде хеша с солью; kdf_salt - соль вывода ключа
-- шифрования на клиенте, она не секретна и отдаётся клиентам владельца.
CREATE TABLE IF NOT EXISTS users (
    id             BIGSERIAL PRIMARY KEY,
    login          TEXT        NOT NULL UNIQUE,
    password_hash  BYTEA       NOT NULL,
    password_salt  BYTEA       NOT NULL,
    kdf_salt       BYTEA       NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Миграция: зашифрованные записи пользователей.
-- Идентификатор записи уникален в пределах пользователя, поэтому чужие записи
-- не могут повлиять на создание своих. Удалённая запись остаётся «надгробием»
-- (deleted = TRUE, пустой encrypted_payload), чтобы другие клиенты узнали об
-- удалении при синхронизации.
CREATE TABLE IF NOT EXISTS secrets (
    user_id           BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    id                UUID        NOT NULL,
    type              SMALLINT    NOT NULL CHECK (type BETWEEN 1 AND 4),
    encrypted_payload BYTEA       NOT NULL,
    version           BIGINT      NOT NULL DEFAULT 1 CHECK (version > 0),
    deleted           BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, id)
);

-- Индекс для выборки записей пользователя в порядке изменения.
CREATE INDEX IF NOT EXISTS idx_secrets_user_updated ON secrets (user_id, updated_at);
