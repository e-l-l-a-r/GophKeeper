// Package auth реализует аутентификацию и авторизацию на сервере GophKeeper
// только средствами стандартной библиотеки: хеширование паролей (PBKDF2),
// подписанные токены доступа (HMAC-SHA256) и gRPC-интерцептор, который
// проверяет токен и передаёт идентификатор пользователя в контекст запроса.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

const (
	// DefaultPBKDF2Iterations - число итераций PBKDF2-HMAC-SHA256 для хеширования
	// паролей; соответствует рекомендации OWASP для SHA-256.
	DefaultPBKDF2Iterations = 600_000

	// saltSize - размер случайной соли пароля в байтах.
	saltSize = 16
	// hashSize - размер хеша пароля в байтах (длина вывода SHA-256).
	hashSize = 32
)

// PasswordHasher хеширует и проверяет пароли пользователей алгоритмом
// PBKDF2-HMAC-SHA256 со случайной солью.
//
// Число итераций нигде не сохраняется вместе с хешем, поэтому его изменение
// делает все ранее сохранённые хеши непроверяемыми.
type PasswordHasher struct {
	iterations int
}

// NewPasswordHasher создаёт PasswordHasher с заданным числом итераций PBKDF2.
// В рабочей конфигурации используйте DefaultPBKDF2Iterations; меньшие значения
// допустимы только в тестах.
func NewPasswordHasher(iterations int) (*PasswordHasher, error) {
	if iterations < 1 {
		return nil, errors.New("число итераций PBKDF2 должно быть положительным")
	}

	return &PasswordHasher{iterations: iterations}, nil
}

// Hash возвращает хеш пароля и случайную соль, с которой он получен.
func (h *PasswordHasher) Hash(password string) (hash, salt []byte, err error) {
	salt = make([]byte, saltSize)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("не удалось сгенерировать соль: %w", err)
	}

	hash, err = deriveKey(password, salt, h.iterations)
	if err != nil {
		return nil, nil, err
	}

	return hash, salt, nil
}

// Verify сообщает, получен ли hash из password с солью salt. Сравнение
// выполняется за постоянное время.
func (h *PasswordHasher) Verify(password string, hash, salt []byte) (bool, error) {
	got, err := deriveKey(password, salt, h.iterations)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(got, hash) == 1, nil
}

// deriveKey выводит ключ длиной hashSize из пароля и соли алгоритмом PBKDF2-HMAC-SHA256.
func deriveKey(password string, salt []byte, iterations int) ([]byte, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, hashSize)
	if err != nil {
		return nil, fmt.Errorf("не удалось вычислить хеш пароля: %w", err)
	}

	return key, nil
}
