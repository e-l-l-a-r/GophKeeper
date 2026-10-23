// Package crypto реализует клиентское шифрование данных GophKeeper только
// средствами стандартной библиотеки: ключ выводится из мастер-пароля
// алгоритмом PBKDF2-HMAC-SHA256, данные шифруются AES-256-GCM. Сервер хранит
// только шифротекст и мастер-пароля не знает.
//
// Формат зашифрованного blob:
//
//	[1 байт]  версия формата (сейчас 1)
//	[4 байта] число итераций PBKDF2, big-endian
//	[12 байт] случайный nonce AES-GCM
//	[N байт]  шифротекст и 16-байтовый тег аутентификации
//
// Версия и число итераций входят в дополнительные аутентифицируемые данные
// (AAD) GCM, поэтому их подмена делает расшифровку невозможной. Число
// итераций хранится в самом blob, чтобы его можно было повышать, не теряя
// возможности прочитать старые записи.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// FormatVersion - текущая версия формата зашифрованного blob.
	FormatVersion byte = 1

	// DefaultIterations - число итераций PBKDF2-HMAC-SHA256 для вывода ключа
	// шифрования; соответствует рекомендации OWASP для SHA-256.
	DefaultIterations = 600_000

	// MinIterations и MaxIterations - допустимые границы числа итераций в blob.
	// Верхняя граница не даёт подделанному blob заставить клиента считать
	// ключ неограниченно долго.
	MinIterations = 1
	MaxIterations = 10_000_000

	// MinSaltSize - минимальный размер соли вывода ключа в байтах.
	MinSaltSize = 16

	// SaltSize - размер соли вывода ключа, которую клиент генерирует при
	// регистрации (NewSalt).
	SaltSize = 32

	// KeySize - размер ключа AES-256 в байтах.
	KeySize = 32

	// headerSize - размер заголовка blob: версия и число итераций.
	headerSize = 1 + 4
	// nonceSize - размер nonce AES-GCM.
	nonceSize = 12
	// tagSize - размер тега аутентификации AES-GCM.
	tagSize = 16

	// Overhead - число байт, на которое шифрование увеличивает данные:
	// заголовок, nonce и тег аутентификации.
	Overhead = headerSize + nonceSize + tagSize
)

var (
	// ErrDecrypt возвращается, если blob не удалось расшифровать: неверный
	// мастер-пароль или повреждённые данные. Эти случаи не различаются
	// намеренно.
	ErrDecrypt = errors.New("не удалось расшифровать данные: неверный мастер-пароль или данные повреждены")
	// ErrFormat возвращается, если blob имеет неизвестную версию формата,
	// недопустимое число итераций или слишком короток.
	ErrFormat = errors.New("неподдерживаемый формат зашифрованных данных")
)

// Key - ключ шифрования, выведенный из мастер-пароля.
type Key struct {
	aead       cipher.AEAD
	iterations uint32
}

// DeriveKey выводит ключ из мастер-пароля password и соли salt (соль выдаёт
// сервер при регистрации и входе) за iterations итераций PBKDF2-HMAC-SHA256.
func DeriveKey(password string, salt []byte, iterations int) (*Key, error) {
	if password == "" {
		return nil, errors.New("мастер-пароль не может быть пустым")
	}
	if len(salt) < MinSaltSize {
		return nil, fmt.Errorf("соль короче %d байт", MinSaltSize)
	}
	if iterations < MinIterations || iterations > MaxIterations {
		return nil, fmt.Errorf("число итераций должно быть от %d до %d", MinIterations, MaxIterations)
	}

	raw, err := pbkdf2.Key(sha256.New, password, salt, iterations, KeySize)
	if err != nil {
		return nil, fmt.Errorf("не удалось вывести ключ шифрования: %w", err)
	}

	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать шифр: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать режим GCM: %w", err)
	}

	return &Key{aead: aead, iterations: uint32(iterations)}, nil
}

// NewSalt возвращает новую случайную соль вывода ключа размера SaltSize.
// Клиент создаёт её один раз при регистрации и передаёт серверу, который
// отдаёт её всем клиентам владельца при входе.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать соль: %w", err)
	}

	return salt, nil
}

// Iterations возвращает число итераций PBKDF2, с которым выведен ключ.
func (k *Key) Iterations() int {
	return int(k.iterations)
}

// Encrypt шифрует plaintext со случайным nonce и возвращает blob в формате
// пакета. Каждый вызов даёт новый результат даже для одинаковых данных.
func (k *Key) Encrypt(plaintext []byte) ([]byte, error) {
	out := make([]byte, headerSize, headerSize+nonceSize+len(plaintext)+tagSize)
	out[0] = FormatVersion
	binary.BigEndian.PutUint32(out[1:headerSize], k.iterations)

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать nonce: %w", err)
	}
	out = append(out, nonce...)

	return k.aead.Seal(out, nonce, plaintext, out[:headerSize]), nil
}

// Decrypt расшифровывает blob, созданный Encrypt. Возвращает ErrFormat для
// blob неизвестного формата и ErrDecrypt при неверном ключе или повреждении.
// Число итераций в blob должно совпадать с числом итераций ключа: ключ для
// другого числа итераций получают через IterationsOf и DeriveKey.
func (k *Key) Decrypt(blob []byte) ([]byte, error) {
	iterations, err := IterationsOf(blob)
	if err != nil {
		return nil, err
	}
	if uint32(iterations) != k.iterations {
		return nil, fmt.Errorf("%w: blob создан с %d итерациями, ключ выведен с %d",
			ErrFormat, iterations, k.iterations)
	}

	nonce := blob[headerSize : headerSize+nonceSize]
	sealed := blob[headerSize+nonceSize:]

	plaintext, err := k.aead.Open(nil, nonce, sealed, blob[:headerSize])
	if err != nil {
		return nil, ErrDecrypt
	}

	return plaintext, nil
}

// IterationsOf возвращает число итераций PBKDF2, записанное в заголовке blob.
// Не проверяет подлинность blob: используется, чтобы выбрать ключ для
// расшифровки. Возвращает ErrFormat для blob неизвестной версии, слишком
// короткого или с недопустимым числом итераций.
func IterationsOf(blob []byte) (int, error) {
	if len(blob) < Overhead {
		return 0, fmt.Errorf("%w: слишком короткие данные", ErrFormat)
	}
	if blob[0] != FormatVersion {
		return 0, fmt.Errorf("%w: версия %d", ErrFormat, blob[0])
	}

	iterations := binary.BigEndian.Uint32(blob[1:headerSize])
	if iterations < MinIterations || iterations > MaxIterations {
		return 0, fmt.Errorf("%w: недопустимое число итераций", ErrFormat)
	}

	return int(iterations), nil
}
