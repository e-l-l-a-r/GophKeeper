package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testSalt = bytes.Repeat([]byte{0x5a}, 32)

// testKey выводит ключ с малым числом итераций, чтобы тесты шли быстро.
func testKey(t *testing.T, password string) *Key {
	t.Helper()

	k, err := DeriveKey(password, testSalt, 10)
	require.NoError(t, err)

	return k
}

func TestDeriveKey(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		salt       []byte
		iterations int
		wantErr    bool
	}{
		{name: "корректные параметры", password: "master", salt: testSalt, iterations: 10},
		{name: "минимальная соль", password: "master", salt: make([]byte, MinSaltSize), iterations: 1},
		{name: "максимум итераций", password: "master", salt: testSalt, iterations: 1, wantErr: false},
		{name: "пустой пароль", salt: testSalt, iterations: 10, wantErr: true},
		{name: "короткая соль", password: "master", salt: make([]byte, MinSaltSize-1), iterations: 10, wantErr: true},
		{name: "нет соли", password: "master", iterations: 10, wantErr: true},
		{name: "ноль итераций", password: "master", salt: testSalt, iterations: 0, wantErr: true},
		{name: "отрицательные итерации", password: "master", salt: testSalt, iterations: -1, wantErr: true},
		{name: "итераций больше максимума", password: "master", salt: testSalt, iterations: MaxIterations + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := DeriveKey(tt.password, tt.salt, tt.iterations)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, k)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.iterations, k.Iterations())
		})
	}
}

func TestKey_EncryptDecryptRoundTrip(t *testing.T) {
	k := testKey(t, "master")

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{name: "короткий текст", plaintext: []byte("секрет")},
		{name: "пустые данные", plaintext: []byte{}},
		{name: "все значения байта", plaintext: func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}

			return b
		}()},
		{name: "крупные данные", plaintext: bytes.Repeat([]byte("0123456789"), 100_000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob, err := k.Encrypt(tt.plaintext)
			require.NoError(t, err)
			assert.Len(t, blob, len(tt.plaintext)+Overhead)

			got, err := k.Decrypt(blob)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(tt.plaintext, got))
		})
	}
}

func TestKey_EncryptIsRandomized(t *testing.T) {
	k := testKey(t, "master")

	first, err := k.Encrypt([]byte("same data"))
	require.NoError(t, err)
	second, err := k.Encrypt([]byte("same data"))
	require.NoError(t, err)

	assert.NotEqual(t, first, second, "одинаковые данные должны шифроваться по-разному (случайный nonce)")
}

func TestKey_BlobDoesNotContainPlaintext(t *testing.T) {
	k := testKey(t, "master")

	blob, err := k.Encrypt([]byte("very-visible-plaintext"))
	require.NoError(t, err)

	assert.NotContains(t, string(blob), "very-visible-plaintext")
}

func TestKey_Decrypt_WrongPassword(t *testing.T) {
	blob, err := testKey(t, "правильный").Encrypt([]byte("секрет"))
	require.NoError(t, err)

	got, err := testKey(t, "неправильный").Decrypt(blob)
	require.ErrorIs(t, err, ErrDecrypt)
	assert.Nil(t, got)
}

func TestKey_Decrypt_WrongSalt(t *testing.T) {
	blob, err := testKey(t, "master").Encrypt([]byte("секрет"))
	require.NoError(t, err)

	other, err := DeriveKey("master", bytes.Repeat([]byte{0x01}, 32), 10)
	require.NoError(t, err)

	_, err = other.Decrypt(blob)
	require.ErrorIs(t, err, ErrDecrypt)
}

func TestKey_Decrypt_TamperedBlob(t *testing.T) {
	k := testKey(t, "master")

	blob, err := k.Encrypt([]byte("секрет"))
	require.NoError(t, err)

	tests := []struct {
		wantErr error
		name    string
		index   int
	}{
		{name: "версия формата", index: 0, wantErr: ErrFormat},
		{name: "число итераций (аутентифицируется)", index: 4, wantErr: ErrFormat},
		{name: "nonce", index: headerSize, wantErr: ErrDecrypt},
		{name: "шифротекст", index: headerSize + nonceSize, wantErr: ErrDecrypt},
		{name: "тег аутентификации", index: len(blob) - 1, wantErr: ErrDecrypt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := bytes.Clone(blob)
			tampered[tt.index] ^= 0x01

			got, err := k.Decrypt(tampered)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, got)
		})
	}
}

// TestKey_Decrypt_HeaderIsAuthenticated проверяет, что подмена числа
// итераций, согласованная с ключом, всё равно ломает расшифровку: заголовок
// входит в AAD.
func TestKey_Decrypt_HeaderIsAuthenticated(t *testing.T) {
	k10 := testKey(t, "master")
	k11, err := DeriveKey("master", testSalt, 11)
	require.NoError(t, err)

	blob, err := k10.Encrypt([]byte("секрет"))
	require.NoError(t, err)

	forged := bytes.Clone(blob)
	binary.BigEndian.PutUint32(forged[1:headerSize], 11)

	_, err = k11.Decrypt(forged)
	require.ErrorIs(t, err, ErrDecrypt, "заголовок подменён, но ключ подходит к подделанному числу итераций")
}

func TestKey_Decrypt_FormatErrors(t *testing.T) {
	k := testKey(t, "master")
	good, err := k.Encrypt([]byte("секрет"))
	require.NoError(t, err)

	withIterations := func(n uint32) []byte {
		b := bytes.Clone(good)
		binary.BigEndian.PutUint32(b[1:headerSize], n)

		return b
	}

	other, err := DeriveKey("master", testSalt, 11)
	require.NoError(t, err)
	otherBlob, err := other.Encrypt([]byte("x"))
	require.NoError(t, err)

	tests := []struct {
		name string
		blob []byte
	}{
		{name: "nil", blob: nil},
		{name: "пустой", blob: []byte{}},
		{name: "короче заголовка", blob: good[:headerSize-1]},
		{name: "короче минимального размера", blob: good[:Overhead-1]},
		{name: "неизвестная версия", blob: append([]byte{9}, good[1:]...)},
		{name: "нулевое число итераций", blob: withIterations(0)},
		{name: "итераций больше максимума", blob: withIterations(MaxIterations + 1)},
		{name: "blob с другим числом итераций", blob: otherBlob},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := k.Decrypt(tt.blob)
			require.ErrorIs(t, err, ErrFormat)
			assert.Nil(t, got)
		})
	}
}

func TestIterationsOf(t *testing.T) {
	k := testKey(t, "master")
	blob, err := k.Encrypt([]byte("x"))
	require.NoError(t, err)

	got, err := IterationsOf(blob)
	require.NoError(t, err)
	assert.Equal(t, 10, got)

	_, err = IterationsOf(blob[:3])
	require.ErrorIs(t, err, ErrFormat)
}

// TestFormatConformance расшифровывает blob стандартной библиотекой по
// описанию формата из документации пакета. Тест защищает формат: его
// изменение сделает старые записи нечитаемыми.
func TestFormatConformance(t *testing.T) {
	const password = "master"

	k := testKey(t, password)
	blob, err := k.Encrypt([]byte("проверка формата"))
	require.NoError(t, err)

	require.Equal(t, FormatVersion, blob[0])
	require.Equal(t, uint32(10), binary.BigEndian.Uint32(blob[1:5]))

	raw, err := pbkdf2.Key(sha256.New, password, testSalt, 10, 32)
	require.NoError(t, err)
	block, err := aes.NewCipher(raw)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := blob[5 : 5+12]
	plaintext, err := gcm.Open(nil, nonce, blob[5+12:], blob[:5])
	require.NoError(t, err)
	assert.Equal(t, "проверка формата", string(plaintext))
}

func TestConstants(t *testing.T) {
	assert.Equal(t, 600_000, DefaultIterations)
	assert.Equal(t, 33, Overhead)
	assert.Equal(t, 32, KeySize)
}

func TestKey_PasswordAndSaltAffectKey(t *testing.T) {
	a := testKey(t, "one")
	b := testKey(t, "two")

	blobA, err := a.Encrypt([]byte("x"))
	require.NoError(t, err)

	_, err = b.Decrypt(blobA)
	require.ErrorIs(t, err, ErrDecrypt)
}

func TestNewSalt(t *testing.T) {
	first, err := NewSalt()
	require.NoError(t, err)
	second, err := NewSalt()
	require.NoError(t, err)

	assert.Len(t, first, SaltSize)
	assert.GreaterOrEqual(t, len(first), MinSaltSize)
	assert.NotEqual(t, first, second, "соль должна быть случайной")

	_, err = DeriveKey("master", first, 1)
	require.NoError(t, err, "сгенерированная соль подходит для вывода ключа")
}
