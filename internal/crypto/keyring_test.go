package crypto

import (
	"bytes"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyring(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		salt       []byte
		iterations int
		wantErr    bool
	}{
		{name: "корректные параметры", password: "master", salt: testSalt, iterations: 10},
		{name: "пустой пароль", salt: testSalt, iterations: 10, wantErr: true},
		{name: "короткая соль", password: "master", salt: []byte{1}, iterations: 10, wantErr: true},
		{name: "нулевые итерации", password: "master", salt: testSalt, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewKeyring(tt.password, tt.salt, tt.iterations)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, r)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, r)
		})
	}
}

func TestKeyring_RoundTrip(t *testing.T) {
	r, err := NewKeyring("master", testSalt, 10)
	require.NoError(t, err)

	blob, err := r.Encrypt([]byte("секрет"))
	require.NoError(t, err)

	iterations, err := IterationsOf(blob)
	require.NoError(t, err)
	assert.Equal(t, 10, iterations)

	got, err := r.Decrypt(blob)
	require.NoError(t, err)
	assert.Equal(t, []byte("секрет"), got)
}

// TestKeyring_ReadsBlobsWithOtherIterations моделирует повышение числа
// итераций: данные, зашифрованные со старым значением, остаются читаемыми.
func TestKeyring_ReadsBlobsWithOtherIterations(t *testing.T) {
	old, err := NewKeyring("master", testSalt, 5)
	require.NoError(t, err)
	oldBlob, err := old.Encrypt([]byte("старая запись"))
	require.NoError(t, err)

	upgraded, err := NewKeyring("master", testSalt, 12)
	require.NoError(t, err)
	newBlob, err := upgraded.Encrypt([]byte("новая запись"))
	require.NoError(t, err)

	got, err := upgraded.Decrypt(oldBlob)
	require.NoError(t, err)
	assert.Equal(t, []byte("старая запись"), got)

	got, err = upgraded.Decrypt(newBlob)
	require.NoError(t, err)
	assert.Equal(t, []byte("новая запись"), got)

	newIterations, err := IterationsOf(newBlob)
	require.NoError(t, err)
	assert.Equal(t, 12, newIterations, "новые данные шифруются текущим числом итераций")
}

func TestKeyring_Decrypt_Errors(t *testing.T) {
	r, err := NewKeyring("master", testSalt, 10)
	require.NoError(t, err)

	blob, err := r.Encrypt([]byte("секрет"))
	require.NoError(t, err)

	t.Run("неверный мастер-пароль", func(t *testing.T) {
		other, err := NewKeyring("другой", testSalt, 10)
		require.NoError(t, err)

		_, err = other.Decrypt(blob)
		require.ErrorIs(t, err, ErrDecrypt)
	})

	t.Run("повреждённые данные", func(t *testing.T) {
		broken := bytes.Clone(blob)
		broken[len(broken)-1] ^= 1

		_, err := r.Decrypt(broken)
		require.ErrorIs(t, err, ErrDecrypt)
	})

	t.Run("неизвестный формат", func(t *testing.T) {
		_, err := r.Decrypt([]byte{1, 2, 3})
		require.ErrorIs(t, err, ErrFormat)
	})
}

func TestKeyring_SaltIsCopied(t *testing.T) {
	salt := bytes.Clone(testSalt)

	r, err := NewKeyring("master", salt, 10)
	require.NoError(t, err)

	// Ключ для другого числа итераций выводится позже, из сохранённой соли.
	other, err := NewKeyring("master", testSalt, 7)
	require.NoError(t, err)
	blob, err := other.Encrypt([]byte("x"))
	require.NoError(t, err)

	salt[0] ^= 0xff

	got, err := r.Decrypt(blob)
	require.NoError(t, err, "изменение исходной соли не должно влиять на связку ключей")
	assert.Equal(t, []byte("x"), got)
}

func TestKeyring_Concurrent(t *testing.T) {
	r, err := NewKeyring("master", testSalt, 10)
	require.NoError(t, err)

	other, err := NewKeyring("master", testSalt, 3)
	require.NoError(t, err)
	foreign, err := other.Encrypt([]byte("чужое число итераций"))
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			blob, encErr := r.Encrypt([]byte("данные"))
			assert.NoError(t, encErr)

			got, decErr := r.Decrypt(blob)
			assert.NoError(t, decErr)
			assert.Equal(t, []byte("данные"), got)

			got, decErr = r.Decrypt(foreign)
			assert.NoError(t, decErr)
			assert.Equal(t, []byte("чужое число итераций"), got)
		}()
	}
	wg.Wait()
}
