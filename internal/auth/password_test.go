package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPasswordHasher(t *testing.T) {
	tests := []struct {
		name       string
		iterations int
		wantErr    bool
	}{
		{name: "положительное число итераций", iterations: 1},
		{name: "значение по умолчанию", iterations: DefaultPBKDF2Iterations},
		{name: "ноль итераций", iterations: 0, wantErr: true},
		{name: "отрицательное число итераций", iterations: -5, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewPasswordHasher(tt.iterations)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, h)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, h)
		})
	}
}

func TestPasswordHasher_HashAndVerify(t *testing.T) {
	h, err := NewPasswordHasher(10)
	require.NoError(t, err)

	hash, salt, err := h.Hash("correct horse")
	require.NoError(t, err)
	assert.Len(t, hash, hashSize)
	assert.Len(t, salt, saltSize)

	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{name: "верный пароль", password: "correct horse", want: true},
		{name: "неверный пароль", password: "wrong horse"},
		{name: "пустой пароль", password: ""},
		{name: "отличие регистром", password: "Correct horse"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := h.Verify(tt.password, hash, salt)
			require.NoError(t, err)
			assert.Equal(t, tt.want, ok)
		})
	}
}

func TestPasswordHasher_HashUsesRandomSalt(t *testing.T) {
	h, err := NewPasswordHasher(10)
	require.NoError(t, err)

	hash1, salt1, err := h.Hash("same password")
	require.NoError(t, err)
	hash2, salt2, err := h.Hash("same password")
	require.NoError(t, err)

	assert.NotEqual(t, salt1, salt2, "соль должна быть случайной")
	assert.NotEqual(t, hash1, hash2, "разные соли дают разные хеши")
}

func TestPasswordHasher_VerifyDependsOnSaltAndIterations(t *testing.T) {
	h, err := NewPasswordHasher(10)
	require.NoError(t, err)

	hash, salt, err := h.Hash("password")
	require.NoError(t, err)

	t.Run("другая соль", func(t *testing.T) {
		other := append([]byte(nil), salt...)
		other[0] ^= 0xff

		ok, err := h.Verify("password", hash, other)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("другое число итераций", func(t *testing.T) {
		other, err := NewPasswordHasher(11)
		require.NoError(t, err)

		ok, err := other.Verify("password", hash, salt)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("хеш неверной длины", func(t *testing.T) {
		ok, err := h.Verify("password", hash[:10], salt)
		require.NoError(t, err)
		assert.False(t, ok)
	})
}
