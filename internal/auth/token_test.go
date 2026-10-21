package auth

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testKey  = bytes.Repeat([]byte{0x42}, MinTokenKeySize)
	testTime = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
)

// clock - управляемые часы для проверки истечения токенов.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newTestManager(t *testing.T, key []byte, ttl time.Duration, c *clock) *TokenManager {
	t.Helper()

	m, err := NewTokenManagerWithClock(key, ttl, c.Now)
	require.NoError(t, err)

	return m
}

func TestNewTokenManager(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		ttl     time.Duration
		wantErr bool
	}{
		{name: "корректные параметры", key: testKey, ttl: time.Hour},
		{name: "слишком короткий ключ", key: testKey[:MinTokenKeySize-1], ttl: time.Hour, wantErr: true},
		{name: "пустой ключ", ttl: time.Hour, wantErr: true},
		{name: "нулевой срок", key: testKey, wantErr: true},
		{name: "отрицательный срок", key: testKey, ttl: -time.Minute, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewTokenManager(tt.key, tt.ttl)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, m)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, m)
		})
	}
}

func TestTokenManager_IssueAndParse(t *testing.T) {
	c := &clock{now: testTime}
	m := newTestManager(t, testKey, 24*time.Hour, c)

	token, expiresAt := m.Issue(42)
	assert.Equal(t, testTime.Add(24*time.Hour), expiresAt)

	userID, err := m.Parse(token)
	require.NoError(t, err)
	assert.Equal(t, int64(42), userID)
}

func TestTokenManager_Expiration(t *testing.T) {
	c := &clock{now: testTime}
	m := newTestManager(t, testKey, time.Hour, c)
	token, _ := m.Issue(7)

	tests := []struct {
		wantErr error
		name    string
		offset  time.Duration
	}{
		{name: "сразу после выпуска", offset: 0},
		{name: "за секунду до истечения", offset: time.Hour - time.Second},
		{name: "в момент истечения", offset: time.Hour, wantErr: ErrExpiredToken},
		{name: "после истечения", offset: 2 * time.Hour, wantErr: ErrExpiredToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.now = testTime.Add(tt.offset)

			userID, err := m.Parse(token)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, int64(7), userID)
		})
	}
}

func TestTokenManager_ParseRejectsInvalid(t *testing.T) {
	c := &clock{now: testTime}
	m := newTestManager(t, testKey, time.Hour, c)

	good, _ := m.Issue(5)
	raw, err := base64.RawURLEncoding.DecodeString(good)
	require.NoError(t, err)

	tamper := func(index int) string {
		cp := append([]byte(nil), raw...)
		cp[index] ^= 0x01

		return base64.RawURLEncoding.EncodeToString(cp)
	}

	otherKey := bytes.Repeat([]byte{0x24}, MinTokenKeySize)
	foreign, _ := newTestManager(t, otherKey, time.Hour, c).Issue(5)

	tests := []struct {
		name  string
		token string
	}{
		{name: "пустая строка", token: ""},
		{name: "не base64", token: "!!!не токен!!!"},
		{name: "слишком короткий", token: base64.RawURLEncoding.EncodeToString(raw[:10])},
		{name: "слишком длинный", token: base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), raw...), 0))},
		{name: "изменён идентификатор пользователя", token: tamper(7)},
		{name: "изменён срок действия", token: tamper(15)},
		{name: "изменена подпись", token: tamper(len(raw) - 1)},
		{name: "выпущен другим ключом", token: foreign},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID, err := m.Parse(tt.token)
			require.ErrorIs(t, err, ErrInvalidToken)
			assert.Zero(t, userID)
		})
	}
}

func TestTokenManager_ParseRejectsNonPositiveUserID(t *testing.T) {
	c := &clock{now: testTime}
	m := newTestManager(t, testKey, time.Hour, c)

	for _, id := range []int64{0, -1} {
		token, _ := m.Issue(id)

		_, err := m.Parse(token)
		require.ErrorIs(t, err, ErrInvalidToken, "идентификатор %d", id)
	}
}

func TestTokenManager_KeyIsCopied(t *testing.T) {
	c := &clock{now: testTime}
	key := bytes.Repeat([]byte{0x11}, MinTokenKeySize)
	m := newTestManager(t, key, time.Hour, c)

	token, _ := m.Issue(1)
	key[0] ^= 0xff

	_, err := m.Parse(token)
	require.NoError(t, err, "изменение исходного среза не должно влиять на менеджер")
}
