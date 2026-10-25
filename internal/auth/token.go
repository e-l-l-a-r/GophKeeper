package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	// MinTokenKeySize - минимальная длина ключа подписи токенов в байтах.
	MinTokenKeySize = 32

	// payloadSize - размер полезной нагрузки токена: идентификатор пользователя
	// (8 байт) и момент истечения в секундах Unix (8 байт).
	payloadSize = 16
	// tokenSize - размер токена до кодирования: нагрузка и подпись HMAC-SHA256.
	tokenSize = payloadSize + sha256.Size
)

var (
	// ErrInvalidToken возвращается, если токен повреждён, подпись неверна или
	// токен выпущен с другим ключом.
	ErrInvalidToken = errors.New("недействительный токен")
	// ErrExpiredToken возвращается, если срок действия токена истёк.
	ErrExpiredToken = errors.New("срок действия токена истёк")
)

// TokenManager выпускает и проверяет токены доступа. Токен состоит из
// идентификатора пользователя, момента истечения и подписи HMAC-SHA256 и
// кодируется в base64url без заполнения.
type TokenManager struct {
	now func() time.Time
	key []byte
	ttl time.Duration
}

// NewTokenManager создаёт менеджер токенов с ключом подписи key (не короче
// MinTokenKeySize байт) и сроком действия токена ttl.
func NewTokenManager(key []byte, ttl time.Duration) (*TokenManager, error) {
	return NewTokenManagerWithClock(key, ttl, time.Now)
}

// NewTokenManagerWithClock создаёт менеджер токенов с заданным источником
// времени now. Подмена часов позволяет проверять истечение токенов в тестах.
func NewTokenManagerWithClock(key []byte, ttl time.Duration, now func() time.Time) (*TokenManager, error) {
	if len(key) < MinTokenKeySize {
		return nil, fmt.Errorf("ключ подписи токенов короче %d байт", MinTokenKeySize)
	}
	if ttl <= 0 {
		return nil, errors.New("срок действия токена должен быть положительным")
	}

	return &TokenManager{key: append([]byte(nil), key...), ttl: ttl, now: now}, nil
}

// Issue выпускает токен для пользователя userID и возвращает его вместе с
// моментом истечения (с точностью до секунды).
func (m *TokenManager) Issue(userID int64) (string, time.Time) {
	expiresAt := m.now().Add(m.ttl).Unix()

	raw := make([]byte, tokenSize)
	binary.BigEndian.PutUint64(raw[0:8], uint64(userID))
	binary.BigEndian.PutUint64(raw[8:payloadSize], uint64(expiresAt))
	copy(raw[payloadSize:], m.sign(raw[:payloadSize]))

	return base64.RawURLEncoding.EncodeToString(raw), time.Unix(expiresAt, 0).UTC()
}

// Parse проверяет токен и возвращает идентификатор пользователя. Возвращает
// ErrInvalidToken для повреждённого или подделанного токена и ErrExpiredToken
// для токена с истёкшим сроком действия.
func (m *TokenManager) Parse(token string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != tokenSize {
		return 0, ErrInvalidToken
	}

	if !hmac.Equal(raw[payloadSize:], m.sign(raw[:payloadSize])) {
		return 0, ErrInvalidToken
	}

	userID := int64(binary.BigEndian.Uint64(raw[0:8]))
	expiresAt := int64(binary.BigEndian.Uint64(raw[8:payloadSize]))

	if userID <= 0 {
		return 0, ErrInvalidToken
	}
	if m.now().Unix() >= expiresAt {
		return 0, ErrExpiredToken
	}

	return userID, nil
}

// sign возвращает подпись HMAC-SHA256 полезной нагрузки токена.
func (m *TokenManager) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, m.key)
	mac.Write(payload)

	return mac.Sum(nil)
}
