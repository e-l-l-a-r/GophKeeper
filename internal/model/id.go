package model

import (
	"crypto/rand"
	"fmt"
)

// NewID возвращает новый случайный идентификатор записи: UUID версии 4 в
// текстовом виде 8-4-4-4-12 строчными шестнадцатеричными цифрами. Сервер
// принимает именно такой формат.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("не удалось сгенерировать идентификатор: %w", err)
	}

	b[6] = b[6]&0x0f | 0x40 // версия 4
	b[8] = b[8]&0x3f | 0x80 // вариант RFC 4122

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
