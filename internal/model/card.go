package model

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// minCardNumberLen и maxCardNumberLen - границы длины номера карты в цифрах.
	minCardNumberLen = 12
	maxCardNumberLen = 19
)

// Card - данные банковской карты.
type Card struct {
	// Number - номер карты; пробелы и дефисы допускаются и отбрасываются.
	Number string `json:"number"`
	// Holder - имя владельца.
	Holder string `json:"holder"`
	// Expiry - срок действия в формате ММ/ГГ или ММ/ГГГГ.
	Expiry string `json:"expiry"`
	// CVV - код безопасности из 3 или 4 цифр.
	CVV string `json:"cvv"`
}

// Validate проверяет данные карты: номер (12-19 цифр, контрольная сумма по
// алгоритму Луна), владельца, срок действия и CVV. Сообщения об ошибках не
// содержат значений полей. Истёкший срок действия ошибкой не считается: так
// можно хранить архивные карты.
func (c Card) Validate() error {
	number := normalizeNumber(c.Number)
	if len(number) < minCardNumberLen || len(number) > maxCardNumberLen || !allDigits(number) {
		return invalidf("номер карты должен состоять из %d-%d цифр", minCardNumberLen, maxCardNumberLen)
	}
	if !luhnValid(number) {
		return invalidf("номер карты не проходит проверку контрольной суммы")
	}

	if strings.TrimSpace(c.Holder) == "" {
		return invalidf("не указан владелец карты")
	}

	if _, _, ok := parseExpiry(c.Expiry); !ok {
		return invalidf("срок действия карты должен быть в формате ММ/ГГ")
	}

	cvv := strings.TrimSpace(c.CVV)
	if (len(cvv) != 3 && len(cvv) != 4) || !allDigits(cvv) {
		return invalidf("CVV должен состоять из 3 или 4 цифр")
	}

	return nil
}

// normalized возвращает копию карты в нормальном виде: номер из одних цифр,
// срок ММ/ГГ, значения без пробелов по краям. Некорректные поля остаются как есть.
func (c Card) normalized() Card {
	out := Card{
		Number: normalizeNumber(c.Number),
		Holder: strings.TrimSpace(c.Holder),
		Expiry: strings.TrimSpace(c.Expiry),
		CVV:    strings.TrimSpace(c.CVV),
	}

	if month, year, ok := parseExpiry(c.Expiry); ok {
		out.Expiry = fmt.Sprintf("%02d/%02d", month, year)
	}

	return out
}

// normalizeNumber удаляет из номера карты пробелы и дефисы.
func normalizeNumber(number string) string {
	return strings.NewReplacer(" ", "", "-", "").Replace(number)
}

// parseExpiry разбирает срок действия ММ/ГГ или ММ/ГГГГ и возвращает месяц и
// год из двух цифр. Четырёхзначный год должен быть в диапазоне 2000-2099.
func parseExpiry(s string) (month, year int, ok bool) {
	parts := strings.Split(strings.TrimSpace(s), "/")
	if len(parts) != 2 {
		return 0, 0, false
	}

	monthPart, yearPart := parts[0], parts[1]
	if len(monthPart) < 1 || len(monthPart) > 2 || !allDigits(monthPart) || !allDigits(yearPart) {
		return 0, 0, false
	}

	month, _ = strconv.Atoi(monthPart)
	if month < 1 || month > 12 {
		return 0, 0, false
	}

	switch len(yearPart) {
	case 2:
		year, _ = strconv.Atoi(yearPart)
	case 4:
		full, _ := strconv.Atoi(yearPart)
		if full < 2000 || full > 2099 {
			return 0, 0, false
		}
		year = full % 100
	default:
		return 0, 0, false
	}

	return month, year, true
}

// luhnValid проверяет контрольную сумму строки цифр по алгоритму Луна.
func luhnValid(digits string) bool {
	sum := 0
	double := false

	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}

	return sum%10 == 0
}

// allDigits сообщает, что s непусто и состоит только из цифр ASCII.
func allDigits(s string) bool {
	if s == "" {
		return false
	}

	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}
