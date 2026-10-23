package model

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCard_Validate(t *testing.T) {
	tests := []struct {
		name    string
		card    Card
		wantErr bool
	}{
		{name: "Visa", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "01/30", CVV: "123"}},
		{name: "Mastercard", card: Card{Number: "5555555555554444", Holder: "A", Expiry: "12/99", CVV: "999"}},
		{name: "American Express, 15 цифр и CVV из 4", card: Card{Number: "378282246310005", Holder: "A", Expiry: "06/27", CVV: "1234"}},
		{name: "номер с пробелами", card: Card{Number: "4111 1111 1111 1111", Holder: "A", Expiry: "01/30", CVV: "123"}},
		{name: "номер с дефисами", card: Card{Number: "4111-1111-1111-1111", Holder: "A", Expiry: "01/30", CVV: "123"}},
		{name: "год из четырёх цифр", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "01/2030", CVV: "123"}},
		{name: "месяц из одной цифры", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "1/30", CVV: "123"}},
		{name: "истёкший срок допустим", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "01/01", CVV: "123"}},

		{name: "пустая карта", card: Card{}, wantErr: true},
		{name: "ошибка контрольной суммы", card: Card{Number: "4111111111111112", Holder: "A", Expiry: "01/30", CVV: "123"}, wantErr: true},
		{name: "слишком короткий номер", card: Card{Number: "41111111111", Holder: "A", Expiry: "01/30", CVV: "123"}, wantErr: true},
		{name: "слишком длинный номер", card: Card{Number: "41111111111111111111", Holder: "A", Expiry: "01/30", CVV: "123"}, wantErr: true},
		{name: "буквы в номере", card: Card{Number: "4111a11111111111", Holder: "A", Expiry: "01/30", CVV: "123"}, wantErr: true},
		{name: "нет владельца", card: Card{Number: "4111111111111111", Holder: "  ", Expiry: "01/30", CVV: "123"}, wantErr: true},
		{name: "нет срока", card: Card{Number: "4111111111111111", Holder: "A", CVV: "123"}, wantErr: true},
		{name: "месяц 13", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "13/30", CVV: "123"}, wantErr: true},
		{name: "месяц 0", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "00/30", CVV: "123"}, wantErr: true},
		{name: "срок через дефис", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "01-30", CVV: "123"}, wantErr: true},
		{name: "год из трёх цифр", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "01/300", CVV: "123"}, wantErr: true},
		{name: "год вне 2000-2099", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "01/1999", CVV: "123"}, wantErr: true},
		{name: "знак в годе", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "01/+3", CVV: "123"}, wantErr: true},
		{name: "нет CVV", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "01/30"}, wantErr: true},
		{name: "CVV из двух цифр", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "01/30", CVV: "12"}, wantErr: true},
		{name: "CVV из пяти цифр", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "01/30", CVV: "12345"}, wantErr: true},
		{name: "буквы в CVV", card: Card{Number: "4111111111111111", Holder: "A", Expiry: "01/30", CVV: "12a"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.card.Validate()
			if tt.wantErr {
				require.ErrorIs(t, err, ErrInvalid)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestCard_ValidateErrorsDoNotLeakValues(t *testing.T) {
	card := Card{Number: "4111111111111112", Holder: "SECRET HOLDER", Expiry: "13/99", CVV: "987"}

	// Проверяем сообщение для каждого поля по очереди.
	cases := []Card{
		card,
		{Number: "4111111111111111", Holder: "", Expiry: card.Expiry, CVV: card.CVV},
		{Number: "4111111111111111", Holder: card.Holder, Expiry: card.Expiry, CVV: card.CVV},
		{Number: "4111111111111111", Holder: card.Holder, Expiry: "01/30", CVV: card.CVV + "99"},
	}

	for _, c := range cases {
		err := c.Validate()
		require.Error(t, err)

		for _, secret := range []string{"4111111111111112", "SECRET HOLDER", "987", "98799"} {
			assert.NotContains(t, err.Error(), secret)
		}
	}
}

func TestLuhnValid(t *testing.T) {
	tests := []struct {
		digits string
		valid  bool
	}{
		{digits: "4111111111111111", valid: true},
		{digits: "5555555555554444", valid: true},
		{digits: "378282246310005", valid: true},
		{digits: "6011111111111117", valid: true},
		{digits: "0000000000000000", valid: true},
		{digits: "4111111111111112"},
		{digits: "4111111111111121"},
		{digits: "1234567812345678"},
	}

	for _, tt := range tests {
		t.Run(tt.digits, func(t *testing.T) {
			assert.Equal(t, tt.valid, luhnValid(tt.digits))
		})
	}
}

func TestParseExpiry(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantMonth int
		wantYear  int
		wantOK    bool
	}{
		{name: "ММ/ГГ", input: "07/30", wantMonth: 7, wantYear: 30, wantOK: true},
		{name: "М/ГГ", input: "7/30", wantMonth: 7, wantYear: 30, wantOK: true},
		{name: "ММ/ГГГГ", input: "12/2031", wantMonth: 12, wantYear: 31, wantOK: true},
		{name: "пробелы по краям", input: " 01/30 ", wantMonth: 1, wantYear: 30, wantOK: true},
		{name: "граница 2000", input: "01/2000", wantMonth: 1, wantYear: 0, wantOK: true},
		{name: "граница 2099", input: "01/2099", wantMonth: 1, wantYear: 99, wantOK: true},
		{name: "пустая строка", input: ""},
		{name: "без разделителя", input: "0730"},
		{name: "два разделителя", input: "07/30/31"},
		{name: "месяц из трёх цифр", input: "007/30"},
		{name: "пустой месяц", input: "/30"},
		{name: "пустой год", input: "07/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			month, year, ok := parseExpiry(tt.input)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantMonth, month)
				assert.Equal(t, tt.wantYear, year)
			}
		})
	}
}

func TestAllDigits(t *testing.T) {
	assert.True(t, allDigits("0123456789"))
	assert.False(t, allDigits(""))
	assert.False(t, allDigits("12 3"))
	assert.False(t, allDigits("١٢٣"), "цифры других алфавитов не допускаются")
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewID(t *testing.T) {
	seen := make(map[string]struct{})

	for range 1000 {
		id, err := NewID()
		require.NoError(t, err)

		assert.Regexp(t, uuidPattern, id, "UUID версии 4 в формате, который принимает сервер")
		seen[id] = struct{}{}
	}

	assert.Len(t, seen, 1000, "идентификаторы не должны повторяться")
}
