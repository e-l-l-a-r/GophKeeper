package model

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validCard возвращает карту с общеизвестным тестовым номером Visa.
func validCard() *Card {
	return &Card{Number: "4111 1111 1111 1111", Holder: "IVAN IVANOV", Expiry: "7/2030", CVV: "123"}
}

func TestKind(t *testing.T) {
	tests := []struct {
		name  string
		str   string
		kind  Kind
		valid bool
	}{
		{name: "логин и пароль", kind: KindLoginPassword, str: "login", valid: true},
		{name: "текст", kind: KindText, str: "text", valid: true},
		{name: "бинарные данные", kind: KindBinary, str: "binary", valid: true},
		{name: "карта", kind: KindCard, str: "card", valid: true},
		{name: "ноль", kind: 0, str: "unknown(0)"},
		{name: "за границей", kind: 5, str: "unknown(5)"},
		{name: "отрицательный", kind: -1, str: "unknown(-1)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.kind.Valid())
			assert.Equal(t, tt.str, tt.kind.String())
		})
	}
}

// TestKindValuesMatchProtocol фиксирует числовые значения типов: они хранятся
// на сервере и совпадают с pb.SecretType.
func TestKindValuesMatchProtocol(t *testing.T) {
	assert.Equal(t, int16(1), int16(KindLoginPassword))
	assert.Equal(t, int16(2), int16(KindText))
	assert.Equal(t, int16(3), int16(KindBinary))
	assert.Equal(t, int16(4), int16(KindCard))
}

func TestParseKind(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Kind
		wantErr bool
	}{
		{name: "login", input: "login", want: KindLoginPassword},
		{name: "в верхнем регистре", input: "CARD", want: KindCard},
		{name: "с пробелами", input: "  text ", want: KindText},
		{name: "binary", input: "Binary", want: KindBinary},
		{name: "неизвестный", input: "note", wantErr: true},
		{name: "пустая строка", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKind(tt.input)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrInvalid)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEntry_Validate(t *testing.T) {
	tests := []struct {
		name    string
		entry   Entry
		wantErr bool
	}{
		{name: "логин и пароль", entry: Entry{Kind: KindLoginPassword, Name: "почта", Login: "me", Password: "pw"}},
		{name: "текст", entry: Entry{Kind: KindText, Name: "заметка", Text: "привет"}},
		{name: "бинарные данные", entry: Entry{Kind: KindBinary, Name: "файл", Data: []byte{0, 1, 2}}},
		{name: "карта", entry: Entry{Kind: KindCard, Name: "зарплатная", Card: validCard()}},
		{name: "метаинформация необязательна", entry: Entry{Kind: KindText, Name: "n", Text: "t", Meta: "сайт example.com"}},
		{name: "название максимальной длины", entry: Entry{Kind: KindText, Name: strings.Repeat("я", MaxNameLen), Text: "t"}},
		{name: "бинарные данные максимального размера", entry: Entry{Kind: KindBinary, Name: "n", Data: make([]byte, MaxBinarySize)}},

		{name: "тип не задан", entry: Entry{Name: "n", Text: "t"}, wantErr: true},
		{name: "неизвестный тип", entry: Entry{Kind: 9, Name: "n", Text: "t"}, wantErr: true},
		{name: "нет названия", entry: Entry{Kind: KindText, Text: "t"}, wantErr: true},
		{name: "название из пробелов", entry: Entry{Kind: KindText, Name: "  \t", Text: "t"}, wantErr: true},
		{name: "слишком длинное название", entry: Entry{Kind: KindText, Name: strings.Repeat("я", MaxNameLen+1), Text: "t"}, wantErr: true},
		{name: "нет логина", entry: Entry{Kind: KindLoginPassword, Name: "n", Password: "pw"}, wantErr: true},
		{name: "нет пароля", entry: Entry{Kind: KindLoginPassword, Name: "n", Login: "me"}, wantErr: true},
		{name: "нет текста", entry: Entry{Kind: KindText, Name: "n"}, wantErr: true},
		{name: "нет данных", entry: Entry{Kind: KindBinary, Name: "n"}, wantErr: true},
		{name: "бинарные данные больше максимума", entry: Entry{Kind: KindBinary, Name: "n", Data: make([]byte, MaxBinarySize+1)}, wantErr: true},
		{name: "нет карты", entry: Entry{Kind: KindCard, Name: "n"}, wantErr: true},
		{name: "некорректная карта", entry: Entry{Kind: KindCard, Name: "n", Card: &Card{Number: "1234"}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entry.Validate()
			if tt.wantErr {
				require.ErrorIs(t, err, ErrInvalid)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestEntry_MarshalUnmarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		entry Entry
	}{
		{
			name:  "логин и пароль",
			entry: Entry{Kind: KindLoginPassword, Name: "почта", Meta: "mail.example.com", Login: "me", Password: "p@ss \"quoted\" \n"},
		},
		{
			name:  "текст с юникодом",
			entry: Entry{Kind: KindText, Name: "заметка", Text: "строка 1\nстрока 2 😀"},
		},
		{
			name:  "бинарные данные со всеми байтами",
			entry: Entry{Kind: KindBinary, Name: "файл", Data: bytes.Repeat([]byte{0x00, 0xff, 0x10, 0x80}, 100)},
		},
		{
			name:  "карта",
			entry: Entry{Kind: KindCard, Name: "карта", Meta: "банк", Card: &Card{Number: "4111111111111111", Holder: "IVAN IVANOV", Expiry: "07/30", CVV: "123"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.entry.ID = "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11"

			data, err := tt.entry.Marshal()
			require.NoError(t, err)

			got, err := Unmarshal(tt.entry.ID, tt.entry.Kind, data)
			require.NoError(t, err)
			assert.Equal(t, tt.entry, got)
		})
	}
}

func TestEntry_Marshal_OnlyRelevantFields(t *testing.T) {
	entry := Entry{
		Kind: KindText, Name: "n", Text: "t",
		Login: "leaked-login", Password: "leaked-password", Data: []byte("leaked-data"), Card: validCard(),
	}

	data, err := entry.Marshal()
	require.NoError(t, err)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(data, &fields))
	assert.Equal(t, map[string]any{"name": "n", "text": "t"}, fields,
		"поля других типов не должны попадать в зашифрованное содержимое")
}

func TestEntry_Marshal_ContainsNoIDOrKind(t *testing.T) {
	data, err := Entry{ID: "secret-id", Kind: KindText, Name: "n", Text: "t"}.Marshal()
	require.NoError(t, err)

	assert.NotContains(t, string(data), "secret-id")
	assert.NotContains(t, string(data), "kind")
}

func TestEntry_Marshal_NormalizesCardAndName(t *testing.T) {
	entry := Entry{
		Kind: KindCard, Name: "  зарплатная  ",
		Card: &Card{Number: " 4111-1111 1111-1111 ", Holder: "  IVAN  ", Expiry: "7/2030", CVV: " 123 "},
	}

	data, err := entry.Marshal()
	require.NoError(t, err)

	got, err := Unmarshal("id", KindCard, data)
	require.NoError(t, err)

	assert.Equal(t, "зарплатная", got.Name)
	require.NotNil(t, got.Card)
	assert.Equal(t, Card{Number: "4111111111111111", Holder: "IVAN", Expiry: "07/30", CVV: "123"}, *got.Card)
	assert.Equal(t, " 4111-1111 1111-1111 ", entry.Card.Number, "исходная запись не изменяется")
}

func TestEntry_Marshal_RejectsInvalid(t *testing.T) {
	data, err := Entry{Kind: KindText, Name: "n"}.Marshal()
	require.ErrorIs(t, err, ErrInvalid)
	assert.Nil(t, data)
}

func TestEntry_MaxBinaryEntryFitsServerLimit(t *testing.T) {
	// Запись максимального размера с названием максимальной длины и
	// метаинформацией 64 КиБ должна укладываться в лимит сервера (10 МиБ)
	// с запасом на заголовок и тег шифрования.
	const serverPayloadLimit = 10 << 20

	entry := Entry{
		Kind: KindBinary, Name: strings.Repeat("я", MaxNameLen),
		Meta: strings.Repeat("м", 32<<10), Data: bytes.Repeat([]byte{0xff}, MaxBinarySize),
	}

	data, err := entry.Marshal()
	require.NoError(t, err)

	const encryptionOverhead = 1 + 4 + 12 + 16
	assert.Less(t, len(data)+encryptionOverhead, serverPayloadLimit)
}

func TestUnmarshal_Errors(t *testing.T) {
	tests := []struct {
		name string
		data string
		kind Kind
	}{
		{name: "некорректный JSON", data: `{`, kind: KindText},
		{name: "неверный тип данных поля", data: `{"name": 5}`, kind: KindText},
		{name: "неизвестный тип записи", data: `{"name": "n"}`, kind: 9},
		{name: "тип не задан", data: `{"name": "n"}`, kind: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Unmarshal("id", tt.kind, []byte(tt.data))
			require.Error(t, err)
		})
	}
}

func TestUnmarshal_ToleratesUnknownFieldsAndIncompleteEntries(t *testing.T) {
	got, err := Unmarshal("id", KindLoginPassword, []byte(`{"name":"n","from_future":1}`))
	require.NoError(t, err)

	assert.Equal(t, "n", got.Name)
	assert.Empty(t, got.Login, "неполную запись можно прочитать")
}
