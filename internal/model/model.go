// Package model описывает записи менеджера паролей GophKeeper: четыре типа
// записей (логин и пароль, текст, бинарные данные, банковская карта),
// произвольную текстовую метаинформацию к любой записи, проверку данных и
// сериализацию содержимого записи для шифрования.
//
// Тип и идентификатор записи хранятся на сервере открыто, а название,
// содержимое и метаинформация сериализуются в JSON (Entry.Marshal) и
// шифруются на клиенте.
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// MaxNameLen - максимальная длина названия записи в символах.
	MaxNameLen = 256

	// MaxBinarySize - максимальный размер бинарных данных записи в байтах
	// (7 МиБ). При сериализации в JSON данные кодируются в base64 и вырастают
	// на треть, поэтому лимит выбран так, чтобы зашифрованная запись с названием
	// максимальной длины укладывалась в лимит сервера (proto.MaxPayloadSize).
	MaxBinarySize = 7 << 20
)

// ErrInvalid - базовая ошибка некорректных данных записи. Подробности
// сообщения не содержат секретов (номера карты, паролей).
var ErrInvalid = errors.New("некорректная запись")

// Kind - тип записи. Числовые значения совпадают с pb.SecretType и
// сохраняются на сервере, поэтому менять их нельзя.
type Kind int16

const (
	// KindLoginPassword - пара логин/пароль.
	KindLoginPassword Kind = 1
	// KindText - произвольные текстовые данные.
	KindText Kind = 2
	// KindBinary - произвольные бинарные данные.
	KindBinary Kind = 3
	// KindCard - данные банковской карты.
	KindCard Kind = 4
)

// Valid сообщает, что k - один из известных типов записей.
func (k Kind) Valid() bool {
	return k >= KindLoginPassword && k <= KindCard
}

// String возвращает короткое имя типа: login, text, binary или card.
func (k Kind) String() string {
	switch k {
	case KindLoginPassword:
		return "login"
	case KindText:
		return "text"
	case KindBinary:
		return "binary"
	case KindCard:
		return "card"
	default:
		return fmt.Sprintf("unknown(%d)", int16(k))
	}
}

// ParseKind разбирает имя типа записи (login, text, binary или card) без учёта регистра.
func ParseKind(s string) (Kind, error) {
	for _, k := range []Kind{KindLoginPassword, KindText, KindBinary, KindCard} {
		if strings.EqualFold(strings.TrimSpace(s), k.String()) {
			return k, nil
		}
	}

	return 0, invalidf("неизвестный тип записи %q, допустимы: login, text, binary, card", s)
}

// Entry - запись менеджера паролей. Заполнять нужно поля, соответствующие
// типу Kind; остальные игнорируются при сериализации.
type Entry struct {
	// Card - данные банковской карты (KindCard).
	Card *Card
	// ID - идентификатор записи (UUID); задаётся при создании.
	ID string
	// Name - название записи, обязательно для всех типов.
	Name string
	// Meta - произвольная текстовая метаинформация (сайт, банк, коды активации
	// и прочее), необязательна для всех типов.
	Meta string
	// Login - логин (KindLoginPassword).
	Login string
	// Password - пароль (KindLoginPassword).
	Password string
	// Text - текст (KindText).
	Text string
	// Data - бинарные данные (KindBinary).
	Data []byte
	// Kind - тип записи.
	Kind Kind
}

// payload - зашифрованное содержимое записи в JSON. Тип и идентификатор в
// него не входят: они хранятся на сервере открыто.
type payload struct {
	Card     *Card  `json:"card,omitempty"`
	Name     string `json:"name"`
	Meta     string `json:"meta,omitempty"`
	Login    string `json:"login,omitempty"`
	Password string `json:"password,omitempty"`
	Text     string `json:"text,omitempty"`
	Data     []byte `json:"data,omitempty"`
}

// Validate проверяет запись: известный тип, название и поля, обязательные для
// этого типа. Возвращает ошибку, оборачивающую ErrInvalid.
func (e Entry) Validate() error {
	if !e.Kind.Valid() {
		return invalidf("неизвестный тип записи %d", int16(e.Kind))
	}

	name := strings.TrimSpace(e.Name)
	if name == "" {
		return invalidf("не указано название записи")
	}
	if utf8.RuneCountInString(name) > MaxNameLen {
		return invalidf("название записи длиннее %d символов", MaxNameLen)
	}

	switch e.Kind {
	case KindLoginPassword:
		if e.Login == "" || e.Password == "" {
			return invalidf("для записи типа login нужны логин и пароль")
		}
	case KindText:
		if e.Text == "" {
			return invalidf("для записи типа text нужен текст")
		}
	case KindBinary:
		if len(e.Data) == 0 {
			return invalidf("для записи типа binary нужны данные")
		}
		if len(e.Data) > MaxBinarySize {
			return invalidf("бинарные данные больше %d байт", MaxBinarySize)
		}
	case KindCard:
		if e.Card == nil {
			return invalidf("для записи типа card нужны данные карты")
		}
		if err := e.Card.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Marshal проверяет запись и сериализует её содержимое в JSON для шифрования.
// В результат попадают только поля, относящиеся к типу записи; данные карты
// приводятся к нормальному виду (номер из цифр, срок ММ/ГГ).
func (e Entry) Marshal() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}

	p := payload{Name: strings.TrimSpace(e.Name), Meta: e.Meta}

	switch e.Kind {
	case KindLoginPassword:
		p.Login, p.Password = e.Login, e.Password
	case KindText:
		p.Text = e.Text
	case KindBinary:
		p.Data = e.Data
	case KindCard:
		card := e.Card.normalized()
		p.Card = &card
	}

	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("не удалось сериализовать запись: %w", err)
	}

	return data, nil
}

// Unmarshal восстанавливает запись с идентификатором id и типом kind из JSON,
// полученного Entry.Marshal. Содержимое не проверяется на полноту: расшифрованные
// данные считаются доверенными, а неполную запись пользователь должен суметь прочитать.
func Unmarshal(id string, kind Kind, data []byte) (Entry, error) {
	if !kind.Valid() {
		return Entry{}, invalidf("неизвестный тип записи %d", int16(kind))
	}

	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		return Entry{}, fmt.Errorf("не удалось разобрать содержимое записи: %w", err)
	}

	return Entry{
		Card:     p.Card,
		ID:       id,
		Name:     p.Name,
		Meta:     p.Meta,
		Login:    p.Login,
		Password: p.Password,
		Text:     p.Text,
		Data:     p.Data,
		Kind:     kind,
	}, nil
}

// invalidf формирует ошибку, оборачивающую ErrInvalid, с пояснением.
func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
