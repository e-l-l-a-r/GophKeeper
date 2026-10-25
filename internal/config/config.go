// Package config реализует чтение настроек приложений из файла в формате JSON
// и разрешение приоритета источников настроек: переменная окружения важнее
// флага командной строки, флаг важнее файла конфигурации, файл важнее значения
// по умолчанию.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Duration - интервал времени из файла конфигурации. В JSON он может быть
// задан строкой в формате time.ParseDuration ("1s", "300ms") или числом секунд.
type Duration time.Duration

// UnmarshalJSON разбирает интервал времени из строки или из числа секунд.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("некорректный интервал: %w", err)
	}

	switch value := raw.(type) {
	case string:
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("некорректный интервал %q: %w", value, err)
		}
		*d = Duration(parsed)
	case float64:
		*d = Duration(time.Duration(value * float64(time.Second)))
	default:
		return fmt.Errorf("некорректный тип интервала: %T", raw)
	}

	return nil
}

// Std возвращает интервал в виде time.Duration.
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

// Load читает файл конфигурации по пути path в структуру dst. Если path пуст,
// файл не читается и dst остаётся незаполненным.
func Load(path string, dst any) error {
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("не удалось прочитать файл конфигурации %q: %w", path, err)
	}

	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("не удалось разобрать файл конфигурации %q: %w", path, err)
	}

	return nil
}

// ResolveString выбирает значение строкового параметра по приоритету
// источников. Пустое envValue считается незаданным, flagChanged сообщает, был
// ли флаг указан в командной строке, flagValue содержит значение флага или его
// значение по умолчанию, fileValue - значение из файла конфигурации.
func ResolveString(envValue string, flagChanged bool, flagValue string, fileValue *string) string {
	if envValue != "" {
		return envValue
	}

	return resolve(flagChanged, flagValue, fileValue)
}

// ResolveBool выбирает значение логического параметра по приоритету источников.
// Нулевой указатель envValue означает, что переменная окружения не задана.
func ResolveBool(envValue *bool, flagChanged bool, flagValue bool, fileValue *bool) bool {
	if envValue != nil {
		return *envValue
	}

	return resolve(flagChanged, flagValue, fileValue)
}

// ResolveDuration выбирает значение интервала по приоритету источников.
// Нулевой указатель envValue означает, что переменная окружения не задана.
func ResolveDuration(envValue *time.Duration, flagChanged bool, flagValue time.Duration, fileValue *Duration) time.Duration {
	if envValue != nil {
		return *envValue
	}
	if flagChanged {
		return flagValue
	}
	if fileValue != nil {
		return fileValue.Std()
	}

	return flagValue
}

// resolve выбирает значение из флага, файла или значения по умолчанию для
// случая, когда переменная окружения не задана.
func resolve[T any](flagChanged bool, flagValue T, fileValue *T) T {
	if flagChanged {
		return flagValue
	}
	if fileValue != nil {
		return *fileValue
	}

	return flagValue
}
