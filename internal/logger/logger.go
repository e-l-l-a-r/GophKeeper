// Package logger предоставляет логгер приложения поверх zap и вспомогательные
// функции для вывода сведений о сборке. Глобального состояния пакет не
// содержит: логгер создаётся через New и передаётся потребителям как
// зависимость.
package logger

import (
	"fmt"
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// notAvailable - значение, которое выводится вместо незаданных сведений о сборке.
const notAvailable = "N/A"

// Logger - логгер приложения поверх zap.Logger.
type Logger struct {
	*zap.Logger
}

// New создаёт логгер с заданным уровнем логирования ("debug", "info", "warn",
// "error"; регистр не важен). Записи выводятся в консольном формате в stderr.
func New(level string) (*Logger, error) {
	lvl, err := zap.ParseAtomicLevel(level)
	if err != nil {
		return nil, fmt.Errorf("некорректный уровень логирования %q: %w", level, err)
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = lvl
	cfg.Encoding = "console"
	cfg.EncoderConfig.ConsoleSeparator = "\t| "
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	cfg.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	log, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("не удалось создать логгер: %w", err)
	}

	return &Logger{Logger: log}, nil
}

// Nop возвращает логгер, который отбрасывает все записи. Удобен в тестах и
// там, где логгер не настроен.
func Nop() *Logger {
	return &Logger{Logger: zap.NewNop()}
}

// PrintBuildInfo выводит в w версию, дату и коммит сборки. Незаданные
// (пустые) значения заменяются на "N/A".
func PrintBuildInfo(w io.Writer, version, date, commit string) error {
	_, err := fmt.Fprintf(w, "Build version: %s\nBuild date: %s\nBuild commit: %s\n",
		orNotAvailable(version), orNotAvailable(date), orNotAvailable(commit))
	if err != nil {
		return fmt.Errorf("не удалось вывести сведения о сборке: %w", err)
	}

	return nil
}

// orNotAvailable возвращает value или "N/A", если value пусто.
func orNotAvailable(value string) string {
	if value == "" {
		return notAvailable
	}

	return value
}
