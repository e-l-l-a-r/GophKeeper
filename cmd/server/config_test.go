package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTokenKey = "0123456789abcdef0123456789abcdef"

// serverEnvVars - все переменные окружения, которые читает сервер.
var serverEnvVars = []string{
	"ADDRESS", "LOG_LEVEL", "DATABASE_DSN", "TOKEN_KEY", "TOKEN_TTL",
	"TLS_CERT", "TLS_KEY", "INSECURE", "CONFIG",
}

// cleanEnv удаляет переменные окружения сервера и восстанавливает их по
// завершении теста. t.Setenv с пустым значением не подходит: переменная
// остаётся заданной.
func cleanEnv(t *testing.T) {
	t.Helper()

	for _, name := range serverEnvVars {
		t.Setenv(name, "") // регистрирует восстановление исходного значения
		require.NoError(t, os.Unsetenv(name))
	}
}

// writeConfigFile создаёт JSON-файл конфигурации и возвращает путь к нему.
func writeConfigFile(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	return path
}

// requiredEnv задаёт минимальный набор обязательных настроек.
func requiredEnv(t *testing.T) {
	t.Helper()

	t.Setenv("DATABASE_DSN", "postgres://localhost/db")
	t.Setenv("TOKEN_KEY", testTokenKey)
	t.Setenv("INSECURE", "true")
}

func TestGetConfig_Defaults(t *testing.T) {
	cleanEnv(t)
	requiredEnv(t)

	got, err := getConfig(nil, &bytes.Buffer{})
	require.NoError(t, err)

	assert.Equal(t, defaultAddress, got.Address)
	assert.Equal(t, defaultLogLevel, got.LogLevel)
	assert.Equal(t, defaultTokenTTL, got.TokenTTL)
	assert.Equal(t, "postgres://localhost/db", got.DatabaseDSN)
	assert.Equal(t, testTokenKey, got.TokenKey)
	assert.True(t, got.Insecure)
	assert.Empty(t, got.ConfigPath)
}

func TestGetConfig_Priority(t *testing.T) {
	file := writeConfigFile(t, `{
		"address": "file:1",
		"log_level": "warn",
		"token_ttl": "2h",
		"insecure": true,
		"database_dsn": "postgres://file",
		"token_key": "`+strings.Repeat("f", 40)+`"
	}`)

	tests := []struct {
		env      map[string]string
		name     string
		wantAddr string
		wantLog  string
		wantDSN  string
		args     []string
		wantTTL  time.Duration
	}{
		{
			name:     "значения из файла",
			args:     []string{"-c", file},
			wantAddr: "file:1", wantLog: "warn", wantTTL: 2 * time.Hour, wantDSN: "postgres://file",
		},
		{
			name:     "флаг важнее файла",
			args:     []string{"-c", file, "-a", "flag:2", "-l", "debug", "--token-ttl", "30m"},
			wantAddr: "flag:2", wantLog: "debug", wantTTL: 30 * time.Minute, wantDSN: "postgres://file",
		},
		{
			name:     "окружение важнее флага",
			args:     []string{"-c", file, "-a", "flag:2", "-l", "debug", "--token-ttl", "30m"},
			env:      map[string]string{"ADDRESS": "env:3", "LOG_LEVEL": "error", "TOKEN_TTL": "10m", "DATABASE_DSN": "postgres://env"},
			wantAddr: "env:3", wantLog: "error", wantTTL: 10 * time.Minute, wantDSN: "postgres://env",
		},
		{
			name:     "путь к файлу из окружения",
			env:      map[string]string{"CONFIG": file},
			wantAddr: "file:1", wantLog: "warn", wantTTL: 2 * time.Hour, wantDSN: "postgres://file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			got, err := getConfig(tt.args, &bytes.Buffer{})
			require.NoError(t, err)

			assert.Equal(t, tt.wantAddr, got.Address)
			assert.Equal(t, tt.wantLog, got.LogLevel)
			assert.Equal(t, tt.wantTTL, got.TokenTTL)
			assert.Equal(t, tt.wantDSN, got.DatabaseDSN)
		})
	}
}

func TestGetConfig_InsecureFromEnvFalseBeatsFile(t *testing.T) {
	cleanEnv(t)
	file := writeConfigFile(t, `{"insecure": true, "database_dsn": "d", "token_key": "`+testTokenKey+`"}`)
	t.Setenv("INSECURE", "false")

	_, err := getConfig([]string{"-c", file}, &bytes.Buffer{})
	require.Error(t, err, "INSECURE=false из окружения должен отключить значение из файла и потребовать TLS")
	assert.Contains(t, err.Error(), "TLS_CERT")
}

func TestGetConfig_SecretsHaveNoFlags(t *testing.T) {
	for _, flag := range []string{"--database-dsn", "--token-key", "--tls-cert", "--tls-key"} {
		t.Run(flag, func(t *testing.T) {
			cleanEnv(t)
			requiredEnv(t)

			_, err := getConfig([]string{flag, "x"}, &bytes.Buffer{})
			require.Error(t, err, "секреты не должны задаваться флагами")
			assert.Contains(t, err.Error(), "unknown flag")
		})
	}
}

func TestGetConfig_Validation(t *testing.T) {
	tests := []struct {
		env         map[string]string
		name        string
		wantMessage string
	}{
		{
			name:        "нет строки подключения",
			env:         map[string]string{"TOKEN_KEY": testTokenKey, "INSECURE": "true"},
			wantMessage: "DATABASE_DSN",
		},
		{
			name:        "нет ключа токенов",
			env:         map[string]string{"DATABASE_DSN": "d", "INSECURE": "true"},
			wantMessage: "TOKEN_KEY",
		},
		{
			name:        "короткий ключ токенов",
			env:         map[string]string{"DATABASE_DSN": "d", "TOKEN_KEY": "short", "INSECURE": "true"},
			wantMessage: "не короче 32",
		},
		{
			name:        "нет TLS без --insecure",
			env:         map[string]string{"DATABASE_DSN": "d", "TOKEN_KEY": testTokenKey},
			wantMessage: "TLS_CERT",
		},
		{
			name:        "только сертификат без ключа",
			env:         map[string]string{"DATABASE_DSN": "d", "TOKEN_KEY": testTokenKey, "TLS_CERT": "c.pem"},
			wantMessage: "TLS_KEY",
		},
		{
			name:        "отрицательный срок токена",
			env:         map[string]string{"DATABASE_DSN": "d", "TOKEN_KEY": testTokenKey, "INSECURE": "true", "TOKEN_TTL": "-1h"},
			wantMessage: "срок действия токена",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			_, err := getConfig(nil, &bytes.Buffer{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantMessage)
		})
	}
}

func TestGetConfig_AllMissingErrorsReportedTogether(t *testing.T) {
	cleanEnv(t)

	_, err := getConfig(nil, &bytes.Buffer{})
	require.Error(t, err)

	for _, want := range []string{"DATABASE_DSN", "TOKEN_KEY", "TLS_CERT"} {
		assert.Contains(t, err.Error(), want)
	}
}

func TestGetConfig_Errors(t *testing.T) {
	broken := writeConfigFile(t, `{`)

	tests := []struct {
		env  map[string]string
		name string
		args []string
	}{
		{name: "неизвестный флаг", args: []string{"--nope"}},
		{name: "файл не существует", args: []string{"-c", filepath.Join(t.TempDir(), "missing.json")}},
		{name: "файл с некорректным JSON", args: []string{"-c", broken}},
		{name: "некорректный срок токена в окружении", env: map[string]string{"TOKEN_TTL": "очень долго"}},
		{name: "некорректное булево в окружении", env: map[string]string{"INSECURE": "возможно"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanEnv(t)
			requiredEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			_, err := getConfig(tt.args, &bytes.Buffer{})
			require.Error(t, err)
		})
	}
}

func TestGetConfig_HelpPrintsUsageWithoutSecrets(t *testing.T) {
	cleanEnv(t)
	requiredEnv(t)

	var out bytes.Buffer
	_, err := getConfig([]string{"--help"}, &out)
	require.Error(t, err)

	assert.Contains(t, out.String(), "--address")
	assert.Contains(t, out.String(), "DATABASE_DSN")
	assert.NotContains(t, out.String(), testTokenKey, "справка не должна показывать значения секретов")
}
