package config

// Server - настройки сервера, прочитанные из файла конфигурации. Нулевой
// указатель означает, что параметр в файле не задан.
//
// Файл содержит секреты (database_dsn, token_key): ограничьте права доступа к
// нему (например, chmod 600) и не добавляйте его в систему контроля версий.
type Server struct {
	// Address - адрес и порт gRPC-сервера.
	Address *string `json:"address"`
	// LogLevel - уровень логирования: debug, info, warn или error.
	LogLevel *string `json:"log_level"`
	// DatabaseDSN - строка подключения к PostgreSQL.
	DatabaseDSN *string `json:"database_dsn"`
	// TokenKey - ключ подписи токенов доступа, не короче 32 символов.
	TokenKey *string `json:"token_key"`
	// TokenTTL - срок действия токена: строка time.ParseDuration или число секунд.
	TokenTTL *Duration `json:"token_ttl"`
	// TLSCert - путь к файлу сертификата TLS в формате PEM.
	TLSCert *string `json:"tls_cert"`
	// TLSKey - путь к файлу закрытого ключа TLS в формате PEM.
	TLSKey *string `json:"tls_key"`
	// Insecure отключает TLS; предназначено только для локальной отладки.
	Insecure *bool `json:"insecure"`
}
