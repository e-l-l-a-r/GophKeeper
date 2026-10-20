package proto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protolib "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// TestServiceContract фиксирует состав сервисов и методов: их переименование
// ломает совместимость клиентов и серверов разных версий.
func TestServiceContract(t *testing.T) {
	tests := []struct {
		name    string
		service string
		methods []string
	}{
		{
			name:    "аутентификация",
			service: "AuthService",
			methods: []string{"Register", "Login"},
		},
		{
			name:    "записи",
			service: "SecretsService",
			methods: []string{"Create", "Get", "Update", "Delete", "Sync"},
		},
	}

	services := File_gophkeeper_proto.Services()
	require.Equal(t, len(tests), services.Len())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := services.ByName(protoreflect.Name(tt.service))
			require.NotNil(t, svc)
			require.Equal(t, len(tt.methods), svc.Methods().Len())

			for _, m := range tt.methods {
				assert.NotNil(t, svc.Methods().ByName(protoreflect.Name(m)), "метод %s", m)
			}
		})
	}
}

// TestSecretTypeValues фиксирует числовые значения типов записей, которые
// сохраняются в базе данных.
func TestSecretTypeValues(t *testing.T) {
	tests := []struct {
		name string
		got  SecretType
		want int32
	}{
		{name: "не задан", got: SecretType_SECRET_TYPE_UNSPECIFIED, want: 0},
		{name: "логин и пароль", got: SecretType_SECRET_TYPE_LOGIN_PASSWORD, want: 1},
		{name: "текст", got: SecretType_SECRET_TYPE_TEXT, want: 2},
		{name: "бинарные данные", got: SecretType_SECRET_TYPE_BINARY, want: 3},
		{name: "карта", got: SecretType_SECRET_TYPE_CARD, want: 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, int32(tt.got))
		})
	}
}

// TestSyncResponseRoundTrip проверяет сериализацию дельты синхронизации.
func TestSyncResponseRoundTrip(t *testing.T) {
	in := &SyncResponse{
		Changed: []*Secret{{
			Id:               "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11",
			Type:             SecretType_SECRET_TYPE_CARD,
			EncryptedPayload: []byte{0x01, 0x02, 0x03},
			Version:          3,
		}},
		DeletedIds: []string{"deleted-1"},
	}

	data, err := protolib.Marshal(in)
	require.NoError(t, err)

	var out SyncResponse
	require.NoError(t, protolib.Unmarshal(data, &out))
	assert.True(t, protolib.Equal(in, &out))
}
