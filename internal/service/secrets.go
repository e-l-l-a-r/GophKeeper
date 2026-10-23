package service

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/e-l-l-a-r/gophkeeper/internal/auth"
	"github.com/e-l-l-a-r/gophkeeper/internal/logger"
	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
	"github.com/e-l-l-a-r/gophkeeper/internal/storage"
)

// uuidLen - длина текстового представления UUID (8-4-4-4-12).
const uuidLen = 36

// SecretsService реализует pb.SecretsServiceServer: создание, чтение,
// изменение, удаление и синхронизацию зашифрованных записей. Все методы
// работают только с записями пользователя, идентификатор которого положил в
// контекст интерцептор авторизации (auth.UnaryInterceptor).
type SecretsService struct {
	pb.UnimplementedSecretsServiceServer

	secrets storage.SecretStorage
	log     *logger.Logger
}

var _ pb.SecretsServiceServer = (*SecretsService)(nil)

// NewSecretsService создаёт сервис записей поверх хранилища secrets.
func NewSecretsService(secrets storage.SecretStorage, log *logger.Logger) *SecretsService {
	return &SecretsService{secrets: secrets, log: log}
}

// Create создаёт запись. Возвращает INVALID_ARGUMENT при некорректных данных
// и ALREADY_EXISTS, если запись с таким идентификатором уже есть.
func (s *SecretsService) Create(ctx context.Context, req *pb.CreateSecretRequest) (*pb.Secret, error) {
	userID, err := userFromContext(ctx)
	if err != nil {
		return nil, err
	}
	id, err := validateSecretID(req.GetId())
	if err != nil {
		return nil, err
	}
	if err = validateSecretType(req.GetType()); err != nil {
		return nil, err
	}
	if err = validatePayload(req.GetEncryptedPayload()); err != nil {
		return nil, err
	}

	created, err := s.secrets.CreateSecret(ctx, userID, storage.Secret{
		ID:               id,
		Type:             int16(req.GetType()),
		EncryptedPayload: req.GetEncryptedPayload(),
	})
	switch {
	case errors.Is(err, storage.ErrSecretExists):
		return nil, status.Error(codes.AlreadyExists, "запись с таким идентификатором уже существует")
	case err != nil:
		return nil, s.internal("создание записи", err)
	}

	return secretToProto(created), nil
}

// Get возвращает запись по идентификатору. Возвращает NOT_FOUND, если записи
// нет, она удалена или принадлежит другому пользователю.
func (s *SecretsService) Get(ctx context.Context, req *pb.GetSecretRequest) (*pb.Secret, error) {
	userID, err := userFromContext(ctx)
	if err != nil {
		return nil, err
	}
	id, err := validateSecretID(req.GetId())
	if err != nil {
		return nil, err
	}

	secret, err := s.secrets.GetSecret(ctx, userID, id)
	switch {
	case errors.Is(err, storage.ErrSecretNotFound):
		return nil, errSecretNotFound()
	case err != nil:
		return nil, s.internal("чтение записи", err)
	}

	return secretToProto(secret), nil
}

// Update заменяет содержимое записи. Возвращает ABORTED, если
// expected_version не совпадает с версией записи на сервере, и NOT_FOUND,
// если записи нет или она удалена.
func (s *SecretsService) Update(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.Secret, error) {
	userID, err := userFromContext(ctx)
	if err != nil {
		return nil, err
	}
	id, err := validateSecretID(req.GetId())
	if err != nil {
		return nil, err
	}
	if err = validateSecretType(req.GetType()); err != nil {
		return nil, err
	}
	if err = validatePayload(req.GetEncryptedPayload()); err != nil {
		return nil, err
	}
	if err = validateExpectedVersion(req.GetExpectedVersion()); err != nil {
		return nil, err
	}

	updated, err := s.secrets.UpdateSecret(ctx, userID, storage.Secret{
		ID:               id,
		Type:             int16(req.GetType()),
		EncryptedPayload: req.GetEncryptedPayload(),
	}, req.GetExpectedVersion())
	if err != nil {
		return nil, s.mutationError("изменение записи", err)
	}

	return secretToProto(updated), nil
}

// Delete помечает запись удалённой. Возвращает ABORTED, если expected_version
// не совпадает с версией записи на сервере, и NOT_FOUND, если записи нет или
// она уже удалена.
func (s *SecretsService) Delete(ctx context.Context, req *pb.DeleteSecretRequest) (*emptypb.Empty, error) {
	userID, err := userFromContext(ctx)
	if err != nil {
		return nil, err
	}
	id, err := validateSecretID(req.GetId())
	if err != nil {
		return nil, err
	}
	if err = validateExpectedVersion(req.GetExpectedVersion()); err != nil {
		return nil, err
	}

	if err = s.secrets.DeleteSecret(ctx, userID, id, req.GetExpectedVersion()); err != nil {
		return nil, s.mutationError("удаление записи", err)
	}

	return &emptypb.Empty{}, nil
}

// Sync возвращает дельту между состоянием клиента и сервера: записи, которых
// нет у клиента или версия которых на сервере новее, и идентификаторы
// известных клиенту записей, удалённых на сервере.
func (s *SecretsService) Sync(ctx context.Context, req *pb.SyncRequest) (*pb.SyncResponse, error) {
	userID, err := userFromContext(ctx)
	if err != nil {
		return nil, err
	}

	known, err := knownVersions(req.GetKnown())
	if err != nil {
		return nil, err
	}

	all, err := s.secrets.ListSecrets(ctx, userID)
	if err != nil {
		return nil, s.internal("получение списка записей", err)
	}

	changed, deleted := diffSecrets(all, known)

	resp := &pb.SyncResponse{
		Changed:    make([]*pb.Secret, 0, len(changed)),
		DeletedIds: deleted,
	}
	for _, secret := range changed {
		resp.Changed = append(resp.Changed, secretToProto(secret))
	}

	return resp, nil
}

// internal логирует внутреннюю ошибку и возвращает клиенту codes.Internal.
func (s *SecretsService) internal(action string, err error) error {
	return internalError(s.log, "secrets", action, err)
}

// mutationError переводит ошибку изменения или удаления записи в код gRPC.
func (s *SecretsService) mutationError(action string, err error) error {
	switch {
	case errors.Is(err, storage.ErrSecretNotFound):
		return errSecretNotFound()
	case errors.Is(err, storage.ErrVersionConflict):
		return status.Error(codes.Aborted, "версия записи изменилась: выполните синхронизацию")
	default:
		return s.internal(action, err)
	}
}

// errSecretNotFound возвращает ошибку «запись не найдена». Сообщение одинаково
// для отсутствующей, удалённой и чужой записи.
func errSecretNotFound() error {
	return status.Error(codes.NotFound, "запись не найдена")
}

// diffSecrets сравнивает записи сервера с версиями, известными клиенту (known:
// идентификатор -> версия), и возвращает записи, которые клиенту нужно
// получить (changed), и идентификаторы известных ему записей, удалённых на
// сервере (deleted). Порядок результатов сохраняет порядок server.
//
// Запись, которую клиент знает с версией выше серверной, не отправляется:
// сервер её не перезаписывает, конфликт разрешится при следующем изменении
// через проверку expected_version.
func diffSecrets(server []storage.Secret, known map[string]int64) (changed []storage.Secret, deleted []string) {
	for _, secret := range server {
		version, isKnown := known[secret.ID]

		switch {
		case secret.Deleted:
			if isKnown {
				deleted = append(deleted, secret.ID)
			}
		case !isKnown || secret.Version > version:
			changed = append(changed, secret)
		}
	}

	return changed, deleted
}

// knownVersions преобразует список пар идентификатор/версия из запроса в
// таблицу, проверяя каждую пару. Повтор идентификатора считается ошибкой.
func knownVersions(pairs []*pb.SecretVersion) (map[string]int64, error) {
	known := make(map[string]int64, len(pairs))

	for _, pair := range pairs {
		id, err := validateSecretID(pair.GetId())
		if err != nil {
			return nil, err
		}
		if pair.GetVersion() < 1 {
			return nil, status.Error(codes.InvalidArgument, "версия известной записи должна быть положительной")
		}
		if _, dup := known[id]; dup {
			return nil, status.Errorf(codes.InvalidArgument, "идентификатор %s указан в known дважды", id)
		}
		known[id] = pair.GetVersion()
	}

	return known, nil
}

// secretToProto преобразует запись хранилища в сообщение протокола.
func secretToProto(secret storage.Secret) *pb.Secret {
	return &pb.Secret{
		Id:               secret.ID,
		Type:             pb.SecretType(secret.Type),
		EncryptedPayload: secret.EncryptedPayload,
		Version:          secret.Version,
		UpdatedAt:        timestamppb.New(secret.UpdatedAt),
	}
}

// userFromContext возвращает идентификатор пользователя, положенный в
// контекст интерцептором авторизации. Без него (интерцептор не подключён или
// отклонил бы запрос) метод отвечает UNAUTHENTICATED.
func userFromContext(ctx context.Context) (int64, error) {
	userID, ok := auth.UserIDFromContext(ctx)
	if !ok {
		return 0, status.Error(codes.Unauthenticated, "пользователь не аутентифицирован")
	}

	return userID, nil
}

// validateSecretID проверяет, что id - UUID в формате 8-4-4-4-12, и
// возвращает его в нижнем регистре, чтобы любые хранилища считали записи
// «ABC...» и «abc...» одной и той же записью.
func validateSecretID(id string) (string, error) {
	if len(id) != uuidLen {
		return "", errInvalidSecretID()
	}

	for i := range len(id) {
		switch i {
		case 8, 13, 18, 23:
			if id[i] != '-' {
				return "", errInvalidSecretID()
			}
		default:
			if !isHexDigit(id[i]) {
				return "", errInvalidSecretID()
			}
		}
	}

	return strings.ToLower(id), nil
}

// errInvalidSecretID возвращает ошибку некорректного идентификатора записи.
func errInvalidSecretID() error {
	return status.Error(codes.InvalidArgument, "идентификатор записи должен быть UUID")
}

// isHexDigit сообщает, что c - шестнадцатеричная цифра.
func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// validateSecretType проверяет, что тип записи задан и известен.
func validateSecretType(t pb.SecretType) error {
	if t < pb.SecretType_SECRET_TYPE_LOGIN_PASSWORD || t > pb.SecretType_SECRET_TYPE_CARD {
		return status.Error(codes.InvalidArgument, "неизвестный тип записи")
	}

	return nil
}

// validatePayload проверяет размер зашифрованного содержимого записи.
// Пустое содержимое недопустимо: так живая запись всегда отличается от
// удалённой, у которой шифротекст очищен.
func validatePayload(payload []byte) error {
	switch {
	case len(payload) == 0:
		return status.Error(codes.InvalidArgument, "содержимое записи не может быть пустым")
	case len(payload) > pb.MaxPayloadSize:
		return status.Errorf(codes.InvalidArgument, "размер записи превышает %d байт", pb.MaxPayloadSize)
	}

	return nil
}

// validateExpectedVersion проверяет ожидаемую версию записи: версии
// начинаются с единицы.
func validateExpectedVersion(version int64) error {
	if version < 1 {
		return status.Error(codes.InvalidArgument, "ожидаемая версия записи должна быть положительной")
	}

	return nil
}
