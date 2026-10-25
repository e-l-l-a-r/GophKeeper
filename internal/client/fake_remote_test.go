package client

import (
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/e-l-l-a-r/gophkeeper/internal/auth"
	"github.com/e-l-l-a-r/gophkeeper/internal/logger"
	"github.com/e-l-l-a-r/gophkeeper/internal/model"
	pb "github.com/e-l-l-a-r/gophkeeper/internal/proto"
	"github.com/e-l-l-a-r/gophkeeper/internal/service"
	"github.com/e-l-l-a-r/gophkeeper/internal/storage"
)

// serverSide - общий «сервер» для нескольких клиентов в тестах: настоящий
// SecretsService поверх хранилища в памяти. Благодаря этому тесты проверяют
// реальные коды ошибок и дельту синхронизации, а не предположения о них.
type serverSide struct {
	svc *service.SecretsService
}

func newServerSide(t *testing.T) *serverSide {
	t.Helper()

	return &serverSide{svc: service.NewSecretsService(storage.NewMemory(), logger.Nop())}
}

// remote возвращает Remote от имени пользователя userID.
func (s *serverSide) remote(userID int64) *fakeRemote {
	return &fakeRemote{svc: s.svc, userID: userID}
}

// fakeRemote - реализация Remote поверх SecretsService без сети. Хуки
// позволяют имитировать сбои и гонки.
type fakeRemote struct {
	svc *service.SecretsService
	// beforeCall вызывается перед каждой операцией; ненулевая ошибка
	// возвращается вместо выполнения операции.
	beforeCall func(op string) error
	// afterCall вызывается после успешной операции на сервере; ненулевая ошибка
	// возвращается вместо результата (ответ «потерялся», а изменение на сервере осталось).
	afterCall func(op string) error
	calls     []string
	userID    int64
	mu        sync.Mutex
}

var _ Remote = (*fakeRemote)(nil)

func (f *fakeRemote) ctx(ctx context.Context) context.Context {
	return auth.ContextWithUserID(ctx, f.userID)
}

// enter фиксирует вызов и применяет хук beforeCall.
func (f *fakeRemote) enter(op string) error {
	f.mu.Lock()
	f.calls = append(f.calls, op)
	hook := f.beforeCall
	f.mu.Unlock()

	if hook != nil {
		return hook(op)
	}

	return nil
}

// leave применяет хук afterCall.
func (f *fakeRemote) leave(op string) error {
	f.mu.Lock()
	hook := f.afterCall
	f.mu.Unlock()

	if hook != nil {
		return hook(op)
	}

	return nil
}

// callLog возвращает список выполненных операций.
func (f *fakeRemote) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.calls...)
}

func (f *fakeRemote) Create(ctx context.Context, id string, kind model.Kind, payload []byte) (Secret, error) {
	if err := f.enter("create"); err != nil {
		return Secret{}, err
	}

	resp, err := f.svc.Create(f.ctx(ctx), &pb.CreateSecretRequest{Id: id, Type: pb.SecretType(kind), EncryptedPayload: payload})
	if err != nil {
		return Secret{}, mapError(err)
	}
	if err := f.leave("create"); err != nil {
		return Secret{}, err
	}

	return secretFromProto(resp)
}

func (f *fakeRemote) Get(ctx context.Context, id string) (Secret, error) {
	if err := f.enter("get"); err != nil {
		return Secret{}, err
	}

	resp, err := f.svc.Get(f.ctx(ctx), &pb.GetSecretRequest{Id: id})
	if err != nil {
		return Secret{}, mapError(err)
	}

	return secretFromProto(resp)
}

func (f *fakeRemote) Update(ctx context.Context, id string, kind model.Kind, payload []byte, version int64) (Secret, error) {
	if err := f.enter("update"); err != nil {
		return Secret{}, err
	}

	resp, err := f.svc.Update(f.ctx(ctx), &pb.UpdateSecretRequest{
		Id: id, Type: pb.SecretType(kind), EncryptedPayload: payload, ExpectedVersion: version,
	})
	if err != nil {
		return Secret{}, mapError(err)
	}
	if err := f.leave("update"); err != nil {
		return Secret{}, err
	}

	return secretFromProto(resp)
}

func (f *fakeRemote) Delete(ctx context.Context, id string, version int64) error {
	if err := f.enter("delete"); err != nil {
		return err
	}

	if _, err := f.svc.Delete(f.ctx(ctx), &pb.DeleteSecretRequest{Id: id, ExpectedVersion: version}); err != nil {
		return mapError(err)
	}

	return f.leave("delete")
}

func (f *fakeRemote) Sync(ctx context.Context, known []Known) ([]Secret, []string, error) {
	if err := f.enter("sync"); err != nil {
		return nil, nil, err
	}

	req := &pb.SyncRequest{}
	for _, k := range known {
		req.Known = append(req.Known, &pb.SecretVersion{Id: k.ID, Version: k.Version})
	}

	resp, err := f.svc.Sync(f.ctx(ctx), req)
	if err != nil {
		return nil, nil, mapError(err)
	}

	changed := make([]Secret, 0, len(resp.GetChanged()))
	for _, s := range resp.GetChanged() {
		secret, convErr := secretFromProto(s)
		if convErr != nil {
			return nil, nil, convErr
		}
		changed = append(changed, secret)
	}

	return changed, resp.GetDeletedIds(), nil
}

// errNetwork - ошибка, которой имитируется потеря связи.
var errNetwork = errors.New("обрыв связи")

// failOn возвращает хук, который отдаёт ошибку err на операции op.
func failOn(op string, err error) func(string) error {
	return func(got string) error {
		if got == op {
			return err
		}

		return nil
	}
}

// failOnce возвращает хук, который отдаёт ошибку err при первом вызове операции op.
func failOnce(op string, err error) func(string) error {
	var once sync.Once

	return func(got string) error {
		if got != op {
			return nil
		}

		var failed error

		once.Do(func() { failed = err })

		return failed
	}
}

func TestFakeRemote_ReturnsRealServerCodes(t *testing.T) {
	// Страховка от расхождения fake и сервера: коды ошибок настоящего сервиса
	// должны преобразовываться в ожидаемые ошибки пакета.
	remote := newServerSide(t).remote(1)
	ctx := context.Background()

	_, err := remote.Get(ctx, "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ожидалась ErrNotFound, получено %v", err)
	}

	_, err = remote.Create(ctx, "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11", model.KindText, []byte("x"))
	if err != nil {
		t.Fatalf("создание: %v", err)
	}

	_, err = remote.Create(ctx, "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11", model.KindText, []byte("x"))
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("ожидалась ErrAlreadyExists, получено %v", err)
	}

	_, err = remote.Update(ctx, "0b9d0a43-6a2f-4c3c-9d57-6a1b3f6a8b11", model.KindText, []byte("y"), 9)
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("ожидалась ErrVersionConflict, получено %v", err)
	}

	if got := status.Code(errors.New("не gRPC")); got != codes.Unknown {
		t.Fatalf("код не-gRPC ошибки: %v", got)
	}
}
