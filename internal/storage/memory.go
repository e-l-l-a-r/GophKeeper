package storage

import (
	"context"
	"slices"
	"sync"
	"time"
)

// Memory - потокобезопасное хранилище пользователей и записей в памяти.
// Реализует UserStorage и SecretStorage с тем же поведением, что и Postgres,
// и предназначено для тестов. Данные теряются при завершении процесса.
type Memory struct {
	users   map[string]User
	secrets map[int64]map[string]Secret
	now     func() time.Time
	// mu защищает все поля ниже и мапы выше.
	mu         sync.Mutex
	nextUserID int64
}

var (
	_ UserStorage   = (*Memory)(nil)
	_ SecretStorage = (*Memory)(nil)
)

// NewMemory создаёт пустое хранилище в памяти, которое берёт время из time.Now.
func NewMemory() *Memory {
	return NewMemoryWithClock(time.Now)
}

// NewMemoryWithClock создаёт пустое хранилище в памяти с заданным источником
// времени now. Подмена часов делает время изменения записей предсказуемым в тестах.
func NewMemoryWithClock(now func() time.Time) *Memory {
	return &Memory{
		users:   make(map[string]User),
		secrets: make(map[int64]map[string]Secret),
		now:     now,
	}
}

// CreateUser сохраняет нового пользователя. Реализует UserStorage.
func (m *Memory) CreateUser(_ context.Context, user User) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.users[user.Login]; ok {
		return User{}, ErrUserExists
	}

	m.nextUserID++
	user.ID = m.nextUserID
	user.CreatedAt = m.now()
	m.users[user.Login] = cloneUser(user)

	return cloneUser(user), nil
}

// UserByLogin возвращает пользователя по логину. Реализует UserStorage.
func (m *Memory) UserByLogin(_ context.Context, login string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[login]
	if !ok {
		return User{}, ErrUserNotFound
	}

	return cloneUser(user), nil
}

// CreateSecret сохраняет новую запись. Реализует SecretStorage.
func (m *Memory) CreateSecret(_ context.Context, userID int64, secret Secret) (Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	userSecrets := m.secrets[userID]
	if userSecrets == nil {
		userSecrets = make(map[string]Secret)
		m.secrets[userID] = userSecrets
	}
	if _, ok := userSecrets[secret.ID]; ok {
		return Secret{}, ErrSecretExists
	}

	secret.Version = 1
	secret.Deleted = false
	secret.UpdatedAt = m.now()
	userSecrets[secret.ID] = cloneSecret(secret)

	return cloneSecret(secret), nil
}

// GetSecret возвращает неудалённую запись. Реализует SecretStorage.
func (m *Memory) GetSecret(_ context.Context, userID int64, id string) (Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, ok := m.secrets[userID][id]
	if !ok || secret.Deleted {
		return Secret{}, ErrSecretNotFound
	}

	return cloneSecret(secret), nil
}

// UpdateSecret заменяет содержимое записи при совпадении версии.
// Реализует SecretStorage.
func (m *Memory) UpdateSecret(_ context.Context, userID int64, secret Secret, expectedVersion int64) (Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	current, err := m.liveSecret(userID, secret.ID, expectedVersion)
	if err != nil {
		return Secret{}, err
	}

	current.Type = secret.Type
	current.EncryptedPayload = slices.Clone(secret.EncryptedPayload)
	current.Version++
	current.UpdatedAt = m.now()
	m.secrets[userID][current.ID] = current

	return cloneSecret(current), nil
}

// DeleteSecret помечает запись удалённой при совпадении версии.
// Реализует SecretStorage.
func (m *Memory) DeleteSecret(_ context.Context, userID int64, id string, expectedVersion int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	current, err := m.liveSecret(userID, id, expectedVersion)
	if err != nil {
		return err
	}

	current.Deleted = true
	current.EncryptedPayload = nil
	current.Version++
	current.UpdatedAt = m.now()
	m.secrets[userID][id] = current

	return nil
}

// ListSecrets возвращает все записи пользователя, включая удалённые, в
// порядке изменения. Реализует SecretStorage.
func (m *Memory) ListSecrets(_ context.Context, userID int64) ([]Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	secrets := make([]Secret, 0, len(m.secrets[userID]))
	for _, secret := range m.secrets[userID] {
		secrets = append(secrets, cloneSecret(secret))
	}

	slices.SortFunc(secrets, func(a, b Secret) int {
		if c := a.UpdatedAt.Compare(b.UpdatedAt); c != 0 {
			return c
		}

		return compareStrings(a.ID, b.ID)
	})

	return secrets, nil
}

// liveSecret возвращает неудалённую запись, проверяя её версию. Вызывается
// под захваченным m.mu.
func (m *Memory) liveSecret(userID int64, id string, expectedVersion int64) (Secret, error) {
	current, ok := m.secrets[userID][id]
	if !ok || current.Deleted {
		return Secret{}, ErrSecretNotFound
	}
	if current.Version != expectedVersion {
		return Secret{}, ErrVersionConflict
	}

	return current, nil
}

// cloneUser возвращает копию пользователя с независимыми срезами байт.
func cloneUser(user User) User {
	user.PasswordHash = slices.Clone(user.PasswordHash)
	user.PasswordSalt = slices.Clone(user.PasswordSalt)
	user.KDFSalt = slices.Clone(user.KDFSalt)

	return user
}

// cloneSecret возвращает копию записи с независимым шифротекстом.
func cloneSecret(secret Secret) Secret {
	secret.EncryptedPayload = slices.Clone(secret.EncryptedPayload)

	return secret
}

// compareStrings сравнивает строки лексикографически: -1, 0 или 1.
func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
