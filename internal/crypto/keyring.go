package crypto

import (
	"fmt"
	"sync"
)

// Keyring шифрует данные ключом с текущим числом итераций и расшифровывает
// blob с любым допустимым числом итераций: ключ для нужного числа итераций
// выводится из мастер-пароля при первом обращении и запоминается. Благодаря
// этому повышение DefaultIterations не делает старые записи нечитаемыми.
//
// Keyring хранит мастер-пароль в памяти на время своей жизни. Безопасен для
// одновременного использования из нескольких горутин.
type Keyring struct {
	keys          map[int]*Key
	password      string
	salt          []byte
	mu            sync.Mutex
	encIterations int
}

// NewKeyring создаёт связку ключей для мастер-пароля password и соли salt,
// которую выдал сервер. Новые данные шифруются ключом, выведенным за
// iterations итераций (обычно DefaultIterations). Ключ шифрования выводится
// сразу, поэтому ошибка в параметрах обнаруживается здесь.
func NewKeyring(password string, salt []byte, iterations int) (*Keyring, error) {
	key, err := DeriveKey(password, salt, iterations)
	if err != nil {
		return nil, err
	}

	return &Keyring{
		keys:          map[int]*Key{iterations: key},
		password:      password,
		salt:          append([]byte(nil), salt...),
		encIterations: iterations,
	}, nil
}

// Encrypt шифрует plaintext ключом с текущим числом итераций.
func (r *Keyring) Encrypt(plaintext []byte) ([]byte, error) {
	key, err := r.keyFor(r.encIterations)
	if err != nil {
		return nil, err
	}

	return key.Encrypt(plaintext)
}

// Decrypt расшифровывает blob, созданный Encrypt с любым допустимым числом
// итераций. Возвращает ErrFormat для blob неизвестного формата и ErrDecrypt
// при неверном мастер-пароле или повреждении.
func (r *Keyring) Decrypt(blob []byte) ([]byte, error) {
	iterations, err := IterationsOf(blob)
	if err != nil {
		return nil, err
	}

	key, err := r.keyFor(iterations)
	if err != nil {
		return nil, err
	}

	return key.Decrypt(blob)
}

// keyFor возвращает ключ для заданного числа итераций, выводя его при
// необходимости. Вывод выполняется под блокировкой: параллельные запросы к
// одному и тому же числу итераций не считают ключ дважды.
func (r *Keyring) keyFor(iterations int) (*Key, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if key, ok := r.keys[iterations]; ok {
		return key, nil
	}

	key, err := DeriveKey(r.password, r.salt, iterations)
	if err != nil {
		return nil, fmt.Errorf("не удалось вывести ключ для %d итераций: %w", iterations, err)
	}
	r.keys[iterations] = key

	return key, nil
}
