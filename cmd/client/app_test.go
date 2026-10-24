package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/e-l-l-a-r/gophkeeper/internal/client"
	"github.com/e-l-l-a-r/gophkeeper/internal/crypto"
	"github.com/e-l-l-a-r/gophkeeper/internal/localstore"
)

func TestRun_Version(t *testing.T) {
	e := newEnv(t, newTestServer(t))

	for _, name := range []string{"version", "--version", "-v"} {
		t.Run(name, func(t *testing.T) {
			out := e.mustDo(nil, name)
			assert.Contains(t, out, "Build version: 1.2.3")
			assert.Contains(t, out, "Build date: 2026-02-03")
			assert.Contains(t, out, "Build commit: abc")
		})
	}
}

func TestRun_VersionWithoutBuildInfo(t *testing.T) {
	var out bytes.Buffer

	a := &app{stdout: &out, stderr: &bytes.Buffer{}}
	require.NoError(t, a.run(context.Background(), []string{"version"}))

	assert.Contains(t, out.String(), "Build version: N/A")
	assert.Contains(t, out.String(), "Build date: N/A")
}

func TestRun_Help(t *testing.T) {
	e := newEnv(t, newTestServer(t))

	for _, name := range []string{"help", "--help", "-h"} {
		t.Run(name, func(t *testing.T) {
			out := e.mustDo(nil, name)

			for _, cmd := range []string{"register", "login", "logout", "add", "get", "list", "edit", "delete", "sync", "resolve", "version"} {
				assert.Contains(t, out, cmd)
			}
		})
	}
}

func TestRun_NoCommandAndUnknownCommand(t *testing.T) {
	e := newEnv(t, newTestServer(t))

	var errOut bytes.Buffer
	a := e.application(nil)
	a.stderr = &errOut

	err := a.run(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, errOut.String(), "Команды:")

	errOut.Reset()
	err = a.run(context.Background(), []string{"launch"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"launch"`)
	assert.Contains(t, errOut.String(), "Команды:", "при неизвестной команде показывается справка")
}

func TestRun_CommandHelpIsNotAnError(t *testing.T) {
	e := newEnv(t, newTestServer(t))

	for _, name := range []string{"register", "login", "logout", "add", "get", "list", "edit", "delete", "sync", "resolve"} {
		t.Run(name, func(t *testing.T) {
			e.errOut.Reset()

			require.NoError(t, e.application(nil).run(context.Background(), []string{name, "--help"}))
			assert.Contains(t, e.errOut.String(), "Использование:")
		})
	}
}

func TestRegisterLoginLogout(t *testing.T) {
	srv := newTestServer(t)
	e := newEnv(t, srv)

	t.Run("регистрация", func(t *testing.T) {
		out := e.mustDo(&scriptedPrompt{lines: []string{" alice "}, secrets: []string{"s3cretpass", "s3cretpass"}}, "register")
		assert.Contains(t, out, `"alice"`)
		assert.Contains(t, out, "мастер-пароль")

		store, err := localstore.Open(e.dir)
		require.NoError(t, err)
		sess, err := store.LoadSession()
		require.NoError(t, err)

		assert.Equal(t, "alice", sess.Login)
		assert.NotEmpty(t, sess.Token)
		assert.Len(t, sess.KDFSalt, crypto.SaltSize)
		assert.Equal(t, defaultServer, sess.Server)
	})

	t.Run("пароли входа не совпадают", func(t *testing.T) {
		other := newEnv(t, srv)

		err := other.do(&scriptedPrompt{lines: []string{"bob"}, secrets: []string{"s3cretpass", "different1"}}, "register")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "не совпадают")
	})

	t.Run("логин занят", func(t *testing.T) {
		other := newEnv(t, srv)

		err := other.do(&scriptedPrompt{lines: []string{"alice"}, secrets: []string{"s3cretpass", "s3cretpass"}}, "register")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "занят")
	})

	t.Run("вход получает соль с сервера", func(t *testing.T) {
		other := newEnv(t, srv)
		out := other.mustDo(&scriptedPrompt{lines: []string{"alice"}, secrets: []string{"s3cretpass"}}, "login")
		assert.Contains(t, out, "alice")

		sess, err := mustStore(t, other).LoadSession()
		require.NoError(t, err)

		first, err := mustStore(t, e).LoadSession()
		require.NoError(t, err)
		assert.Equal(t, first.KDFSalt, sess.KDFSalt, "второе устройство получает ту же соль ключа шифрования")
	})

	t.Run("неверный пароль входа", func(t *testing.T) {
		other := newEnv(t, srv)

		err := other.do(&scriptedPrompt{lines: []string{"alice"}, secrets: []string{"wrongpass1"}}, "login")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "неверный логин или пароль")

		_, loadErr := mustStore(t, other).LoadSession()
		require.ErrorIs(t, loadErr, localstore.ErrNoSession, "при неудачном входе сессия не сохраняется")
	})
}

func mustStore(t *testing.T, e *testEnv) *localstore.Store {
	t.Helper()

	s, err := localstore.Open(e.dir)
	require.NoError(t, err)

	return s
}

func TestLogout(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	out := e.mustDo(nil, "logout")
	assert.Contains(t, out, "Сессия завершена")

	_, err := mustStore(t, e).LoadSession()
	require.ErrorIs(t, err, localstore.ErrNoSession)

	e.mustDo(nil, "logout") // повторный выход - не ошибка
}

func TestCommandsRequireLogin(t *testing.T) {
	e := newEnv(t, newTestServer(t))

	for _, args := range [][]string{
		{"list"}, {"sync"}, {"get", "x"}, {"delete", "x", "-y"}, {"edit", "x"},
		{"add", "text"}, {"resolve", "x", "--keep", "local"},
	} {
		t.Run(args[0], func(t *testing.T) {
			err := e.do(&scriptedPrompt{}, args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "не вошли")
		})
	}
}

func TestRegister_ServerUnavailable(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.unavailable = true

	err := e.do(&scriptedPrompt{lines: []string{"alice"}, secrets: []string{"s3cretpass", "s3cretpass"}}, "register")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "недоступен")
}

func TestSecretsRequireTerminal(t *testing.T) {
	e := newEnv(t, newTestServer(t))

	err := e.do(&scriptedPrompt{lines: []string{"alice"}, secretErr: errNotTerminal}, "register")
	require.ErrorIs(t, err, errNotTerminal)
	assert.Contains(t, err.Error(), "интерактивно")

	err = e.do(&scriptedPrompt{lines: []string{"alice"}, secretErr: errNotTerminal}, "login")
	require.ErrorIs(t, err, errNotTerminal)
}

func TestNoArgsCommandsRejectExtraArguments(t *testing.T) {
	e := newEnv(t, newTestServer(t))

	for _, name := range []string{"register", "login", "logout", "list", "sync"} {
		t.Run(name, func(t *testing.T) {
			err := e.do(&scriptedPrompt{}, name, "лишнее")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "не принимает аргументов")
		})
	}
}

func TestGlobalFlagsAndEnvPriority(t *testing.T) {
	cfgFile := writeFile(t, "client.json", []byte(`{"server": "file:1", "ca_file": "/file.pem", "insecure": true}`))

	tests := []struct {
		env        map[string]string
		name       string
		wantServer string
		wantCA     string
		args       []string
		wantInsec  bool
	}{
		{name: "значения по умолчанию", wantServer: defaultServer},
		{name: "из файла", args: []string{"-c", cfgFile}, wantServer: "file:1", wantCA: "/file.pem", wantInsec: true},
		{name: "флаг важнее файла", args: []string{"-c", cfgFile, "-s", "flag:2", "--ca-file", "/flag.pem"}, wantServer: "flag:2", wantCA: "/flag.pem", wantInsec: true},
		{
			name: "окружение важнее флага", args: []string{"-c", cfgFile, "-s", "flag:2"},
			env:        map[string]string{"GOPHKEEPER_SERVER": "env:3", "GOPHKEEPER_CA_FILE": "/env.pem", "GOPHKEEPER_INSECURE": "false"},
			wantServer: "env:3", wantCA: "/env.pem", wantInsec: false,
		},
		{name: "файл из окружения", env: map[string]string{"GOPHKEEPER_CONFIG": cfgFile}, wantServer: "file:1", wantCA: "/file.pem", wantInsec: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
			flags := addGlobalFlags(fs)
			require.NoError(t, fs.Parse(append([]string{"--dir", t.TempDir()}, tt.args...)))

			g, err := resolveGlobals(fs, flags)
			require.NoError(t, err)

			assert.Equal(t, tt.wantServer, g.server)
			assert.Equal(t, tt.wantCA, g.caFile)
			assert.Equal(t, tt.wantInsec, g.insecure)
			assert.Equal(t, defaultTimeout, g.timeout)
		})
	}
}

func TestGlobalFlags_DefaultDirAndErrors(t *testing.T) {
	cleanEnv(t)

	t.Run("каталог по умолчанию", func(t *testing.T) {
		fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
		flags := addGlobalFlags(fs)
		require.NoError(t, fs.Parse(nil))

		g, err := resolveGlobals(fs, flags)
		require.NoError(t, err)
		assert.Equal(t, "gophkeeper", filepath.Base(g.dir))
	})

	tests := []struct {
		env  map[string]string
		name string
		args []string
	}{
		{name: "пустой адрес сервера", args: []string{"-s", ""}},
		{name: "отрицательное время", args: []string{"--timeout", "-1s"}},
		{name: "нулевое время", args: []string{"--timeout", "0s"}},
		{name: "файл не существует", args: []string{"-c", "/нет/такого/файла.json"}},
		{name: "некорректное булево в окружении", env: map[string]string{"GOPHKEEPER_INSECURE": "возможно"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
			flags := addGlobalFlags(fs)
			require.NoError(t, fs.Parse(tt.args))

			_, err := resolveGlobals(fs, flags)
			require.Error(t, err)
		})
	}
}

func TestSecretsHaveNoFlags(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	for _, flag := range []string{"--password", "--master-password", "--cvv", "--token"} {
		t.Run(flag, func(t *testing.T) {
			err := e.do(&scriptedPrompt{}, "list", flag, "x")
			require.Error(t, err, "секреты не должны передаваться флагами")
			assert.Contains(t, err.Error(), "unknown flag")
		})
	}
}

func TestExplain(t *testing.T) {
	tests := []struct {
		err      error
		name     string
		contains string
	}{
		{name: "нет ошибки"},
		{name: "нет сессии", err: localstore.ErrNoSession, contains: "не вошли"},
		{name: "токен недействителен", err: client.ErrUnauthenticated, contains: "login"},
		{name: "неверный мастер-пароль", err: crypto.ErrDecrypt, contains: "мастер-пароль"},
		{name: "прочая ошибка", err: errors.New("своя ошибка"), contains: "своя ошибка"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := explain(tt.err)
			if tt.err == nil {
				require.NoError(t, got)
				return
			}

			require.Error(t, got)
			assert.Contains(t, got.Error(), tt.contains)
		})
	}
}

func TestExplainAuth(t *testing.T) {
	assert.Contains(t, explainAuth(client.ErrLoginTaken).Error(), "занят")
	assert.Contains(t, explainAuth(client.ErrInvalidCredentials).Error(), "неверный логин или пароль")
	assert.Contains(t, explainAuth(client.ErrUnavailable).Error(), "недоступен")

	plain := errors.New("другая")
	assert.Equal(t, plain, explainAuth(plain))
}

func TestOfflineRemote(t *testing.T) {
	var r offlineRemote
	ctx := context.Background()

	_, err := r.Create(ctx, "", 0, nil)
	require.ErrorIs(t, err, client.ErrUnavailable)
	_, err = r.Get(ctx, "")
	require.ErrorIs(t, err, client.ErrUnavailable)
	_, err = r.Update(ctx, "", 0, nil, 0)
	require.ErrorIs(t, err, client.ErrUnavailable)
	require.ErrorIs(t, r.Delete(ctx, "", 0), client.ErrUnavailable)
	_, _, err = r.Sync(ctx, nil)
	require.ErrorIs(t, err, client.ErrUnavailable)
}

func TestExpiredSessionIsNotUsed(t *testing.T) {
	e := newEnv(t, newTestServer(t))
	e.register()

	store := mustStore(t, e)
	sess, err := store.LoadSession()
	require.NoError(t, err)
	sess.ExpiresAt = testNow.Add(-time.Second)
	require.NoError(t, store.SaveSession(sess))

	err = e.do(nil, "sync")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "истёк")
}
