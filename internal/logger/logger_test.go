package logger

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		wantErr bool
	}{
		{name: "debug", level: "debug"},
		{name: "info в верхнем регистре", level: "INFO"},
		{name: "warn", level: "warn"},
		{name: "error", level: "error"},
		{name: "неизвестный уровень", level: "verbose", wantErr: true},
		{name: "пустой уровень означает info", level: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := New(tt.level)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, l)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, l)
			assert.NotNil(t, l.Logger)
		})
	}
}

func TestNop(t *testing.T) {
	l := Nop()
	require.NotNil(t, l)
	assert.NotPanics(t, func() { l.Info("сообщение") })
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("запись невозможна")
}

func TestPrintBuildInfo(t *testing.T) {
	tests := []struct {
		name    string
		version string
		date    string
		commit  string
		want    string
	}{
		{
			name:    "все значения заданы",
			version: "1.0.0",
			date:    "2026-01-02",
			commit:  "abc123",
			want:    "Build version: 1.0.0\nBuild date: 2026-01-02\nBuild commit: abc123\n",
		},
		{
			name: "значения не заданы",
			want: "Build version: N/A\nBuild date: N/A\nBuild commit: N/A\n",
		},
		{
			name:    "часть значений не задана",
			version: "0.1",
			want:    "Build version: 0.1\nBuild date: N/A\nBuild commit: N/A\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, PrintBuildInfo(&buf, tt.version, tt.date, tt.commit))
			assert.Equal(t, tt.want, buf.String())
		})
	}
}

func TestPrintBuildInfo_WriteError(t *testing.T) {
	err := PrintBuildInfo(failingWriter{}, "1", "2", "3")
	require.Error(t, err)
}
