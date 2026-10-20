package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptr[T any](v T) *T { return &v }

func TestDuration_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{name: "строка с секундами", input: `"1s"`, want: time.Second},
		{name: "строка с миллисекундами", input: `"300ms"`, want: 300 * time.Millisecond},
		{name: "число секунд", input: `5`, want: 5 * time.Second},
		{name: "дробное число секунд", input: `1.5`, want: 1500 * time.Millisecond},
		{name: "некорректная строка", input: `"abc"`, wantErr: true},
		{name: "булево значение", input: `true`, wantErr: true},
		{name: "некорректный JSON", input: `{`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalJSON([]byte(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, d.Std())
		})
	}
}

func TestLoad(t *testing.T) {
	type sample struct {
		Address *string   `json:"address"`
		Timeout *Duration `json:"timeout"`
	}

	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.json")
	require.NoError(t, os.WriteFile(validPath, []byte(`{"address":"localhost:1","timeout":"2s"}`), 0o600))
	brokenPath := filepath.Join(dir, "broken.json")
	require.NoError(t, os.WriteFile(brokenPath, []byte(`{`), 0o600))

	t.Run("пустой путь", func(t *testing.T) {
		var got sample
		require.NoError(t, Load("", &got))
		assert.Nil(t, got.Address)
	})

	t.Run("корректный файл", func(t *testing.T) {
		var got sample
		require.NoError(t, Load(validPath, &got))
		require.NotNil(t, got.Address)
		assert.Equal(t, "localhost:1", *got.Address)
		require.NotNil(t, got.Timeout)
		assert.Equal(t, 2*time.Second, got.Timeout.Std())
	})

	t.Run("файл не существует", func(t *testing.T) {
		var got sample
		require.Error(t, Load(filepath.Join(dir, "missing.json"), &got))
	})

	t.Run("некорректный JSON", func(t *testing.T) {
		var got sample
		require.Error(t, Load(brokenPath, &got))
	})
}

func TestResolveString(t *testing.T) {
	tests := []struct {
		file        *string
		name        string
		env         string
		flag        string
		want        string
		flagChanged bool
	}{
		{name: "окружение важнее всего", env: "env", flagChanged: true, flag: "flag", file: ptr("file"), want: "env"},
		{name: "флаг важнее файла", flagChanged: true, flag: "flag", file: ptr("file"), want: "flag"},
		{name: "файл важнее значения по умолчанию", flag: "default", file: ptr("file"), want: "file"},
		{name: "значение по умолчанию", flag: "default", want: "default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ResolveString(tt.env, tt.flagChanged, tt.flag, tt.file))
		})
	}
}

func TestResolveBool(t *testing.T) {
	tests := []struct {
		env         *bool
		file        *bool
		name        string
		flagChanged bool
		flag        bool
		want        bool
	}{
		{name: "окружение false важнее всего", env: ptr(false), flagChanged: true, flag: true, file: ptr(true), want: false},
		{name: "флаг важнее файла", flagChanged: true, flag: true, file: ptr(false), want: true},
		{name: "файл важнее значения по умолчанию", flag: false, file: ptr(true), want: true},
		{name: "значение по умолчанию", flag: true, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ResolveBool(tt.env, tt.flagChanged, tt.flag, tt.file))
		})
	}
}

func TestResolveDuration(t *testing.T) {
	fileValue := Duration(10 * time.Second)

	tests := []struct {
		env         *time.Duration
		file        *Duration
		name        string
		flag        time.Duration
		want        time.Duration
		flagChanged bool
	}{
		{name: "окружение важнее всего", env: ptr(time.Second), flagChanged: true, flag: 2 * time.Second, file: &fileValue, want: time.Second},
		{name: "флаг важнее файла", flagChanged: true, flag: 2 * time.Second, file: &fileValue, want: 2 * time.Second},
		{name: "файл важнее значения по умолчанию", flag: 3 * time.Second, file: &fileValue, want: 10 * time.Second},
		{name: "значение по умолчанию", flag: 3 * time.Second, want: 3 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ResolveDuration(tt.env, tt.flagChanged, tt.flag, tt.file))
		})
	}
}

func TestDuration_MarshalRoundTripInStruct(t *testing.T) {
	var got struct {
		Interval Duration `json:"interval"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{"interval":"1m"}`), &got))
	assert.Equal(t, time.Minute, got.Interval.Std())
}
