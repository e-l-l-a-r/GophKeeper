package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	publicMethod  = "/gophkeeper.v1.AuthService/Login"
	privateMethod = "/gophkeeper.v1.SecretsService/Get"
)

func TestContextUserID(t *testing.T) {
	_, ok := UserIDFromContext(context.Background())
	assert.False(t, ok)

	userID, ok := UserIDFromContext(ContextWithUserID(context.Background(), 9))
	require.True(t, ok)
	assert.Equal(t, int64(9), userID)
}

func TestUnaryInterceptor(t *testing.T) {
	c := &clock{now: testTime}
	m := newTestManager(t, testKey, time.Hour, c)
	valid, _ := m.Issue(11)

	expiredManager := newTestManager(t, testKey, time.Hour, &clock{now: testTime.Add(-2 * time.Hour)})
	expired, _ := expiredManager.Issue(11)

	tests := []struct {
		md       metadata.MD
		name     string
		method   string
		wantUser int64
		wantCode codes.Code
		wantCall bool
	}{
		{
			name:     "публичный метод без токена",
			method:   publicMethod,
			wantCode: codes.OK,
			wantCall: true,
		},
		{
			name:     "закрытый метод с токеном",
			method:   privateMethod,
			md:       metadata.Pairs("authorization", "Bearer "+valid),
			wantCode: codes.OK,
			wantCall: true,
			wantUser: 11,
		},
		{
			name:     "схема в другом регистре",
			method:   privateMethod,
			md:       metadata.Pairs("authorization", "bEaReR "+valid),
			wantCode: codes.OK,
			wantCall: true,
			wantUser: 11,
		},
		{
			name:     "метаданных нет",
			method:   privateMethod,
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "нет заголовка authorization",
			method:   privateMethod,
			md:       metadata.Pairs("x-other", "value"),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "другая схема авторизации",
			method:   privateMethod,
			md:       metadata.Pairs("authorization", "Basic "+valid),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "токен без схемы",
			method:   privateMethod,
			md:       metadata.Pairs("authorization", valid),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "пустой токен после схемы",
			method:   privateMethod,
			md:       metadata.Pairs("authorization", "Bearer "),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "подделанный токен",
			method:   privateMethod,
			md:       metadata.Pairs("authorization", "Bearer "+valid[:len(valid)-2]+"AA"),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "просроченный токен",
			method:   privateMethod,
			md:       metadata.Pairs("authorization", "Bearer "+expired),
			wantCode: codes.Unauthenticated,
		},
	}

	intercept := UnaryInterceptor(m, publicMethod)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.md != nil {
				ctx = metadata.NewIncomingContext(ctx, tt.md)
			}

			called := false
			var gotUser int64
			handler := func(ctx context.Context, req any) (any, error) {
				called = true
				gotUser, _ = UserIDFromContext(ctx)

				return req, nil
			}

			resp, err := intercept(ctx, "запрос", &grpc.UnaryServerInfo{FullMethod: tt.method}, handler)

			assert.Equal(t, tt.wantCode, status.Code(err))
			assert.Equal(t, tt.wantCall, called)
			assert.Equal(t, tt.wantUser, gotUser)
			if tt.wantCode == codes.OK {
				assert.Equal(t, "запрос", resp)
			} else {
				assert.Nil(t, resp)
			}
		})
	}
}

func TestUnaryInterceptor_ExpiredAndInvalidHaveDifferentMessages(t *testing.T) {
	m := newTestManager(t, testKey, time.Hour, &clock{now: testTime})
	expiredManager := newTestManager(t, testKey, time.Hour, &clock{now: testTime.Add(-2 * time.Hour)})
	expired, _ := expiredManager.Issue(1)

	intercept := UnaryInterceptor(m)
	info := &grpc.UnaryServerInfo{FullMethod: privateMethod}
	handler := func(context.Context, any) (any, error) { return nil, nil }

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+expired))
	_, err := intercept(ctx, nil, info, handler)
	assert.Equal(t, ErrExpiredToken.Error(), status.Convert(err).Message())

	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer мусор"))
	_, err = intercept(ctx, nil, info, handler)
	assert.Equal(t, ErrInvalidToken.Error(), status.Convert(err).Message())
}
