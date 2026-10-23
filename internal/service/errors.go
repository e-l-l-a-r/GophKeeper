package service

import (
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/e-l-l-a-r/gophkeeper/internal/logger"
)

// internalError логирует внутреннюю ошибку сервиса svc при выполнении
// действия action и возвращает клиенту общий код codes.Internal без
// подробностей: детали сбоя (адреса, тексты SQL) клиенту знать не нужно.
func internalError(log *logger.Logger, svc, action string, err error) error {
	log.Error("внутренняя ошибка сервиса",
		zap.String("сервис", svc), zap.String("действие", action), zap.Error(err))

	return status.Error(codes.Internal, "внутренняя ошибка сервера")
}
