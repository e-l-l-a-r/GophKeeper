# Makefile проекта GophKeeper.
#
# Исполняемые файлы Go могут отсутствовать в PATH. Путь к go задаётся
# переменной GO: make test GO=/home/ellar/work/go_sdk/go1.26.2/bin/go

GO ?= go
COVER_PROFILE ?= coverage.out
COVER_MIN ?= 70

# Инструменты генерации кода по .proto: protoc и плагины лежат вне PATH.
PROTOC ?= $(HOME)/.local/protoc/bin/protoc
PROTOC_INCLUDE ?= $(HOME)/.local/protoc/include
PROTO_PLUGINS ?= $(HOME)/go/bin

# Сборка клиента: версия, дата и коммит передаются в бинарный файл через
# -ldflags и выводятся командой gophkeeper version. Версию можно задать явно:
# make build-client VERSION=1.0.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BIN_DIR ?= bin
LDFLAGS = -s -w \
	-X main.buildVersion=$(VERSION) \
	-X main.buildDate=$(DATE) \
	-X main.buildCommit=$(COMMIT)

# Платформы, под которые собирается клиент: ОС/архитектура.
CLIENT_PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all fmt vet lint test cover tidy proto build-server build-client build-client-all

all: fmt vet lint test

## fmt: форматирует исходный код
fmt:
	$(GO) fmt ./...

## vet: базовая статика
vet:
	$(GO) vet ./...

## lint: мультичекер проекта. Замечания по файлам из go-build cache (os.Exit в
## сгенерированных main стандартной библиотеки) и по сгенерированным
## *.pb.go отфильтрованы; цель падает, если остались замечания по коду проекта.
lint:
	@out=$$($(GO) run ./cmd/staticlint ./... 2>&1 | grep -v -e '/go-build/' -e '\.pb\.go:' -e '^exit status'); \
	if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

## test: юнит-тесты с проверкой гонок
test:
	$(GO) test -race ./...

## cover: покрытие тестами и проверка порога COVER_MIN, %.
## Сгенерированный код (*.pb.go) из профиля исключается.
cover:
	$(GO) test -coverprofile=$(COVER_PROFILE) ./...
	@grep -v '\.pb\.go:' $(COVER_PROFILE) > $(COVER_PROFILE).tmp && mv $(COVER_PROFILE).tmp $(COVER_PROFILE)
	@$(GO) tool cover -func=$(COVER_PROFILE) | tail -n 1
	@$(GO) tool cover -func=$(COVER_PROFILE) | awk -v min=$(COVER_MIN) \
		'/^total:/ { gsub("%", "", $$3); if ($$3 + 0 < min) { printf "покрытие %s%% ниже порога %s%%\n", $$3, min; exit 1 } }'

## tidy: приводит go.mod и go.sum в порядок
tidy:
	$(GO) mod tidy

## proto: генерирует Go-код в internal/proto и спецификацию Swagger в api/swagger
proto:
	PATH=$(PROTO_PLUGINS):$$PATH $(PROTOC) \
		--proto_path=api/proto --proto_path=$(PROTOC_INCLUDE) \
		--go_out=internal/proto --go_opt=paths=source_relative \
		--go-grpc_out=internal/proto --go-grpc_opt=paths=source_relative \
		--openapiv2_out=api/swagger \
		--openapiv2_opt=generate_unbound_methods=true,allow_merge=true,merge_file_name=gophkeeper \
		api/proto/gophkeeper.proto

## build-server: собирает сервер для текущей платформы в $(BIN_DIR)/server
build-server:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/server ./cmd/server

## build-client: собирает клиент для текущей платформы в $(BIN_DIR)/gophkeeper
build-client:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gophkeeper ./cmd/client

## build-client-all: кросс-сборка клиента для Linux, macOS и Windows (см. CLIENT_PLATFORMS)
build-client-all:
	@for platform in $(CLIENT_PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		out="$(BIN_DIR)/gophkeeper-$$os-$$arch$$ext"; \
		echo "$(GO) build $$out"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o "$$out" ./cmd/client || exit 1; \
	done
