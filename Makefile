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

.PHONY: all fmt vet lint test cover tidy proto

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
