# Makefile проекта GophKeeper.
#
# Исполняемые файлы Go могут отсутствовать в PATH. Путь к go задаётся
# переменной GO: make test GO=/home/ellar/work/go_sdk/go1.26.2/bin/go

GO ?= go
COVER_PROFILE ?= coverage.out
COVER_MIN ?= 70

.PHONY: all fmt vet lint test cover tidy

all: fmt vet lint test

## fmt: форматирует исходный код
fmt:
	$(GO) fmt ./...

## vet: базовая статика
vet:
	$(GO) vet ./...

## lint: мультичекер проекта. Замечания по файлам из go-build cache (os.Exit в
## сгенерированных main стандартной библиотеки) отфильтрованы; цель падает,
## если остались замечания по коду проекта.
lint:
	@out=$$($(GO) run ./cmd/staticlint ./... 2>&1 | grep -v -e '/go-build/' -e '^exit status'); \
	if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

## test: юнит-тесты с проверкой гонок
test:
	$(GO) test -race ./...

## cover: покрытие тестами и проверка порога COVER_MIN, %
cover:
	$(GO) test -coverprofile=$(COVER_PROFILE) ./...
	@$(GO) tool cover -func=$(COVER_PROFILE) | tail -n 1
	@$(GO) tool cover -func=$(COVER_PROFILE) | awk -v min=$(COVER_MIN) \
		'/^total:/ { gsub("%", "", $$3); if ($$3 + 0 < min) { printf "покрытие %s%% ниже порога %s%%\n", $$3, min; exit 1 } }'

## tidy: приводит go.mod и go.sum в порядок
tidy:
	$(GO) mod tidy
