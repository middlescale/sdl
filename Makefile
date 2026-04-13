MODE ?= debug

PACKAGE = sdl-cli
SERVICE_BIN = sdl-service
CLI_BIN = sdl

BINARY_debug = target/debug/$(SERVICE_BIN)
BINARY_release = target/release/$(SERVICE_BIN)
CLI_BINARY_debug = target/debug/$(CLI_BIN)
CLI_BINARY_release = target/release/$(CLI_BIN)

IMAGE_NAME_debug = ghcr.io/middlescale/$(SERVICE_BIN):debug
IMAGE_NAME_release = ghcr.io/middlescale/$(SERVICE_BIN):latest

BINARY = $(BINARY_$(MODE))
CLI_BINARY = $(CLI_BINARY_$(MODE))
IMAGE_NAME = $(IMAGE_NAME_$(MODE))
CARGO_BUILD_ARGS =

ifeq ($(MODE),release)
CARGO_BUILD_ARGS += --release
endif

ifneq (,$(wildcard .env))
include .env
export GHCR_TOKEN GHCR_USER
endif

GHCR_USER ?= middlescale

.PHONY: all debug release build docker push login test clean help

all: build

debug:
	$(MAKE) MODE=debug build

release:
	$(MAKE) MODE=release build

build:
	cargo build -p $(PACKAGE) $(CARGO_BUILD_ARGS)

docker: build
	docker build --no-cache --build-arg BINARY_PATH=$(BINARY) -t $(IMAGE_NAME) .

login:
	@if [ -z "$$GHCR_TOKEN" ]; then echo "GHCR_TOKEN is not set"; exit 1; fi
	echo $$GHCR_TOKEN | docker login ghcr.io -u $(GHCR_USER) --password-stdin

push: build docker login
	docker push $(IMAGE_NAME)

test:
	cargo test -p sdl --quiet
	cargo test -p sdl-cli --quiet

clean:
	cargo clean

help:
	@echo "默认行为:"
	@echo "  make / make build     构建 SDL debug 版（$(CLI_BINARY), $(BINARY)）"
	@echo "  make release          构建 SDL release 版"
	@echo "  make test             运行本地测试"
	@echo ""
	@echo "镜像相关:"
	@echo "  make docker MODE=debug|release"
	@echo "  make push   MODE=debug|release"
	@echo "  当前镜像名: $(IMAGE_NAME)"
	@echo ""
	@echo "环境变量:"
	@echo "  GHCR_USER   (默认: middlescale)"
	@echo "  GHCR_TOKEN  (push/login 时必填)"
