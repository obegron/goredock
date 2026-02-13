SHELL := /bin/bash

BINARY := sidewhale
IMAGE_NAME ?= sidewhale
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PLATFORM ?= linux/amd64
LDFLAGS := -s -w -X 'main.version=$(VERSION)'

.PHONY: help build image docker-build docker-push image-run smoke-pull clean

help:
	@echo "Targets:"
	@echo "  build   Build $(BINARY) binary"
	@echo "  image         Build container image ($(IMAGE_NAME):$(VERSION))"
	@echo "  docker-build  Build image via buildx for $(PLATFORM)"
	@echo "  docker-push   Build and push image with provenance + SBOM"
	@echo "  image-run   Run image in host network mode and print DOCKER_HOST env var"
	@echo "  smoke-pull  Quick API smoke test (ping/version + image pull)"
	@echo "  clean   Remove build artifacts"
	@echo "Variables:"
	@echo "  VERSION    Override version tag (default: git describe or dev)"
	@echo "  IMAGE_NAME Override image name (default: sidewhale)"
	@echo "  PLATFORM   buildx platform (default: linux/amd64)"
	@echo "  SMOKE_IMAGE Image used by smoke-pull (default: redis:7-alpine)"
	@echo "  SIDEWHALE_RUN_ARGS Extra args passed to sidewhale in smoke-pull"

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE_NAME):$(VERSION) .

docker-build:
	docker buildx build --platform $(PLATFORM) --build-arg VERSION=$(VERSION) -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest . --load

docker-push:
	docker buildx build --platform $(PLATFORM) --provenance=true --sbom=true --build-arg VERSION=$(VERSION) -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest . --push

image-run:
	@echo "Set:"
	@echo "  export DOCKER_HOST=tcp://127.0.0.1:23750"
	@echo ""
	docker run --rm --network host $(IMAGE_NAME):$(VERSION) --listen :23750 --listen-unix /tmp/sidewhale/docker.sock

SMOKE_IMAGE ?= redis:7-alpine
SIDEWHALE_RUN_ARGS ?=

smoke-pull:
	@set -euo pipefail; \
	container=sidewhale-smoke; \
	docker rm -f $$container >/dev/null 2>&1 || true; \
	trap 'docker rm -f $$container >/dev/null 2>&1 || true' EXIT; \
	docker run -d --name $$container --network host $(IMAGE_NAME):$(VERSION) --listen :23750 --listen-unix /tmp/sidewhale/docker.sock $(SIDEWHALE_RUN_ARGS) >/dev/null; \
	sleep 1; \
	curl -fsS http://127.0.0.1:23750/_ping >/dev/null; \
	curl -fsS http://127.0.0.1:23750/version >/dev/null; \
	curl -fsS -X POST "http://127.0.0.1:23750/v1.41/images/create?fromImage=$(SMOKE_IMAGE)" >/dev/null; \
	echo "smoke ok: pulled $(SMOKE_IMAGE)"

clean:
	rm -f $(BINARY)
