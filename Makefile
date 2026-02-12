SHELL := /bin/bash

BINARY := tcexecutor
IMAGE_NAME ?= tcexecutor
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X 'main.version=$(VERSION)'

.PHONY: help build image image-run clean

help:
	@echo "Targets:"
	@echo "  build   Build $(BINARY) binary"
	@echo "  image   Build container image ($(IMAGE_NAME):$(VERSION))"
	@echo "  image-run   Run image and print DOCKER_HOST env var"
	@echo "  clean   Remove build artifacts"
	@echo "Variables:"
	@echo "  VERSION    Override version tag (default: git describe or dev)"
	@echo "  IMAGE_NAME Override image name (default: tcexecutor)"

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE_NAME):$(VERSION) .

image-run:
	@echo "Set:"
	@echo "  export DOCKER_HOST=tcp://127.0.0.1:8080"
	@echo ""
	docker run --rm -p 8080:8080 $(IMAGE_NAME):$(VERSION)

clean:
	rm -f $(BINARY)
