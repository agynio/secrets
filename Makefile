SHELL := /bin/bash

.PHONY: all proto build test lint fmt clean

all: build

proto:
	# secrets/v1 is vendored under proto/ until the ImagePullSecret removal
	# lands in buf.build/agynio/api; see proto/buf.yaml.
	buf generate proto --template buf.gen.yaml
	buf generate buf.build/agynio/api --path agynio/api/egress/v1

build:
	GOFLAGS=-mod=mod go build ./...

test:
	GOFLAGS=-mod=mod go test ./...

lint:
	GOFLAGS=-mod=mod go vet ./...

fmt:
	gofmt -w $(shell find . -type f -name '*.go')

clean:
	rm -rf gen
