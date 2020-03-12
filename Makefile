#!/usr/bin/make -f

test:
	go test -timeout=1s -race -covermode=atomic .

compile:
	go build ./...

build: test compile

tcr:
	go mod tidy
	go fmt ./...
	go test ./...


.PHONY: test compile build tcr
