.PHONY: build
build:
	@mkdir -p ./dist
	go build  -o ./dist/reverse-proxy cmd/*
	GOOS=linux GOARCH=amd64  go build  -o ./dist/reverse-proxy-linux-amd64 cmd/*