VERSION := $(shell git describe --tags --always)
LDFLAGS=-ldflags "-s -w -X=main.version=$(VERSION)"
GOROOT:=$(shell go env GOROOT)

# If the first argument is "run"...
ifeq (run,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

.PHONY: build
build:
	go build $(LDFLAGS) ./cmd/chain-bench

.PHONY: run
run:
	go run $(LDFLAGS) ./cmd/chain-bench $(RUN_ARGS)

.PHONY: test
test:
	go test -v ./cmd/... ./internal/...

.PHONY: test-coverage
test-coverage:
	go test -coverprofile=coverage.out -covermode=atomic -v ./cmd/... ./internal/...

.PHONY: build-wasm
build-wasm:
	GOOS=js GOARCH=wasm go build -o chain-bench.wasm ./wasm/main.go

.PHONY: run-wasm-example-web
start-wasm-example-web: build-wasm
	cp ./chain-bench.wasm ./docs/examples/wasm/web && \
	cp $(GOROOT)/misc/wasm/wasm_exec.js ./docs/examples/wasm/web && \
	cd ./docs/examples/wasm/web && \
	docker build -t chain-bench-wasm-example-web . && \
	docker run -d -p 3000:80 --name wasm-example chain-bench-wasm-example-web && \
	rm -rf ./docs/examples/wasm/web/chain-bench.wasm && \
	rm -rf ./docs/examples/wasm/web/wasm_exec.js && \
	echo "Chain bench WASM minimal example is running at - http://localhost:3000/"

.PHONY: stop-wasm-example-web
stop-wasm-example-web:
	docker rm -f wasm-example && \
	docker rmi -f chain-bench-wasm-example-web && \
	echo "Chain bench WASM minimal example stopped"

	

