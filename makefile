VERSION := $(shell git describe --tags --always)
LDFLAGS=-ldflags "-s -w -X=main.version=$(VERSION)"

MKDOCS_IMAGE := aquasec/mkdocs-material:dev
MKDOCS_PORT := 8000

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
	go test -v ./...

.PHONY: test-coverage
test-coverage:
	go test -coverprofile=coverage.out -covermode=atomic -v ./...

# Run MkDocs development server to preview the documentation page
.PHONY: mkdocs-serve
mkdocs-serve:
	docker build -t $(MKDOCS_IMAGE) -f docs/build/Dockerfile docs/build
	docker run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE)

