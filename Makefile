# MCPSoc Makefile

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=mcpsoc
BINARY_UNIX=$(BINARY_NAME)_unix

# Build info
VERSION ?= $(shell git describe --tags --always --dirty)
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT ?= $(shell git rev-parse HEAD)

# Linker flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

.PHONY: all build clean test coverage deps lint docker help

all: test build

## Build:
build: ## Build the binary file
	$(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME) -v ./cmd/mcpsoc-host

build-linux: ## Build the binary file for Linux
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_UNIX) -v ./cmd/mcpsoc-host

build-all: ## Build binaries for all platforms
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/mcpsoc-host
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/mcpsoc-host
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/mcpsoc-host

## Test:
test: ## Run tests
	$(GOTEST) -v ./...

test-coverage: ## Run tests with coverage
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

test-race: ## Run tests with race detector
	$(GOTEST) -v -race ./...

## Quality:
lint: ## Run linter
	golangci-lint run

fmt: ## Format code
	$(GOCMD) fmt ./...

vet: ## Run go vet
	$(GOCMD) vet ./...

## Dependencies:
deps: ## Download dependencies
	$(GOMOD) download
	$(GOMOD) tidy

deps-update: ## Update dependencies
	$(GOGET) -u ./...
	$(GOMOD) tidy

## Development:
dev: ## Run in development mode
	$(GOCMD) run ./cmd/mcpsoc-host

dev-watch: ## Run with file watching (requires air)
	air

## Database:
db-migrate: ## Run database migrations
	$(GOCMD) run ./cmd/mcpsoc-cli migrate up

db-seed: ## Seed database with test data
	$(GOCMD) run ./cmd/mcpsoc-cli seed

## Docker:
docker-build: ## Build docker image
	docker build -t mcpsoc:$(VERSION) .

docker-run: ## Run docker container
	docker run -p 8080:8080 mcpsoc:$(VERSION)

docker-compose-up: ## Start with docker-compose
	docker-compose up -d

docker-compose-down: ## Stop docker-compose
	docker-compose down

## Clean:
clean: ## Remove build artifacts
	$(GOCLEAN)
	rm -rf bin/
	rm -f coverage.out coverage.html

## Tools:
install-tools: ## Install development tools
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOGET) github.com/cosmtrek/air@latest

## Help:
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)