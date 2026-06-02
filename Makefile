.PHONY: build run keygen rotate docker up vet test

build:
	go build -mod=vendor ./...

vet:
	go vet -mod=vendor ./...

test:
	go test -mod=vendor ./...

run:
	go run -mod=vendor ./cmd/tpt-identity serve --config config.yaml

keygen:
	go run -mod=vendor ./cmd/tpt-identity keygen --out-sign keys/ed25519.pem

rotate:
	go run -mod=vendor ./cmd/tpt-identity rotate --old-key keys/ed25519.pem --out keys/ed25519-new.pem

docker:
	docker build -t tpt-identity .

up:
	docker compose up

dev:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up
