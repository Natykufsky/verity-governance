.PHONY: test test-race vet lint fmt tidy

test:
	go test -v ./...

test-race:
	go test -race -count=1 -v ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

