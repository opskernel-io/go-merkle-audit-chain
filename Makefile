.PHONY: test vet check bench

test:
	go test -race ./...

vet:
	go vet ./...

check: vet test

bench:
	go test -bench=. -benchmem ./...
