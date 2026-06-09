BINARY := goscan
DIST_DIR := dist
VERSION ?= 0.1.0

.PHONY: test build run fmt clean release

test:
	go test ./...

build:
	go build -buildvcs=false -o $(BINARY) ./cmd/goscan

run:
	go run ./cmd/goscan scan 127.0.0.1 -Pn -p 22,80,443

fmt:
	gofmt -w ./cmd ./internal ./pkg

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf $(DIST_DIR)

release:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY)-linux-amd64 ./cmd/goscan
	GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY)-windows-amd64.exe ./cmd/goscan
	tar -C $(DIST_DIR) -czf $(DIST_DIR)/$(BINARY)-v$(VERSION)-linux-amd64.tar.gz $(BINARY)-linux-amd64
	cd $(DIST_DIR) && zip -q $(BINARY)-v$(VERSION)-windows-amd64.zip $(BINARY)-windows-amd64.exe
	cd $(DIST_DIR) && sha256sum $(BINARY)-linux-amd64 $(BINARY)-windows-amd64.exe *.tar.gz *.zip > checksums.txt
