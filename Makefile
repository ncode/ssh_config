BUMP_VERSION := go run github.com/kevinburke/bump_version@v0.0.0-20240229201700-392026682451
WRITE_MAILMAP := go run github.com/kevinburke/write_mailmap@v0.0.0-20180427174204-754cdd25e871

lint:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

test:
	@# the timeout helps guard against infinite recursion
	go test -timeout=250ms ./...

race-test:
	go test -timeout=500ms -race ./...

release: test
	$(BUMP_VERSION) --tag-prefix=v minor config.go

force: ;

AUTHORS.txt: force
	$(WRITE_MAILMAP) > AUTHORS.txt

authors: AUTHORS.txt
