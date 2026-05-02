.PHONY: all clean test ipk-rdt

all: ipk-rdt

ipk-rdt:
	go build -o ipk-rdt ./cmd/ipk-rdt

test:
	go test -v -timeout 300s ./test/

clean:
	rm -f ipk-rdt
