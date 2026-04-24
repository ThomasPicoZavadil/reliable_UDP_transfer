.PHONY: all clean ipk-rdt

all: ipk-rdt

ipk-rdt:
	go build -o ipk-rdt ./cmd/ipk-rdt

clean:
	rm -f ipk-rdt
