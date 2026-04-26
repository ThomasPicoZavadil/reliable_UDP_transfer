package app

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"ipk-rdt/internal/config"
	"ipk-rdt/internal/protocol"
)

// RunServer binds to a UDP socket, reads incoming datagrams sequentially, and writes to an output stream
func RunServer(cfg *config.Config, out io.Writer) error {
	addr := net.JoinHostPort(cfg.Address, strconv.Itoa(cfg.Port))

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer conn.Close()

	buf := make([]byte, 1200)

	// Keep listening block indefinitely (or until interrupted/fatal error)
	for {
		n, _, readErr := conn.ReadFromUDP(buf)
		if n > 0 {
			if n < protocol.HeaderSize {
				fmt.Fprintf(os.Stderr, "Received packet too small to contain header (size %d)\n", n)
				continue
			}

			headerBytes := buf[:protocol.HeaderSize]
			payload := buf[protocol.HeaderSize:n]

			var h protocol.Header
			err := h.Decode(headerBytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to decode header: %v\n", err)
				continue
			}

			crc := protocol.CalculateChecksum(headerBytes, payload)
			if crc != h.Checksum {
				fmt.Fprintf(os.Stderr, "Checksum validation failed! Expected: %x, Got: %x. Dropping packet.\n", h.Checksum, crc)
				continue
			}

			fmt.Fprintf(os.Stderr, "Server received packet - ConnID: %d, Seq: %d, Ack: %d, Len: %d, Checksum: %x\n", 
				h.ConnectionID, h.SeqNum, h.AckNum, h.Length, h.Checksum)

			_, writeErr := out.Write(payload)
			if writeErr != nil {
				return fmt.Errorf("failed to write output stream: %w", writeErr)
			}
		}

		if readErr != nil {
			return fmt.Errorf("error reading from UDP socket: %w", readErr)
		}
	}
}
