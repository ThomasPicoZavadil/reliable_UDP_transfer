package app

import (
	"fmt"
	"io"
	"net"

	"ipk-rdt/internal/config"
)

// RunServer binds to a UDP socket, reads incoming datagrams sequentially, and writes to an output stream.
func RunServer(cfg *config.Config, out io.Writer) error {
	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	if cfg.Address == "" {
		addr = fmt.Sprintf(":%d", cfg.Port)
	}

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

	// Keep listening block indefinitely (or until interrupted/fatal error) for now
	for {
		n, _, readErr := conn.ReadFromUDP(buf)
		if n > 0 {
			_, writeErr := out.Write(buf[:n])
			if writeErr != nil {
				return fmt.Errorf("failed to write output stream: %w", writeErr)
			}
		}

		if readErr != nil {
			return fmt.Errorf("error reading from UDP socket: %w", readErr)
		}
	}
}
