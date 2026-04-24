package app

import (
	"fmt"
	"io"
	"net"

	"ipk-rdt/internal/config"
)

// RunClient reads from the input stream and sends data sequentially over UDP.
func RunClient(cfg *config.Config, in io.Reader) error {
	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	// Assign max payload limit
	buf := make([]byte, 1200)

	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			_, writeErr := conn.Write(buf[:n])
			if writeErr != nil {
				return fmt.Errorf("failed to send data: %w", writeErr)
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return fmt.Errorf("error reading input stream: %w", readErr)
		}
	}

	return nil
}
