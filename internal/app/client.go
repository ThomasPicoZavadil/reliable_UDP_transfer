package app

import (
	"fmt"
	"io"
	"net"
	"os"

	"ipk-rdt/internal/config"
	"ipk-rdt/internal/protocol"
)

// RunClient reads from the input stream and sends data sequentially over UDP
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

	// Assign max payload limit based on full minus header bytes
	buf := make([]byte, 1200-protocol.HeaderSize)

	var seqNum uint32 = 0

	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			payload := buf[:n]

			h := protocol.Header{
				ConnectionID: 1,
				SeqNum:       seqNum,
				AckNum:       0,
				Flags:        0,
				Padding:      0,
				Length:       uint16(n),
				Checksum:     0,
			}
			
			headerBytes := h.Encode()
			h.Checksum = protocol.CalculateChecksum(headerBytes, payload)
			headerBytes = h.Encode()

			fmt.Fprintf(os.Stderr, "Client sent packet - ConnID: %d, Seq: %d, Ack: %d, Len: %d, Checksum: %x\n", 
				h.ConnectionID, h.SeqNum, h.AckNum, h.Length, h.Checksum)

			combined := append(headerBytes, payload...)

			_, writeErr := conn.Write(combined)
			if writeErr != nil {
				return fmt.Errorf("failed to send data: %w", writeErr)
			}
			seqNum += uint32(n)
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
