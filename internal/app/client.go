package app

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	"ipk-rdt/internal/config"
	"ipk-rdt/internal/protocol"
)

// clientHandshake handles the SYN-ACK handshake sequence with the server
func clientHandshake(conn *net.UDPConn, connID uint32, timeoutSec int) error {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("handshake timeout: failed to establish connection within %d seconds", timeoutSec)
		}

		// Prepare and send SYN
		synHeader := protocol.Header{
			ConnectionID: connID,
			SeqNum:       0,
			AckNum:       0,
			Flags:        protocol.FlagSYN,
			Padding:      0,
			Length:       0,
			Checksum:     0,
		}

		hBytes := synHeader.Encode()
		synHeader.Checksum = protocol.CalculateChecksum(hBytes, nil)
		hBytes = synHeader.Encode()

		_, err := conn.Write(hBytes)
		if err != nil {
			return fmt.Errorf("failed to send SYN: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Client sent SYN - ConnID: %d\n", connID)

		// Wait for SYN-ACK with a short loop timeframe
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buf := make([]byte, 1200)
		n, _, err := conn.ReadFromUDP(buf)

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Retry connection loop natively
				continue
			}
			return fmt.Errorf("failed reading during handshake: %w", err)
		}

		if n < protocol.HeaderSize {
			continue // Drop
		}

		var recvHeader protocol.Header
		hBytesRecv := buf[:protocol.HeaderSize]

		if err := recvHeader.Decode(hBytesRecv); err != nil {
			continue
		}

		crc := protocol.CalculateChecksum(hBytesRecv, buf[protocol.HeaderSize:n])
		if crc != recvHeader.Checksum {
			continue // Drop
		}

		if recvHeader.ConnectionID != connID {
			continue // Drop cross connection
		}

		if (recvHeader.Flags & (protocol.FlagSYN | protocol.FlagACK)) == (protocol.FlagSYN | protocol.FlagACK) {
			fmt.Fprintf(os.Stderr, "Client received SYN-ACK - ConnID: %d\n", recvHeader.ConnectionID)

			// Send ACK safely
			ackHeader := protocol.Header{
				ConnectionID: connID,
				SeqNum:       0,
				AckNum:       recvHeader.SeqNum + 1,
				Flags:        protocol.FlagACK,
				Padding:      0,
				Length:       0,
				Checksum:     0,
			}
			aBytes := ackHeader.Encode()
			ackHeader.Checksum = protocol.CalculateChecksum(aBytes, nil)
			aBytes = ackHeader.Encode()

			_, err = conn.Write(aBytes)
			if err != nil {
				return fmt.Errorf("failed to send ACK: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Client sent ACK - ConnID: %d\n", connID)

			conn.SetReadDeadline(time.Time{})
			return nil
		}
	}
}

// RunClient reads from the input stream and sends data sequentially over UDP
func RunClient(cfg *config.Config, in io.Reader) error {
	addr := net.JoinHostPort(cfg.Address, strconv.Itoa(cfg.Port))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	connID := rand.Uint32()
	err = clientHandshake(conn, connID, cfg.Timeout)
	if err != nil {
		return err
	}

	// Assign max payload limit based on full minus header bytes
	buf := make([]byte, 1200-protocol.HeaderSize)

	var seqNum uint32 = 0

	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			payload := buf[:n]

			h := protocol.Header{
				ConnectionID: connID,
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
