package app

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"ipk-rdt/internal/config"
	"ipk-rdt/internal/protocol"
)

func serverHandshake(conn *net.UDPConn, timeoutSec int) (*net.UDPAddr, uint32, []byte, error) {
	buf := make([]byte, 1200)

	var clientAddr *net.UDPAddr
	var connID uint32
	var recvHeader protocol.Header
	var initSeqNum uint32

	// State: LISTEN -> block indefinitely on the connection until standard read
	conn.SetReadDeadline(time.Time{})

	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed reading in LISTEN: %w", err)
		}

		if n < protocol.HeaderSize {
			continue
		}

		hBytes := buf[:protocol.HeaderSize]
		payload := buf[protocol.HeaderSize:n]

		if err := recvHeader.Decode(hBytes); err != nil {
			continue
		}

		crc := protocol.CalculateChecksum(hBytes, payload)
		if crc != recvHeader.Checksum {
			continue // Valid checksum drop
		}

		if (recvHeader.Flags & protocol.FlagSYN) == protocol.FlagSYN {
			fmt.Fprintf(os.Stderr, "Server received SYN - ConnID: %d\n", recvHeader.ConnectionID)
			clientAddr = addr
			connID = recvHeader.ConnectionID
			initSeqNum = recvHeader.SeqNum
			break
		}
	}

	// State 2: SYN_RECEIVED waiting natively on internal SYN-ACK timers
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)

	for {
		if time.Now().After(deadline) {
			return nil, 0, nil, fmt.Errorf("handshake timeout: failed to complete handshake within %d seconds", timeoutSec)
		}

		synAckHeader := protocol.Header{
			ConnectionID: connID,
			SeqNum:       0,
			AckNum:       initSeqNum + 1,
			Flags:        protocol.FlagSYN | protocol.FlagACK,
			Padding:      0,
			Length:       0,
			Checksum:     0,
		}
		saBytes := synAckHeader.Encode()
		synAckHeader.Checksum = protocol.CalculateChecksum(saBytes, nil)
		saBytes = synAckHeader.Encode()

		_, err := conn.WriteToUDP(saBytes, clientAddr)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed to send SYN-ACK: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Server sent SYN-ACK - ConnID: %d\n", connID)

		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, addr, err := conn.ReadFromUDP(buf)

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Retry connection loop
				continue
			}
			return nil, 0, nil, fmt.Errorf("failed reading in SYN_RECEIVED: %w", err)
		}

		// Ensure it correlates to address
		if addr.String() != clientAddr.String() {
			continue // Cross communication drop securely
		}

		if n < protocol.HeaderSize {
			continue
		}

		var ackHeader protocol.Header
		hBytes := buf[:protocol.HeaderSize]
		payload := buf[protocol.HeaderSize:n]

		if err := ackHeader.Decode(hBytes); err != nil {
			continue
		}

		crc := protocol.CalculateChecksum(hBytes, payload)
		if crc != ackHeader.Checksum {
			continue
		}

		if ackHeader.ConnectionID != connID {
			continue
		}

		// Handle Formal Explicit ACK
		if (ackHeader.Flags & protocol.FlagACK) == protocol.FlagACK {
			fmt.Fprintf(os.Stderr, "Server received ACK - ConnID: %d. Handshake COMPLETE!\n", connID)
			conn.SetReadDeadline(time.Time{})
			return clientAddr, connID, nil, nil
		}

		// Handle Implicit ACK (non-SYN packet from correct client)
		if (ackHeader.Flags & protocol.FlagSYN) == 0 {
			fmt.Fprintf(os.Stderr, "Server received Data implicitly ACKing handshake - ConnID: %d. Handshake COMPLETE!\n", connID)
			conn.SetReadDeadline(time.Time{})
			return clientAddr, connID, nil, nil
		}
	}
}

func serverTeardown(conn *net.UDPConn, connID uint32, clientAddr *net.UDPAddr, finSeqNum uint32, timeoutSec int) error {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)

	finAckHeader := protocol.Header{
		ConnectionID: connID,
		SeqNum:       0,
		AckNum:       finSeqNum + 1,
		Flags:        protocol.FlagFIN | protocol.FlagACK,
		Padding:      0,
		Length:       0,
		Checksum:     0,
	}
	faBytes := finAckHeader.Encode()
	finAckHeader.Checksum = protocol.CalculateChecksum(faBytes, nil)
	faBytes = finAckHeader.Encode()

	buf := make([]byte, 1200)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("server teardown limits timeout: failed receiving final structural explicit ACK bounding %d seconds cleanly", timeoutSec)
		}

		conn.WriteToUDP(faBytes, clientAddr)
		fmt.Fprintf(os.Stderr, "Server iteratively isolated explicitly sending internal FIN-ACK - ConnID: %d\n", connID)

		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, addr, err := conn.ReadFromUDP(buf)

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Retry explicit standard FIN-ACK boundaries Native
				continue
			}
			return fmt.Errorf("failed executing dynamic structurally isolated read frames mapping teardown: %w", err)
		}

		if addr.String() != clientAddr.String() || n < protocol.HeaderSize {
			continue
		}

		var ackHeader protocol.Header
		if ackHeader.Decode(buf[:protocol.HeaderSize]) == nil {
			crc := protocol.CalculateChecksum(buf[:protocol.HeaderSize], buf[protocol.HeaderSize:n])
			if crc == ackHeader.Checksum && ackHeader.ConnectionID == connID {
				if (ackHeader.Flags & protocol.FlagACK) == protocol.FlagACK {
					fmt.Fprintf(os.Stderr, "Server accurately validated explicit final cumulative ACK - ConnID: %d. Teardown COMPLETE!\n", connID)
					return nil
				}
			}
		}
	}
}

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

	clientAddr, targetConnID, _, err := serverHandshake(conn, cfg.Timeout)
	if err != nil {
		return err
	}

	var expectedSeqNum uint32 = 0
	recvBuffer := make(map[uint32][]byte)
	lastProgress := time.Now()
	progressTimeout := time.Duration(cfg.Timeout) * time.Second

	buf := make([]byte, 1200)

	for {
		// Check progress timeout
		if time.Since(lastProgress) > progressTimeout {
			return fmt.Errorf("no protocol progress for %d seconds", cfg.Timeout)
		}

		conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, addr, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		if addr.String() != clientAddr.String() {
			continue
		}

		if n > 0 {
			if n < protocol.HeaderSize {
				continue
			}

			headerBytes := buf[:protocol.HeaderSize]
			payload := buf[protocol.HeaderSize:n]

			var h protocol.Header
			err := h.Decode(headerBytes)
			if err != nil {
				continue
			}

			crc := protocol.CalculateChecksum(headerBytes, payload)
			if crc != h.Checksum {
				continue
			}

			if h.ConnectionID != targetConnID {
				continue
			}

			if (h.Flags & protocol.FlagFIN) == protocol.FlagFIN {
				fmt.Fprintf(os.Stderr, "Server received FIN - ConnID: %d\n", h.ConnectionID)
				err := serverTeardown(conn, targetConnID, clientAddr, h.SeqNum, cfg.Timeout)
				if err != nil {
					return err
				}
				break
			}

			if h.SeqNum == expectedSeqNum {
				_, writeErr := out.Write(payload)
				if writeErr != nil {
					return fmt.Errorf("failed to write output stream: %w", writeErr)
				}
				expectedSeqNum += uint32(h.Length)
				lastProgress = time.Now() // genuine progress: new in-order data

				for {
					if cachedPayload, exists := recvBuffer[expectedSeqNum]; exists {
						_, writeErr := out.Write(cachedPayload)
						if writeErr != nil {
							return fmt.Errorf("failed to write cached output: %w", writeErr)
						}
						delete(recvBuffer, expectedSeqNum)
						expectedSeqNum += uint32(len(cachedPayload))
					} else {
						break
					}
				}

			} else if h.SeqNum > expectedSeqNum {
				if _, exists := recvBuffer[h.SeqNum]; !exists {
					bufferCopy := make([]byte, len(payload))
					copy(bufferCopy, payload)
					recvBuffer[h.SeqNum] = bufferCopy
					lastProgress = time.Now() // genuine progress: new cached data
				}
			}

			ackHeader := protocol.Header{
				ConnectionID: targetConnID,
				SeqNum:       0,
				AckNum:       h.SeqNum,
				Flags:        protocol.FlagACK,
				Padding:      0,
				Length:       0,
				Checksum:     0,
			}
			aBytes := ackHeader.Encode()
			ackHeader.Checksum = protocol.CalculateChecksum(aBytes, nil)
			aBytes = ackHeader.Encode()
			conn.WriteToUDP(aBytes, clientAddr)
		}
	}

	return nil
}
