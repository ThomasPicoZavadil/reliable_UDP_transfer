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

		// Handle Implicit ACK (Valid ID mapped traffic natively avoiding flag mappings)
		if (ackHeader.Flags & protocol.FlagSYN) == 0 {
			fmt.Fprintf(os.Stderr, "Server received Data implicitly ACKing handshake - ConnID: %d. Handshake COMPLETE!\n", connID)
			conn.SetReadDeadline(time.Time{})

			dataPayload := make([]byte, len(payload))
			copy(dataPayload, payload)
			return clientAddr, connID, dataPayload, nil
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

	clientAddr, targetConnID, initPayload, err := serverHandshake(conn, cfg.Timeout)
	if err != nil {
		return err
	}

	var expectedSeqNum uint32 = 0

	if initPayload != nil && len(initPayload) > 0 {
		_, writeErr := out.Write(initPayload)
		if writeErr != nil {
			return fmt.Errorf("failed to write early output stream: %w", writeErr)
		}
		expectedSeqNum += uint32(len(initPayload))

		// Dispatch formal explicit ACK for implicitly bypassed traffic
		ackHeader := protocol.Header{
			ConnectionID: targetConnID,
			SeqNum:       0,
			AckNum:       expectedSeqNum,
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

	buf := make([]byte, 1200)

	// Keep listening block indefinitely (or until interrupted/fatal error) natively filtering using targets
	for {
		conn.SetReadDeadline(time.Time{})
		n, addr, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			return fmt.Errorf("error reading from UDP socket: %w", readErr)
		}

		if addr.String() != clientAddr.String() {
			continue
		}

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

			if h.ConnectionID != targetConnID {
				continue // Drop foreign payloads natively
			}

			// Trap Explicit Structural FIN markers organically jumping to mapping states Native
			if (h.Flags & protocol.FlagFIN) == protocol.FlagFIN {
				fmt.Fprintf(os.Stderr, "Server intercepted isolated bounding mappings dynamically terminating - ConnID: %d\n", h.ConnectionID)
				err := serverTeardown(conn, targetConnID, clientAddr, h.SeqNum, cfg.Timeout)
				if err != nil {
					return err
				}
				break // Gracefully map boundary teardowns
			}

			// Core sequential filtering
			if h.SeqNum == expectedSeqNum {
				fmt.Fprintf(os.Stderr, "Server received in-order packet - Seq: %d, Len: %d\n", h.SeqNum, h.Length)
				_, writeErr := out.Write(payload)
				if writeErr != nil {
					return fmt.Errorf("failed to write output stream: %w", writeErr)
				}
				expectedSeqNum += uint32(h.Length)
			} else {
				fmt.Fprintf(os.Stderr, "Server received out-of-order packet - Seq: %d (expected %d). Dropping.\n", h.SeqNum, expectedSeqNum)
			}

			// Cumulatively generate returning dynamic ACKs structurally mapped tracking latest guaranteed bounds
			ackHeader := protocol.Header{
				ConnectionID: targetConnID,
				SeqNum:       0,
				AckNum:       expectedSeqNum,
				Flags:        protocol.FlagACK,
				Padding:      0,
				Length:       0,
				Checksum:     0,
			}
			aBytes := ackHeader.Encode()
			ackHeader.Checksum = protocol.CalculateChecksum(aBytes, nil)
			aBytes = ackHeader.Encode()

			_, sendErr := conn.WriteToUDP(aBytes, clientAddr)
			if sendErr != nil {
				fmt.Fprintf(os.Stderr, "Server failed sending local ACK natively: %v\n", sendErr)
			}
		}
	}

	return nil
}
