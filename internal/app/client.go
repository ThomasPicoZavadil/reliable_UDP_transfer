package app

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"ipk-rdt/internal/config"
	"ipk-rdt/internal/protocol"
)

type Packet struct {
	SeqNum uint32
	Data   []byte
	Acked  bool
}

type Sender struct {
	WindowSize uint32
	SendBase   uint32
	NextSeqNum uint32

	Buffer map[uint32]*Packet

	mu         sync.Mutex
	windowCond *sync.Cond

	conn   *net.UDPConn
	connID uint32

	retransmitInterval time.Duration
	done               chan struct{}
	baseTimer          *time.Timer

	lastProgress    time.Time
	progressTimeout time.Duration
}

func NewSender(conn *net.UDPConn, connID uint32, windowSizePackets uint32, progressTimeout time.Duration) *Sender {
	s := &Sender{
		WindowSize:         windowSizePackets,
		SendBase:           0,
		NextSeqNum:         0,
		Buffer:             make(map[uint32]*Packet),
		conn:               conn,
		connID:             connID,
		retransmitInterval: 100 * time.Millisecond,
		done:               make(chan struct{}),
		lastProgress:       time.Now(),
		progressTimeout:    progressTimeout,
	}
	s.windowCond = sync.NewCond(&s.mu)

	s.baseTimer = time.AfterFunc(s.retransmitInterval, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		// On timeout, retransmit ALL unacked packets in the window
		for _, pkt := range s.Buffer {
			if !pkt.Acked {
				s.conn.Write(pkt.Data)
			}
		}
		if len(s.Buffer) > 0 {
			s.baseTimer.Reset(s.retransmitInterval)
		}
	})
	s.baseTimer.Stop()

	return s
}

func (s *Sender) Stop() {
	s.baseTimer.Stop()
	close(s.done)
}

func (s *Sender) Start(in io.Reader) error {
	go s.receiveACKs()

	maxPayload := uint32(1200 - protocol.HeaderSize)
	buf := make([]byte, maxPayload)

	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			payload := make([]byte, n)
			copy(payload, buf[:n])

			s.mu.Lock()
			// Block if the window is full
			for uint32(len(s.Buffer)) >= s.WindowSize {
				s.windowCond.Wait()
			}

			// Capture sequence number before creating header
			seqNum := s.NextSeqNum
			s.NextSeqNum += uint32(n)

			h := protocol.Header{
				ConnectionID: s.connID,
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

			combined := append(headerBytes, payload...)

			p := &Packet{
				SeqNum: seqNum,
				Data:   combined,
			}
			
			s.Buffer[seqNum] = p

			if len(s.Buffer) == 1 {
				s.baseTimer.Reset(s.retransmitInterval)
			}
			s.mu.Unlock()

			_, writeErr := s.conn.Write(p.Data)
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

	// Wait for all outstanding packets to be ACKed
	s.mu.Lock()
	for len(s.Buffer) > 0 {
		s.windowCond.Wait()
	}
	s.mu.Unlock()

	return nil
}

func (s *Sender) receiveACKs() {
	buf := make([]byte, 1200)
	for {
		select {
		case <-s.done:
			return
		default:
		}

		// Check progress timeout
		s.mu.Lock()
		if time.Since(s.lastProgress) > s.progressTimeout {
			s.mu.Unlock()
			fmt.Fprintf(os.Stderr, "Client error: no protocol progress for %d seconds\n", int(s.progressTimeout.Seconds()))
			os.Exit(1)
		}
		s.mu.Unlock()

		s.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, _, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		if n < protocol.HeaderSize {
			continue
		}

		hBytes := buf[:protocol.HeaderSize]
		var ackHeader protocol.Header
		if err := ackHeader.Decode(hBytes); err != nil {
			continue
		}

		crc := protocol.CalculateChecksum(hBytes, buf[protocol.HeaderSize:n])
		if crc != ackHeader.Checksum {
			continue
		}

		if ackHeader.ConnectionID != s.connID {
			continue
		}

		if (ackHeader.Flags & protocol.FlagACK) == protocol.FlagACK {
			s.mu.Lock()
			ackNum := ackHeader.AckNum // Now represents explicit Selective ACK SeqNum
			
			if pkt, ok := s.Buffer[ackNum]; ok && !pkt.Acked {
				pkt.Acked = true
				s.lastProgress = time.Now() // genuine protocol progress
			}

			// Contiguous window sliding: find how far SendBase can advance
			advanced := false
			for {
				if pkt, ok := s.Buffer[s.SendBase]; ok && pkt.Acked {
					// Safely delete and jump the bytes
					payloadSize := uint32(len(pkt.Data) - protocol.HeaderSize)
					delete(s.Buffer, s.SendBase)
					s.SendBase += payloadSize
					advanced = true
				} else {
					break // Gap detected or mapped limit explicitly reached natively
				}
			}

			if advanced {
				if len(s.Buffer) == 0 {
					s.baseTimer.Stop()
				} else {
					s.baseTimer.Reset(s.retransmitInterval)
				}
				s.windowCond.Broadcast() // Wake up the sender explicitly
			}
			s.mu.Unlock()
		}
	}
}

// clientTeardown maps FIN bounds generating native TIME_WAIT isolation mappings
func clientTeardown(conn *net.UDPConn, connID uint32, finSeqNum uint32, timeoutSec int) error {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	buf := make([]byte, 1200)

	// Phase 1: Generate explicit FIN, bound loops natively triggering timeouts mapped globally
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("teardown timeout: failed to complete FIN_WAIT cleanly within %d seconds", timeoutSec)
		}

		finHeader := protocol.Header{
			ConnectionID: connID,
			SeqNum:       finSeqNum,
			AckNum:       0,
			Flags:        protocol.FlagFIN,
			Padding:      0,
			Length:       0,
			Checksum:     0,
		}
		fBytes := finHeader.Encode()
		finHeader.Checksum = protocol.CalculateChecksum(fBytes, nil)
		fBytes = finHeader.Encode()

		_, err := conn.Write(fBytes)
		if err != nil {
			return fmt.Errorf("failed to send explicit FIN: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Client sent explicit FIN - ConnID: %d\n", connID)

		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Retry connection FIN drops
				continue
			}
			return fmt.Errorf("failed reading dynamic frames during teardown FIN_WAIT: %w", err)
		}

		if n < protocol.HeaderSize {
			continue // Drop explicit structural fails natively
		}

		var recvHeader protocol.Header
		hBytesRecv := buf[:protocol.HeaderSize]
		if err := recvHeader.Decode(hBytesRecv); err != nil {
			continue
		}

		crc := protocol.CalculateChecksum(hBytesRecv, buf[protocol.HeaderSize:n])
		if crc != recvHeader.Checksum {
			continue
		}

		if recvHeader.ConnectionID != connID {
			continue
		}

		if (recvHeader.Flags & (protocol.FlagFIN | protocol.FlagACK)) == (protocol.FlagFIN | protocol.FlagACK) {
			fmt.Fprintf(os.Stderr, "Client received structural FIN-ACK - ConnID: %d\n", recvHeader.ConnectionID)
			break // Break exactly into TIME_WAIT bounds logically natively
		}
	}

	// Phase 2: Form final cumulative explicit ACK natively executing structurally silent timeouts 
	timeWaitDeadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)

	ackHeader := protocol.Header{
		ConnectionID: connID,
		SeqNum:       0,
		AckNum:       0,
		Flags:        protocol.FlagACK,
		Padding:      0,
		Length:       0,
		Checksum:     0,
	}
	aBytes := ackHeader.Encode()
	ackHeader.Checksum = protocol.CalculateChecksum(aBytes, nil)
	aBytes = ackHeader.Encode()

	conn.Write(aBytes)
	fmt.Fprintf(os.Stderr, "Client sent final cumulative ACK - ConnID: %d. Entering silent TIME_WAIT for %ds\n", connID, timeoutSec)

	for {
		if time.Now().After(timeWaitDeadline) {
			break
		}

		conn.SetReadDeadline(timeWaitDeadline)
		n, _, err := conn.ReadFromUDP(buf)

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
		}

		if n >= protocol.HeaderSize {
			var rHead protocol.Header
			if rHead.Decode(buf[:protocol.HeaderSize]) == nil {
				if protocol.CalculateChecksum(buf[:protocol.HeaderSize], buf[protocol.HeaderSize:n]) == rHead.Checksum && rHead.ConnectionID == connID {
					if (rHead.Flags & (protocol.FlagFIN | protocol.FlagACK)) == (protocol.FlagFIN | protocol.FlagACK) {
						fmt.Fprintf(os.Stderr, "Client mathematically targeted duplicate FIN-ACK recursively in TIME_WAIT. Re-sending explicitly isolated ACK...\n")
						conn.Write(aBytes)
					}
				}
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Client explicit TIME_WAIT timed successfully elegantly. Teardown COMPLETE!\n")
	return nil
}

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

	sender := NewSender(conn, connID, 32, time.Duration(cfg.Timeout)*time.Second)
	err = sender.Start(in)
	if err != nil {
		return err
	}
	sender.Stop()

	err = clientTeardown(conn, connID, sender.NextSeqNum, cfg.Timeout)
	if err != nil {
		return err
	}

	return nil
}
