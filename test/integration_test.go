// Tato testovací část byla vytvořena s pomocí AI (Claude Opus)
// a následně upravena autorem.

package test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	mathrand "math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"ipk-rdt/internal/protocol"
)

var binaryPath string

//  Test Result Tracker 

type testResult struct {
	name     string
	category string
	passed   bool
}

var (
	resultsMu sync.Mutex
	results   []testResult
)

// track registers a test under a category and records its result on cleanup.
func track(t *testing.T, category string) {
	t.Helper()
	resultsMu.Lock()
	idx := len(results)
	results = append(results, testResult{name: t.Name(), category: category})
	resultsMu.Unlock()

	t.Cleanup(func() {
		resultsMu.Lock()
		results[idx].passed = !t.Failed()
		resultsMu.Unlock()
	})
}

func printSummary() {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  ═══════════════════════════════════════════════════════\n")
	fmt.Fprintf(os.Stderr, "  Test Summary\n")
	fmt.Fprintf(os.Stderr, "  ═══════════════════════════════════════════════════════\n")

	categories := []string{"Protocol", "Transfer", "I/O Modes", "IPv6", "Network", "CLI", "Signal", "Timeout"}
	totalPass, totalFail := 0, 0

	for _, cat := range categories {
		pass, fail := 0, 0
		for _, r := range results {
			if r.category == cat {
				if r.passed {
					pass++
				} else {
					fail++
				}
			}
		}
		if pass+fail == 0 {
			continue
		}
		totalPass += pass
		totalFail += fail
		fmt.Fprintf(os.Stderr, "  %-12s %d/%d passed\n", cat, pass, pass+fail)
	}

	fmt.Fprintf(os.Stderr, "  ───────────────────────────────────────────────────────\n")
	total := totalPass + totalFail
	if totalFail == 0 {
		fmt.Fprintf(os.Stderr, "  All %d tests passed\n", total)
	} else {
		fmt.Fprintf(os.Stderr, "  %d/%d tests passed, %d failed\n", totalPass, total, totalFail)
		for _, r := range results {
			if !r.passed {
				fmt.Fprintf(os.Stderr, "    FAIL: %s\n", r.name)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "  ═══════════════════════════════════════════════════════\n\n")
}

//  TestMain 

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "ipk-rdt-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	binaryPath = filepath.Join(tmpDir, "ipk-rdt")

	_, filename, _, _ := runtime.Caller(0)
	projectRoot := filepath.Dir(filepath.Dir(filename))

	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/ipk-rdt")
	cmd.Dir = projectRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build binary: %v\n%s\n", err, out)
		os.Exit(1)
	}

	code := m.Run()
	printSummary()
	os.Exit(code)
}

//  Protocol Unit Tests 

func TestCRC16_KnownValue(t *testing.T) {
	track(t, "Protocol")
	// CRC16-CCITT-FALSE of "123456789" is 0x29B1
	got := protocol.CRC16_CCITT([]byte("123456789"))
	if got != 0x29B1 {
		t.Errorf("CRC16_CCITT(\"123456789\") = 0x%04X, want 0x29B1", got)
	}
}

func TestCRC16_Empty(t *testing.T) {
	track(t, "Protocol")
	got := protocol.CRC16_CCITT([]byte{})
	if got != 0xFFFF {
		t.Errorf("CRC16_CCITT(empty) = 0x%04X, want 0xFFFF", got)
	}
}

func TestCRC16_DifferentInputs(t *testing.T) {
	track(t, "Protocol")
	a := protocol.CRC16_CCITT([]byte("hello"))
	b := protocol.CRC16_CCITT([]byte("world"))
	if a == b {
		t.Error("different inputs should produce different CRCs")
	}
}

func TestCRC16_Deterministic(t *testing.T) {
	track(t, "Protocol")
	input := []byte("test data for CRC")
	if protocol.CRC16_CCITT(input) != protocol.CRC16_CCITT(input) {
		t.Error("same input produced different CRCs")
	}
}

func TestChecksum_ZerosField(t *testing.T) {
	track(t, "Protocol")
	h := &protocol.Header{ConnectionID: 42, SeqNum: 100, Length: 5}
	payload := []byte("hello")

	crc1 := protocol.CalculateChecksum(h.Encode(), payload)
	h.Checksum = 0xBEEF
	crc2 := protocol.CalculateChecksum(h.Encode(), payload)

	if crc1 != crc2 {
		t.Errorf("checksum should be independent of stored field: 0x%04X vs 0x%04X", crc1, crc2)
	}
}

func TestChecksum_DetectsCorruption(t *testing.T) {
	track(t, "Protocol")
	h := &protocol.Header{ConnectionID: 1, Length: 4}
	encoded := h.Encode()
	if protocol.CalculateChecksum(encoded, []byte("test")) == protocol.CalculateChecksum(encoded, []byte("teSt")) {
		t.Error("CRC should differ for corrupted payload")
	}
}

func TestChecksum_NilPayload(t *testing.T) {
	track(t, "Protocol")
	h := &protocol.Header{ConnectionID: 1, Flags: protocol.FlagSYN}
	if protocol.CalculateChecksum(h.Encode(), nil) == 0 {
		t.Error("CRC of header-only packet should be non-zero")
	}
}

func TestChecksum_TooSmallHeader(t *testing.T) {
	track(t, "Protocol")
	if protocol.CalculateChecksum([]byte{1, 2, 3}, nil) != 0 {
		t.Error("expected 0 for undersized header")
	}
}

func TestHeaderEncodeDecode(t *testing.T) {
	track(t, "Protocol")
	h := &protocol.Header{
		ConnectionID: 0x12345678, SeqNum: 0x9ABCDEF0, AckNum: 0x0FEDCBA9,
		Flags: protocol.FlagSYN | protocol.FlagACK, Length: 10,
	}
	encoded := h.Encode()
	if len(encoded) != protocol.HeaderSize {
		t.Fatalf("expected %d bytes, got %d", protocol.HeaderSize, len(encoded))
	}

	var d protocol.Header
	if err := d.Decode(encoded); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if d.ConnectionID != h.ConnectionID || d.SeqNum != h.SeqNum || d.AckNum != h.AckNum || d.Flags != h.Flags || d.Length != h.Length {
		t.Error("decoded header does not match original")
	}
}

func TestHeaderDecode_TooSmall(t *testing.T) {
	track(t, "Protocol")
	var h protocol.Header
	if h.Decode([]byte{1, 2, 3}) == nil {
		t.Error("expected error for undersized buffer")
	}
}

func TestChecksum_RoundTrip(t *testing.T) {
	track(t, "Protocol")
	h := &protocol.Header{ConnectionID: 1, SeqNum: 2, AckNum: 3, Flags: protocol.FlagSYN, Length: 4}
	payload := []byte("test")

	encoded := h.Encode()
	crc := protocol.CalculateChecksum(encoded, payload)
	h.Checksum = crc
	encodedWithCrc := h.Encode()

	if protocol.CalculateChecksum(encodedWithCrc, payload) != crc {
		t.Error("checksum mismatch after round-trip")
	}
}

//  Helpers 

func findFreePort(t *testing.T) int {
	t.Helper()
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

func randomData(t *testing.T, n int) []byte {
	t.Helper()
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}
	return data
}

// transferFile runs a client→server transfer and returns the output bytes.
// Program stderr is suppressed so test output stays clean.
func transferFile(t *testing.T, input []byte, addr string, timeout time.Duration) []byte {
	t.Helper()
	port := findFreePort(t)
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.bin")
	outputFile := filepath.Join(tmpDir, "output.bin")
	os.WriteFile(inputFile, input, 0644)

	serverCmd := exec.Command(binaryPath, "-s", "-p", fmt.Sprintf("%d", port), "-a", addr, "-o", outputFile, "-w", "5")
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	clientCmd := exec.Command(binaryPath, "-c", "-a", addr, "-p", fmt.Sprintf("%d", port), "-i", inputFile, "-w", "5")
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("client start failed: %v", err)
	}

	done := make(chan error, 2)
	go func() { done <- clientCmd.Wait() }()
	go func() { done <- serverCmd.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				serverCmd.Process.Kill()
				clientCmd.Process.Kill()
				t.Fatalf("process failed: %v", err)
			}
		case <-timer.C:
			serverCmd.Process.Kill()
			clientCmd.Process.Kill()
			t.Fatalf("transfer timed out after %v", timeout)
		}
	}

	output, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	return output
}

//  Transfer Tests 

func TestTransfer_EmptyFile(t *testing.T) {
	track(t, "Transfer")
	output := transferFile(t, []byte{}, "127.0.0.1", 10*time.Second)
	if len(output) != 0 {
		t.Errorf("expected empty output, got %d bytes", len(output))
	}
}

func TestTransfer_SingleByte(t *testing.T) {
	track(t, "Transfer")
	input := []byte{0x42}
	output := transferFile(t, input, "127.0.0.1", 10*time.Second)
	if !bytes.Equal(input, output) {
		t.Errorf("mismatch: got %x, want %x", output, input)
	}
}

func TestTransfer_SmallText(t *testing.T) {
	track(t, "Transfer")
	input := []byte("Hello, IPK Reliable UDP Transfer!")
	output := transferFile(t, input, "127.0.0.1", 10*time.Second)
	if !bytes.Equal(input, output) {
		t.Errorf("mismatch:\ngot:  %q\nwant: %q", output, input)
	}
}

func TestTransfer_OneFullPacket(t *testing.T) {
	track(t, "Transfer")
	input := randomData(t, 1182)
	output := transferFile(t, input, "127.0.0.1", 10*time.Second)
	if sha256hex(input) != sha256hex(output) {
		t.Error("checksum mismatch for single full packet")
	}
}

func TestTransfer_MultiplePackets(t *testing.T) {
	track(t, "Transfer")
	input := randomData(t, 50*1024)
	output := transferFile(t, input, "127.0.0.1", 15*time.Second)
	if sha256hex(input) != sha256hex(output) {
		t.Errorf("checksum mismatch: sent %d bytes, received %d", len(input), len(output))
	}
}

func TestTransfer_LargeFile(t *testing.T) {
	track(t, "Transfer")
	input := randomData(t, 500*1024)
	output := transferFile(t, input, "127.0.0.1", 30*time.Second)
	if sha256hex(input) != sha256hex(output) {
		t.Errorf("checksum mismatch: sent %d, received %d", len(input), len(output))
	}
}

func TestTransfer_BinaryAllByteValues(t *testing.T) {
	track(t, "Transfer")
	input := make([]byte, 256*10)
	for i := range input {
		input[i] = byte(i % 256)
	}
	output := transferFile(t, input, "127.0.0.1", 10*time.Second)
	if !bytes.Equal(input, output) {
		t.Error("binary transfer mismatch for all byte values")
	}
}

func TestTransfer_WindowBoundary(t *testing.T) {
	track(t, "Transfer")
	input := randomData(t, 32*1182)
	output := transferFile(t, input, "127.0.0.1", 15*time.Second)
	if sha256hex(input) != sha256hex(output) {
		t.Errorf("checksum mismatch at window boundary")
	}
}

//  I/O Mode Tests 

func TestTransfer_StdinToFile(t *testing.T) {
	track(t, "I/O Modes")
	port := findFreePort(t)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.bin")
	input := []byte("stdin to file transfer test data\n")

	serverCmd := exec.Command(binaryPath, "-s", "-p", fmt.Sprintf("%d", port), "-a", "127.0.0.1", "-o", outputFile, "-w", "5")
	serverCmd.Start()
	time.Sleep(50 * time.Millisecond)

	clientCmd := exec.Command(binaryPath, "-c", "-a", "127.0.0.1", "-p", fmt.Sprintf("%d", port), "-w", "5")
	clientCmd.Stdin = bytes.NewReader(input)
	clientCmd.Start()

	done := make(chan error, 2)
	go func() { done <- clientCmd.Wait() }()
	go func() { done <- serverCmd.Wait() }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				serverCmd.Process.Kill()
				clientCmd.Process.Kill()
				t.Fatalf("process failed: %v", err)
			}
		case <-time.After(15 * time.Second):
			serverCmd.Process.Kill()
			clientCmd.Process.Kill()
			t.Fatal("timed out")
		}
	}
	output, _ := os.ReadFile(outputFile)
	if !bytes.Equal(input, output) {
		t.Errorf("stdin→file mismatch:\ngot:  %q\nwant: %q", output, input)
	}
}

func TestTransfer_FileToStdout(t *testing.T) {
	track(t, "I/O Modes")
	port := findFreePort(t)
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.bin")
	input := []byte("file to stdout transfer test data\n")
	os.WriteFile(inputFile, input, 0644)

	var serverOut bytes.Buffer
	serverCmd := exec.Command(binaryPath, "-s", "-p", fmt.Sprintf("%d", port), "-a", "127.0.0.1", "-w", "5")
	serverCmd.Stdout = &serverOut
	serverCmd.Start()
	time.Sleep(50 * time.Millisecond)

	clientCmd := exec.Command(binaryPath, "-c", "-a", "127.0.0.1", "-p", fmt.Sprintf("%d", port), "-i", inputFile, "-w", "5")
	clientCmd.Start()

	done := make(chan error, 2)
	go func() { done <- clientCmd.Wait() }()
	go func() { done <- serverCmd.Wait() }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				serverCmd.Process.Kill()
				clientCmd.Process.Kill()
				t.Fatalf("process failed: %v", err)
			}
		case <-time.After(15 * time.Second):
			serverCmd.Process.Kill()
			clientCmd.Process.Kill()
			t.Fatal("timed out")
		}
	}
	if !bytes.Equal(input, serverOut.Bytes()) {
		t.Errorf("file→stdout mismatch:\ngot:  %q\nwant: %q", serverOut.Bytes(), input)
	}
}

func TestTransfer_StdinToStdout(t *testing.T) {
	track(t, "I/O Modes")
	port := findFreePort(t)
	input := []byte("stdin to stdout pipe transfer!\n")

	var serverOut bytes.Buffer
	serverCmd := exec.Command(binaryPath, "-s", "-p", fmt.Sprintf("%d", port), "-a", "127.0.0.1", "-w", "5")
	serverCmd.Stdout = &serverOut
	serverCmd.Start()
	time.Sleep(50 * time.Millisecond)

	clientCmd := exec.Command(binaryPath, "-c", "-a", "127.0.0.1", "-p", fmt.Sprintf("%d", port), "-w", "5")
	clientCmd.Stdin = bytes.NewReader(input)
	clientCmd.Start()

	done := make(chan error, 2)
	go func() { done <- clientCmd.Wait() }()
	go func() { done <- serverCmd.Wait() }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				serverCmd.Process.Kill()
				clientCmd.Process.Kill()
				t.Fatalf("process failed: %v", err)
			}
		case <-time.After(15 * time.Second):
			serverCmd.Process.Kill()
			clientCmd.Process.Kill()
			t.Fatal("timed out")
		}
	}
	if !bytes.Equal(input, serverOut.Bytes()) {
		t.Errorf("stdin→stdout mismatch:\ngot:  %q\nwant: %q", serverOut.Bytes(), input)
	}
}

//  IPv6 

func TestTransfer_IPv6(t *testing.T) {
	track(t, "IPv6")
	conn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback not available")
	}
	conn.Close()

	input := randomData(t, 10*1024)
	output := transferFile(t, input, "::1", 15*time.Second)
	if sha256hex(input) != sha256hex(output) {
		t.Error("IPv6 transfer checksum mismatch")
	}
}

//  CLI Validation 

func TestCLI_InvalidArgs(t *testing.T) {
	track(t, "CLI")
	cases := []struct {
		name string
		args []string
	}{
		{"no mode", []string{"-p", "9000"}},
		{"both modes", []string{"-c", "-s", "-p", "9000"}},
		{"no port", []string{"-c", "-a", "127.0.0.1"}},
		{"invalid port", []string{"-c", "-a", "127.0.0.1", "-p", "0"}},
		{"negative port", []string{"-c", "-a", "127.0.0.1", "-p", "-1"}},
		{"port too high", []string{"-c", "-a", "127.0.0.1", "-p", "70000"}},
		{"client no address", []string{"-c", "-p", "9000"}},
		{"negative timeout", []string{"-c", "-a", "127.0.0.1", "-p", "9000", "-w", "-1"}},
		{"zero timeout", []string{"-c", "-a", "127.0.0.1", "-p", "9000", "-w", "0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if exec.Command(binaryPath, tc.args...).Run() == nil {
				t.Errorf("expected non-zero exit for args %v", tc.args)
			}
		})
	}
}

func TestCLI_Help(t *testing.T) {
	track(t, "CLI")
	out, err := exec.Command(binaryPath, "-h").Output()
	if err != nil {
		t.Fatalf("-h should exit 0, got: %v", err)
	}
	if len(out) == 0 {
		t.Error("help output should not be empty")
	}
}

//  Signal Handling 

func TestSignal_CleanExit(t *testing.T) {
	track(t, "Signal")
	port := findFreePort(t)
	serverCmd := exec.Command(binaryPath, "-s", "-p", fmt.Sprintf("%d", port), "-a", "127.0.0.1", "-w", "30")
	serverCmd.Start()
	time.Sleep(100 * time.Millisecond)

	serverCmd.Process.Signal(syscall.SIGTERM)

	done := make(chan error, 1)
	go func() { done <- serverCmd.Wait() }()
	select {
	case <-done:
		// exited promptly — pass
	case <-time.After(3 * time.Second):
		serverCmd.Process.Kill()
		t.Fatal("server did not terminate within 3s of SIGTERM")
	}
}

//  Timeout Behavior 

func TestTimeout_EmptyTransfer(t *testing.T) {
	track(t, "Timeout")
	port := findFreePort(t)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.bin")

	serverCmd := exec.Command(binaryPath, "-s", "-p", fmt.Sprintf("%d", port), "-a", "127.0.0.1", "-o", outputFile, "-w", "2")
	serverCmd.Start()
	time.Sleep(50 * time.Millisecond)

	clientCmd := exec.Command(binaryPath, "-c", "-a", "127.0.0.1", "-p", fmt.Sprintf("%d", port), "-w", "2")
	clientCmd.Stdin = bytes.NewReader([]byte{})
	clientCmd.Start()

	done := make(chan error, 2)
	go func() { done <- clientCmd.Wait() }()
	go func() { done <- serverCmd.Wait() }()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			serverCmd.Process.Kill()
			clientCmd.Process.Kill()
			t.Fatal("hung instead of completing")
		}
	}
}

func TestTimeout_ClientExitsWhenServerDies(t *testing.T) {
	track(t, "Timeout")
	port := findFreePort(t)

	serverCmd := exec.Command(binaryPath, "-s", "-p", fmt.Sprintf("%d", port), "-a", "127.0.0.1", "-w", "2")
	serverCmd.Start()
	time.Sleep(50 * time.Millisecond)

	pr, pw, _ := os.Pipe()
	clientCmd := exec.Command(binaryPath, "-c", "-a", "127.0.0.1", "-p", fmt.Sprintf("%d", port), "-w", "2")
	clientCmd.Stdin = pr
	clientCmd.Start()

	pw.Write(randomData(t, 5000))
	time.Sleep(300 * time.Millisecond)
	serverCmd.Process.Kill()
	serverCmd.Wait()
	pw.Close()

	done := make(chan error, 1)
	go func() { done <- clientCmd.Wait() }()
	select {
	case err := <-done:
		pr.Close()
		if err == nil {
			t.Error("client should exit non-zero when server dies")
		}
	case <-time.After(8 * time.Second):
		pr.Close()
		clientCmd.Process.Kill()
		t.Fatal("client did not terminate after server was killed")
	}
}

//  Network Impairment Proxy 

type udpProxy struct {
	listener   *net.UDPConn
	serverAddr *net.UDPAddr
	lossRate   float64     // 0.0 to 1.0
	delayMs    int         // base delay in ms
	jitterMs   int         // +/- jitter in ms
	done       chan struct{}
}

func newUDPProxy(t *testing.T, serverPort int, lossRate float64, delayMs, jitterMs int) *udpProxy {
	t.Helper()
	listenAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		t.Fatalf("proxy listen failed: %v", err)
	}
	serverAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", serverPort))
	return &udpProxy{
		listener:   conn,
		serverAddr: serverAddr,
		lossRate:   lossRate,
		delayMs:    delayMs,
		jitterMs:   jitterMs,
		done:       make(chan struct{}),
	}
}

func (p *udpProxy) Port() int {
	return p.listener.LocalAddr().(*net.UDPAddr).Port
}

func (p *udpProxy) Start() {
	rng := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	// Track client address (first non-server sender)
	var clientAddr *net.UDPAddr
	buf := make([]byte, 1500)

	go func() {
		for {
			p.listener.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, addr, err := p.listener.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-p.done:
					return
				default:
					continue
				}
			}

			// Simulate loss
			if rng.Float64() < p.lossRate {
				continue
			}

			pkt := make([]byte, n)
			copy(pkt, buf[:n])

			// Determine direction
			var dst *net.UDPAddr
			if addr.String() == p.serverAddr.String() {
				dst = clientAddr
			} else {
				clientAddr = addr
				dst = p.serverAddr
			}
			if dst == nil {
				continue
			}

			// Simulate delay + jitter
			delay := p.delayMs
			if p.jitterMs > 0 {
				delay += rng.Intn(2*p.jitterMs+1) - p.jitterMs
			}
			if delay < 0 {
				delay = 0
			}

			finalDst := dst
			if delay > 0 {
				go func() {
					time.Sleep(time.Duration(delay) * time.Millisecond)
					p.listener.WriteToUDP(pkt, finalDst)
				}()
			} else {
				p.listener.WriteToUDP(pkt, finalDst)
			}
		}
	}()
}

func (p *udpProxy) Stop() {
	close(p.done)
	p.listener.Close()
}

// transferViaProxy runs a transfer through the UDP proxy with network impairment.
func transferViaProxy(t *testing.T, input []byte, lossRate float64, delayMs, jitterMs int, timeout time.Duration) []byte {
	t.Helper()
	serverPort := findFreePort(t)
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.bin")
	outputFile := filepath.Join(tmpDir, "output.bin")
	os.WriteFile(inputFile, input, 0644)

	// Start real server
	serverCmd := exec.Command(binaryPath, "-s", "-p", fmt.Sprintf("%d", serverPort), "-a", "127.0.0.1", "-o", outputFile, "-w", "10")
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Start proxy
	proxy := newUDPProxy(t, serverPort, lossRate, delayMs, jitterMs)
	proxy.Start()

	// Client connects to proxy, not server
	clientCmd := exec.Command(binaryPath, "-c", "-a", "127.0.0.1", "-p", fmt.Sprintf("%d", proxy.Port()), "-i", inputFile, "-w", "10")
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("client start failed: %v", err)
	}

	done := make(chan error, 2)
	go func() { done <- clientCmd.Wait() }()
	go func() { done <- serverCmd.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				serverCmd.Process.Kill()
				clientCmd.Process.Kill()
				proxy.Stop()
				t.Fatalf("process failed: %v", err)
			}
		case <-timer.C:
			serverCmd.Process.Kill()
			clientCmd.Process.Kill()
			proxy.Stop()
			t.Fatalf("transfer timed out after %v", timeout)
		}
	}
	proxy.Stop()

	output, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	return output
}

//  Network Impairment Tests 

func TestNetwork_PacketLoss5(t *testing.T) {
	track(t, "Network")
	input := randomData(t, 50*1024)
	output := transferViaProxy(t, input, 0.05, 0, 0, 60*time.Second)
	if sha256hex(input) != sha256hex(output) {
		t.Errorf("checksum mismatch with 5%% loss: sent %d, received %d", len(input), len(output))
	}
}

func TestNetwork_PacketLoss10(t *testing.T) {
	track(t, "Network")
	input := randomData(t, 50*1024)
	output := transferViaProxy(t, input, 0.10, 0, 0, 60*time.Second)
	if sha256hex(input) != sha256hex(output) {
		t.Errorf("checksum mismatch with 10%% loss: sent %d, received %d", len(input), len(output))
	}
}

func TestNetwork_DelayAndJitter(t *testing.T) {
	track(t, "Network")
	input := randomData(t, 30*1024)
	output := transferViaProxy(t, input, 0.0, 20, 30, 60*time.Second)
	if sha256hex(input) != sha256hex(output) {
		t.Errorf("checksum mismatch with delay+jitter: sent %d, received %d", len(input), len(output))
	}
}
