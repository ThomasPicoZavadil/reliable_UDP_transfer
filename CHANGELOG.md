# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2026-05-03

### Added (Implemented Functionality)
- **3-Way Handshake**: Secure connection establishment (`SYN`, `SYN-ACK`, `ACK`) with randomly generated 32-bit Connection IDs to prevent overlapping session corruption.
- **Graceful Teardown**: Bi-directional connection termination (`FIN`, `FIN-ACK`, `ACK`) implementing a strict `TIME_WAIT` loop bounding to prevent ICMP unreachable errors.
- **Selective Repeat ARQ**: Fully integrated sliding window mechanism (fixed size of 32 packets). Replaces Go-Back-N with explicit tracking of selectively acknowledged segments and contiguous window sliding.
- **Packet Integrity**: 16-bit CRC-CCITT-FALSE checksum calculation mapping across the custom 18-byte header and all appended payload data.
- **Global Progress Timeouts**: Implementation of the `-w` flag. Triggers a strict non-zero exit gracefully interrupting blocking I/O if no valid protocol progress is observed on the network.
- **I/O Routing**: Full support for bidirectional pipe manipulation mapping `stdin` to `stdout` seamlessly alongside standard file stream descriptors.
- **Out-of-Order Caching**: The server explicitly caches out-of-order sequence payloads into a memory map and selectively flushes them sequentially once gaps are satisfied.
- **Dual Stack IP**: Native programmatic interoperability traversing both IPv4 and IPv6 network loops and external environments.
- **Signal Handling**: Robust `SIGINT` and `SIGTERM` OS traps to aggressively terminate and exit processes cleanly.
- **Automated Testing Suite**: A robust internal UDP network proxy simulating explicit 10% packet drops, jitter, and delay, spanning 31 integrated tests evaluating I/O limits, hashes, and protocol unit bounds.

### Known Limitations
There are **no known limitations** preventing the full execution, testing, or operation of the reliable transport protocol as mandated by the project specification.

*Minor architectural notes (not functional limitations):*
- The client does not implement dynamic Congestion Control algorithms (e.g., TCP Tahoe/Reno AIMD) since it operates strictly within the mandated Selective Repeat baseline.

