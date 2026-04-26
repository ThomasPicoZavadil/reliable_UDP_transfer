package protocol

// CRC16_CCITT calculates a basic CRC-16 checksum using the CCITT-FALSE polynomial (0x1021)
func CRC16_CCITT(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if (crc & 0x8000) != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// CalculateChecksum helper zeroes out the existing checksum fields natively,
// concatenates the header slice and payload slice, builds the checksum,
// and returns the value
func CalculateChecksum(header, payload []byte) uint16 {
	if len(header) < HeaderSize {
		return 0
	}

	// Make a copy of the header
	checkCopy := make([]byte, len(header))
	copy(checkCopy, header)

	// Zero out the checksum field indices
	checkCopy[16] = 0
	checkCopy[17] = 0

	// Validate CRC16 on combined payload
	combined := append(checkCopy, payload...)
	return CRC16_CCITT(combined)
}
