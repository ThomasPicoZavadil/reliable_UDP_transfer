package protocol

import (
	"encoding/binary"
	"errors"
)

const HeaderSize = 18

const (
	FlagSYN byte = 1 << 0
	FlagACK byte = 1 << 1
	FlagFIN byte = 1 << 2
)

type Header struct {
	ConnectionID uint32
	SeqNum       uint32
	AckNum       uint32
	Flags        byte
	Padding      byte
	Length       uint16 // Size of the payload data
	Checksum     uint16 // CRC16 of header + payload
}

// Encode packs the Header into a newly allocated byte slice
func (h *Header) Encode() []byte {
	b := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(b[0:4], h.ConnectionID)
	binary.BigEndian.PutUint32(b[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(b[8:12], h.AckNum)
	b[12] = h.Flags
	b[13] = h.Padding
	binary.BigEndian.PutUint16(b[14:16], h.Length)
	binary.BigEndian.PutUint16(b[16:18], h.Checksum)
	return b
}

// Decode unpacks the Header fields from the given byte slice
func (h *Header) Decode(b []byte) error {
	if len(b) < HeaderSize {
		return errors.New("buffer too small for header")
	}
	h.ConnectionID = binary.BigEndian.Uint32(b[0:4])
	h.SeqNum = binary.BigEndian.Uint32(b[4:8])
	h.AckNum = binary.BigEndian.Uint32(b[8:12])
	h.Flags = b[12]
	h.Padding = b[13]
	h.Length = binary.BigEndian.Uint16(b[14:16])
	h.Checksum = binary.BigEndian.Uint16(b[16:18])
	return nil
}
