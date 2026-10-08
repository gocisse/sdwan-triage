package testpcap

import (
	"encoding/binary"
	"io"
	"time"
)

// pcapng block types and constants used by WritePCAPNG.
const (
	ngBlockSectionHeader = 0x0A0D0D0A
	ngBlockInterface     = 0x00000001
	ngBlockEnhancedPkt   = 0x00000006
	ngByteOrderMagic     = 0x1A2B3C4D
)

// pcap link types used by fixtures.
const (
	LinkTypeEthernet       = 1
	LinkTypeRaw            = 101
	LinkTypeEthernetMPkt   = 274 // IEEE 802.3br; not decodable by gopacket
	defaultNGSnapLen       = 65535
	ngMicrosecondsPerSec   = 1000000
	ngSectionLengthUnknown = ^uint64(0)
)

// NGPacket is one packet of a pcapng fixture: the interface it was captured on
// (index into the link-type list given to WritePCAPNG) and its bytes.
type NGPacket struct {
	Interface int
	Data      []byte
}

func ngPad(n int) int { return (4 - n%4) % 4 }

// WritePCAPNG writes a little-endian pcapng stream with one interface
// description block per entry of linkTypes followed by one enhanced packet
// block per packet. Packet i is stamped base + i*interval (microseconds), so
// output is deterministic. No new dependency is used.
func WritePCAPNG(w io.Writer, linkTypes []uint16, packets []NGPacket, base time.Time, interval time.Duration) error {
	le := binary.LittleEndian

	shb := make([]byte, 28)
	le.PutUint32(shb[0:], ngBlockSectionHeader)
	le.PutUint32(shb[4:], 28)
	le.PutUint32(shb[8:], ngByteOrderMagic)
	le.PutUint16(shb[12:], 1)
	le.PutUint16(shb[14:], 0)
	le.PutUint64(shb[16:], ngSectionLengthUnknown)
	le.PutUint32(shb[24:], 28)
	if _, err := w.Write(shb); err != nil {
		return err
	}

	for _, lt := range linkTypes {
		idb := make([]byte, 20)
		le.PutUint32(idb[0:], ngBlockInterface)
		le.PutUint32(idb[4:], 20)
		le.PutUint16(idb[8:], lt)
		le.PutUint32(idb[12:], defaultNGSnapLen)
		le.PutUint32(idb[16:], 20)
		if _, err := w.Write(idb); err != nil {
			return err
		}
	}

	for i, pkt := range packets {
		ts := base.Add(time.Duration(i) * interval)
		us := uint64(ts.Unix())*ngMicrosecondsPerSec + uint64(ts.Nanosecond()/1000)
		padded := len(pkt.Data) + ngPad(len(pkt.Data))
		total := 32 + padded
		blk := make([]byte, total)
		le.PutUint32(blk[0:], ngBlockEnhancedPkt)
		le.PutUint32(blk[4:], uint32(total))
		le.PutUint32(blk[8:], uint32(pkt.Interface))
		le.PutUint32(blk[12:], uint32(us>>32))
		le.PutUint32(blk[16:], uint32(us))
		le.PutUint32(blk[20:], uint32(len(pkt.Data)))
		le.PutUint32(blk[24:], uint32(len(pkt.Data)))
		copy(blk[28:], pkt.Data)
		le.PutUint32(blk[total-4:], uint32(total))
		if _, err := w.Write(blk); err != nil {
			return err
		}
	}
	return nil
}

// EthernetNG wraps Ethernet frames as packets on interface 0.
func EthernetNG(frames [][]byte) []NGPacket {
	out := make([]NGPacket, len(frames))
	for i, f := range frames {
		out[i] = NGPacket{Interface: 0, Data: f}
	}
	return out
}
