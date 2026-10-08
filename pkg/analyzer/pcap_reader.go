package analyzer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ─── Unified PCAP/pcapng Reader ─────────────────────────────────

// CaptureFormat identifies the packet capture file format.
type CaptureFormat string

const (
	FormatPCAP   CaptureFormat = "pcap"
	FormatPCAPNG CaptureFormat = "pcapng"
)

// Magic bytes for format detection.
const (
	pcapMagicBE uint32 = 0xA1B2C3D4 // pcap big-endian
	pcapMagicLE uint32 = 0xD4C3B2A1 // pcap little-endian
	pcapMagicNS uint32 = 0xA1B23C4D // pcap nanosecond-resolution big-endian
	pcapMagicNL uint32 = 0x4D3CB2A1 // pcap nanosecond-resolution little-endian
	pcapngMagic uint32 = 0x0A0D0D0A // pcapng Section Header Block
)

// PacketReader is the minimal interface satisfied by both
// pcapgo.Reader (pcap) and pcapgo.NgReader (pcapng).
type PacketReader interface {
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	LinkType() layers.LinkType
}

// CaptureHandle bundles the reader, detected format, and the
// underlying file so the caller can defer file.Close().
type CaptureHandle struct {
	Reader PacketReader
	Format CaptureFormat
	File   *os.File
}

// Close closes the underlying file.
func (h *CaptureHandle) Close() error {
	if h.File != nil {
		return h.File.Close()
	}
	return nil
}

// OpenCapture opens a packet capture file, auto-detects the format
// (pcap vs pcapng) via magic bytes, and returns the appropriate reader.
//
// The caller owns the CaptureHandle and must call h.Close() when done.
func OpenCapture(filePath string) (*CaptureHandle, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open capture file: %w", err)
	}

	format, err := detectFormat(f)
	if err != nil {
		f.Close()
		return nil, err
	}

	// Seek back to start so the reader sees the full file.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to seek: %w", err)
	}

	handle := &CaptureHandle{File: f, Format: format}

	switch format {
	case FormatPCAPNG:
		ngReader, err := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{
			WantMixedLinkType: true,
		})
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("failed to create pcapng reader: %w", err)
		}
		handle.Reader = ngReader

	default: // FormatPCAP
		pcapReader, err := pcapgo.NewReader(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("failed to create pcap reader: %w", err)
		}
		handle.Reader = pcapReader
	}

	return handle, nil
}

// PacketLinkType returns the link type that must be used to decode the packet
// described by ci. pcapng files are opened with WantMixedLinkType, in which
// case NgReader.LinkType() is meaningless (zero value, i.e. LinkTypeNull) and
// the packet's own interface link type is carried in ci.AncillaryData[0].
// perPacket reports whether the link type came from the packet itself; for
// classic pcap (no ancillary data) the reader-wide link type is returned
// unchanged and perPacket is false.
//
// Note: gopacket's layers.LinkType is a uint8, so pcapng link types >= 256
// (e.g. 274, IEEE 802.3br mPackets) arrive truncated (274 -> 18).
func PacketLinkType(r PacketReader, ci gopacket.CaptureInfo) (lt layers.LinkType, perPacket bool) {
	if len(ci.AncillaryData) > 0 {
		if v, ok := ci.AncillaryData[0].(layers.LinkType); ok {
			return v, true
		}
	}
	return r.LinkType(), false
}

// IsSupportedLinkType reports whether packets of this (per-packet, pcapng)
// link type are decoded by the analyzer. Anything else is counted as
// unsupported and never handed to the detectors.
func IsSupportedLinkType(lt layers.LinkType) bool {
	switch lt {
	case layers.LinkTypeEthernet, layers.LinkTypeRaw, layers.LinkTypeIPv4,
		layers.LinkTypeIPv6, layers.LinkTypeLinuxSLL:
		return true
	}
	return false
}

// LinkTypeLabel renders a link type for user-facing messages.
func LinkTypeLabel(lt layers.LinkType) string {
	if lt == 18 {
		// gopacket truncates pcapng link type 274 (IEEE 802.3br mPackets) to 18.
		return "18 (pcapng link type 274, IEEE 802.3br mPackets, truncated by the decoder library)"
	}
	return fmt.Sprintf("%d", uint8(lt))
}

// OpenCaptureFromReader creates a PacketReader from an io.Reader when
// the magic bytes have already been consumed (e.g. bytes.Buffer in tests).
// It always creates a pcap reader for backward compatibility with tests.
func OpenCaptureFromReader(r io.Reader) (PacketReader, error) {
	return pcapgo.NewReader(r)
}

// detectFormat reads the first 4 bytes of a file to determine the
// capture format. The caller should seek back to 0 after this call.
func detectFormat(f *os.File) (CaptureFormat, error) {
	var magic uint32
	if err := binary.Read(f, binary.BigEndian, &magic); err != nil {
		return "", fmt.Errorf("failed to read magic bytes (file may be empty or corrupt): %w", err)
	}

	switch magic {
	case pcapMagicBE, pcapMagicLE, pcapMagicNS, pcapMagicNL:
		return FormatPCAP, nil
	case pcapngMagic:
		return FormatPCAPNG, nil
	default:
		return "", fmt.Errorf("unrecognised capture format (magic: 0x%08X). Expected .pcap or .pcapng", magic)
	}
}

// DetectCaptureFormat returns the format of a capture file without
// opening a full reader. Useful for UI/metadata display.
func DetectCaptureFormat(filePath string) (CaptureFormat, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return detectFormat(f)
}
