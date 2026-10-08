package analyzer

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ErrNoDecodablePackets is returned by Processor.Process when a capture
// contained packets but none of them could be decoded. Callers must report the
// error instead of producing a health verdict: an undecoded capture says
// nothing about the network.
var ErrNoDecodablePackets = errors.New("capture contains packets but none could be decoded")

// decodeStats accounts for what happened to every packet read from a capture.
// It is bounded (one map keyed by link type, at most 256 entries) and
// deterministic. It is deliberately not part of models.TriageReport.
type decodeStats struct {
	read        int                     // packets returned by the reader
	decoded     int                     // packets decoded without a decode error
	failed      int                     // packets of a supported link type with a decode error
	unsupported map[layers.LinkType]int // packets skipped because their link type is unsupported
}

func (d *decodeStats) addUnsupported(lt layers.LinkType) {
	if d.unsupported == nil {
		d.unsupported = make(map[layers.LinkType]int)
	}
	d.unsupported[lt]++
}

// record classifies a packet created with a supported link type. A packet
// counts as decoded when its link or network layer was decoded: unknown upper
// protocols (unrecognised EtherType, unsupported application layers) are normal
// traffic, not a decoding failure of the capture.
func (d *decodeStats) record(pkt gopacket.Packet) {
	if pkt.LinkLayer() != nil || pkt.NetworkLayer() != nil {
		d.decoded++
		return
	}
	d.failed++
}

func (d *decodeStats) unsupportedTotal() int {
	n := 0
	for _, c := range d.unsupported {
		n += c
	}
	return n
}

// describeUnsupported lists unsupported link types in ascending order.
func (d *decodeStats) describeUnsupported() string {
	keys := make([]int, 0, len(d.unsupported))
	for lt := range d.unsupported {
		keys = append(keys, int(lt))
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		lt := layers.LinkType(k)
		parts = append(parts, fmt.Sprintf("link type %s: %d packets", LinkTypeLabel(lt), d.unsupported[lt]))
	}
	return strings.Join(parts, "; ")
}

func (d *decodeStats) noDecodableError() error {
	msg := fmt.Sprintf("%d packets read, 0 could be decoded", d.read)
	if len(d.unsupported) > 0 {
		msg += " (unsupported " + d.describeUnsupported() + ")"
	} else if d.failed > 0 {
		msg += fmt.Sprintf(" (%d decode failures)", d.failed)
	}
	return fmt.Errorf("%w: %s; no analysis was performed", ErrNoDecodablePackets, msg)
}

// DecodeSummary is a read-only snapshot of the processor's decode accounting
// for the most recent Process call.
type DecodeSummary struct {
	PacketsRead         int
	PacketsDecoded      int
	DecodeFailed        int
	PacketsUnsupported  int
	UnsupportedByType   map[layers.LinkType]int
	UnsupportedDescribe string // deterministic, e.g. "link type 18 (...): 10667 packets"
}

// DecodeSummary returns the decode accounting of the last Process call.
func (p *Processor) DecodeSummary() DecodeSummary {
	byType := make(map[layers.LinkType]int, len(p.decode.unsupported))
	for k, v := range p.decode.unsupported {
		byType[k] = v
	}
	return DecodeSummary{
		PacketsRead:         p.decode.read,
		PacketsDecoded:      p.decode.decoded,
		DecodeFailed:        p.decode.failed,
		PacketsUnsupported:  p.decode.unsupportedTotal(),
		UnsupportedByType:   byType,
		UnsupportedDescribe: p.decode.describeUnsupported(),
	}
}

// PartialDecodeNotice returns a user-facing warning when some packets were
// skipped because of an unsupported link type, or "" if there is nothing to say.
func (s DecodeSummary) PartialDecodeNotice() string {
	if s.PacketsUnsupported == 0 {
		return ""
	}
	pct := 100 * float64(s.PacketsUnsupported) / float64(s.PacketsRead)
	return fmt.Sprintf("%d of %d packets (%.1f%%) use an unsupported link type and were NOT analyzed (%s); results cover only the %d decoded packets",
		s.PacketsUnsupported, s.PacketsRead, pct, s.UnsupportedDescribe, s.PacketsDecoded)
}
