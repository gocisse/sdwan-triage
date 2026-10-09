package detector

import (
	"math"
	"testing"
	"time"
)

var rtpT0 = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// rtpPacket builds an RTP datagram payload: 12-byte header + 10 media bytes.
func rtpPacket(pt uint8, seq uint16, ts, ssrc uint32) []byte {
	b := make([]byte, 22)
	b[0] = 0x80
	b[1] = pt & 0x7F
	b[2], b[3] = byte(seq>>8), byte(seq)
	b[4], b[5], b[6], b[7] = byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts)
	b[8], b[9], b[10], b[11] = byte(ssrc>>24), byte(ssrc>>16), byte(ssrc>>8), byte(ssrc)
	return b
}

type rtpSample struct {
	pt  uint8
	seq uint16
	ts  uint32
	at  time.Duration // arrival offset from rtpT0
}

func feed(a *RTPAnalyzer, ssrc uint32, samples []rtpSample) *RTPStream {
	for _, s := range samples {
		a.parseRTPPacket(rtpPacket(s.pt, s.seq, s.ts, ssrc), "10.0.0.1", "10.0.0.2", 4000, 4002, rtpT0.Add(s.at))
	}
	return a.streams[a.getStreamKey("10.0.0.1", "10.0.0.2", 4000, 4002, ssrc)]
}

// refJitter is the reference RFC 3550 recurrence J += (|D|-J)/16 over |D| values.
func refJitter(ds []float64) float64 {
	j := 0.0
	for _, d := range ds {
		j += (math.Abs(d) - j) / 16
	}
	return j
}

func near(t *testing.T, name string, got, want, tol float64) {
	t.Helper()
	if math.IsNaN(got) || math.IsInf(got, 0) || math.Abs(got-want) > tol {
		t.Errorf("%s = %.17g, want %.17g (tol %g)", name, got, want, tol)
	}
}

// Nine updates of |D| = 16 ticks from J0 = 0.
const (
	jitter9Ticks = 7.049207892501727
	jitter9Ms8k  = 0.8811509865627158
	jitter9Ms90k = 0.07832453213890808
)

func TestRTPClockRates_StaticMapping(t *testing.T) {
	want := map[uint8]uint32{
		0: 8000, 3: 8000, 4: 8000, 5: 8000, 6: 16000, 7: 8000, 8: 8000, 9: 8000,
		10: 44100, 11: 44100, 12: 8000, 13: 8000, 14: 90000, 15: 8000, 16: 11025,
		17: 22050, 18: 8000, 25: 90000, 26: 90000, 28: 90000, 31: 90000,
		32: 90000, 33: 90000, 34: 90000,
	}
	if len(rtpClockRates) != len(want) {
		t.Errorf("clock table has %d entries, want %d", len(rtpClockRates), len(want))
	}
	for pt, hz := range want {
		if rtpClockRates[pt] != hz {
			t.Errorf("PT %d clock = %d, want %d", pt, rtpClockRates[pt], hz)
		}
	}
	// Unassigned/reserved static and every dynamic type: unknown.
	for _, pt := range []uint8{1, 2, 19, 20, 21, 22, 23, 24, 27, 29, 30, 96, 101, 111, 127} {
		if hz, ok := rtpClockRates[pt]; ok {
			t.Errorf("PT %d must have no clock rate, got %d", pt, hz)
		}
	}
}

func TestRTPJitter_Known8kHz(t *testing.T) {
	a := NewRTPAnalyzer()
	var samples []rtpSample
	at := time.Duration(0)
	for i := 0; i < 10; i++ {
		samples = append(samples, rtpSample{0, uint16(100 + i), uint32(1000 + 160*i), at})
		if i%2 == 0 {
			at += 22 * time.Millisecond // +2 ms = +16 ticks
		} else {
			at += 18 * time.Millisecond // -2 ms = -16 ticks
		}
	}
	s := feed(a, 7, samples)
	if s.ClockRate != 8000 || s.JitterSamples != 9 {
		t.Fatalf("clock=%d samples=%d", s.ClockRate, s.JitterSamples)
	}
	near(t, "J ticks", s.Jitter, jitter9Ticks, 1e-9)
	near(t, "closed form", s.Jitter, 16*(1-math.Pow(15.0/16.0, 9)), 1e-9)
	ms, ok := s.JitterMs()
	if !ok {
		t.Fatal("jitter should be available")
	}
	near(t, "jitter ms", ms, jitter9Ms8k, 1e-12)
}

func TestRTPJitter_RecurrenceFirstValues(t *testing.T) {
	if refJitter([]float64{16}) != 1.0 || refJitter([]float64{16, 16}) != 1.9375 {
		t.Error("reference recurrence J1/J2 must be exactly 1.0 and 1.9375")
	}
}

func TestRTPJitter_Known90kHz(t *testing.T) {
	a := NewRTPAnalyzer()
	step := time.Duration(math.Round(3000.0 / 90000.0 * 1e9)) // 33.333... ms
	dev := time.Duration(math.Round(16.0 / 90000.0 * 1e9))    // 16 ticks
	var samples []rtpSample
	var ds []float64
	at := time.Duration(0)
	var prev time.Duration
	for i := 0; i < 10; i++ {
		samples = append(samples, rtpSample{34, uint16(i + 1), uint32(5000 + 3000*i), at})
		if i > 0 {
			ds = append(ds, (at-prev).Seconds()*90000-3000)
		}
		prev = at
		if i%2 == 0 {
			at += step + dev
		} else {
			at += step - dev
		}
	}
	s := feed(a, 8, samples)
	if s.ClockRate != 90000 {
		t.Fatalf("clock = %d", s.ClockRate)
	}
	// Expected from the reference recurrence over the achieved arrival times.
	near(t, "J ticks", s.Jitter, refJitter(ds), 1e-9)
	ms, _ := s.JitterMs()
	near(t, "jitter ms", ms, refJitter(ds)/90000*1000, 1e-12)
	// Nanosecond rounding keeps it within 1e-6 ms of the ideal 16-tick value.
	near(t, "jitter ms vs ideal", ms, jitter9Ms90k, 1e-6)
}

func TestRTPJitter_SameTicksDifferentClocks(t *testing.T) {
	s0 := &RTPStream{ClockRate: rtpClockRates[0], Jitter: jitter9Ticks, JitterSamples: 9}
	s34 := &RTPStream{ClockRate: rtpClockRates[34], Jitter: jitter9Ticks, JitterSamples: 9}
	m0, ok0 := s0.JitterMs()
	m34, ok34 := s34.JitterMs()
	if !ok0 || !ok34 {
		t.Fatal("both must be available")
	}
	near(t, "8k ms", m0, jitter9Ms8k, 1e-12)
	near(t, "90k ms", m34, jitter9Ms90k, 1e-12)
	near(t, "ratio", m0/m34, 90000.0/8000.0, 1e-9)
}

func TestRTPJitter_UnknownClockUnavailable(t *testing.T) {
	for _, pt := range []uint8{1, 19, 96, 101, 111, 127} {
		a := NewRTPAnalyzer()
		var samples []rtpSample
		for i := 0; i < 8; i++ {
			samples = append(samples, rtpSample{pt, uint16(i + 1), uint32(160 * i), time.Duration(i) * 25 * time.Millisecond})
		}
		s := feed(a, 9, samples)
		if _, ok := s.JitterMs(); ok {
			t.Errorf("PT %d: jitter must be unavailable", pt)
		}
		if s.Jitter != 0 || s.JitterSamples != 0 {
			t.Errorf("PT %d: unknown clock must not accumulate (J=%v samples=%d)", pt, s.Jitter, s.JitterSamples)
		}
		if s.PacketCount != 8 {
			t.Errorf("PT %d: packet counting must be unchanged, got %d", pt, s.PacketCount)
		}
	}
}

func TestRTPJitter_ZeroIsMeasuredNotUnavailable(t *testing.T) {
	a := NewRTPAnalyzer()
	var samples []rtpSample
	for i := 0; i < 6; i++ {
		samples = append(samples, rtpSample{0, uint16(i + 1), uint32(160 * i), time.Duration(i) * 20 * time.Millisecond})
	}
	s := feed(a, 10, samples)
	ms, ok := s.JitterMs()
	if !ok || ms != 0 {
		t.Errorf("perfectly regular stream: got (%v,%v), want (0,true)", ms, ok)
	}
}

func TestRTPJitter_InsufficientPackets(t *testing.T) {
	a := NewRTPAnalyzer()
	s := feed(a, 11, []rtpSample{{0, 1, 0, 0}})
	if _, ok := s.JitterMs(); ok {
		t.Error("a single packet must have no jitter")
	}
	feed(a, 11, []rtpSample{{0, 2, 160, 20 * time.Millisecond}, {0, 3, 320, 40 * time.Millisecond}, {0, 4, 480, 60 * time.Millisecond}})
	if len(a.GetStreams()) != 0 {
		t.Error("streams below the 5-packet minimum must stay suppressed")
	}
	feed(a, 11, []rtpSample{{0, 5, 640, 80 * time.Millisecond}})
	if len(a.GetStreams()) != 1 {
		t.Error("5 packets must be kept")
	}
}

// oneUpdate feeds two packets and returns the stream after a single jitter update.
func oneUpdate(pt uint8, lastTS, ts uint32, gap time.Duration) *RTPStream {
	a := NewRTPAnalyzer()
	return feed(a, 12, []rtpSample{{pt, 1, lastTS, 0}, {pt, 2, ts, gap}})
}

func TestRTPJitter_TimestampArithmetic(t *testing.T) {
	cases := []struct {
		name      string
		last, ts  uint32
		gap       time.Duration
		wantDelta float64
		wantJ     float64
	}{
		{"forward", 1000, 1160, 20 * time.Millisecond, 160, 0},
		{"rollover regular", 4294967040, 96, 44 * time.Millisecond, 352, 0},
		{"rollover with 20ms arrival", 4294967040, 96, 20 * time.Millisecond, 352, 12.0},
		{"earlier timestamp", 1160, 1000, 20 * time.Millisecond, -160, 20.0},
		{"reset forward", 1160, 9000000, 20 * time.Millisecond, 8998840, 562417.5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := oneUpdate(0, c.last, c.ts, c.gap)
			if got := float64(int32(c.ts - c.last)); got != c.wantDelta {
				t.Fatalf("tsDelta = %v, want %v", got, c.wantDelta)
			}
			near(t, "J", s.Jitter, c.wantJ, 1e-9)
			if s.Jitter < 0 || s.Jitter > 1e6 {
				t.Errorf("unsigned-wrap artifact in J: %v", s.Jitter)
			}
		})
	}
}

func TestRTPJitter_ResetDecaysWithoutArtifacts(t *testing.T) {
	a := NewRTPAnalyzer()
	samples := []rtpSample{{0, 1, 1160, 0}, {0, 2, 9000000, 20 * time.Millisecond}}
	for i := 0; i < 16; i++ {
		samples = append(samples, rtpSample{0, uint16(3 + i), uint32(9000000 + 160*(i+1)), time.Duration(40+20*i) * time.Millisecond})
	}
	s := feed(a, 13, samples)
	want := 562417.5 * math.Pow(15.0/16.0, 16)
	near(t, "decayed J", s.Jitter, want, 1e-3)
	if math.IsNaN(s.Jitter) || math.IsInf(s.Jitter, 0) {
		t.Error("J must be finite")
	}
}

func TestRTPJitter_TimestampDeltaBoundaries(t *testing.T) {
	for _, c := range []struct {
		name     string
		ts       uint32
		wantDiff float64
	}{
		{"+2^31-1", 2147483647, 2147483647},
		{"-2^31", 2147483648, -2147483648},
	} {
		t.Run(c.name, func(t *testing.T) {
			gap := 20 * time.Millisecond
			s := oneUpdate(0, 0, c.ts, gap)
			arrival := gap.Seconds() * 8000
			want := math.Abs(arrival-c.wantDiff) / 16
			near(t, "J1", s.Jitter, want, 1e-9)
			if s.Jitter < 0 || math.IsInf(s.Jitter, 0) || math.IsNaN(s.Jitter) {
				t.Errorf("J1 not finite/non-negative: %v", s.Jitter)
			}
		})
	}
}

func TestRTPJitter_LargeArrivalGapIsNotCapped(t *testing.T) {
	s := oneUpdate(0, 1000, 1160, time.Hour)
	near(t, "J", s.Jitter, 1799990.0, 1e-6) // (3600*8000-160)/16
	if s.JitterSamples != 1 {
		t.Errorf("large gaps are not skipped, samples=%d", s.JitterSamples)
	}
}

func TestRTPJitter_ForeignPayloadType(t *testing.T) {
	a := NewRTPAnalyzer()
	s := feed(a, 14, []rtpSample{
		{0, 1, 1000, 0},
		{0, 2, 1160, 20 * time.Millisecond}, // D=0
		{96, 3, 900000, 25 * time.Millisecond},
		{0, 4, 1480, 60 * time.Millisecond}, // compared to the seq-2 packet: 40ms=320 ticks vs ts +320 => D=0
	})
	if s.PacketCount != 4 {
		t.Errorf("PacketCount = %d, want 4 (foreign PT still counted)", s.PacketCount)
	}
	if s.JitterSamples != 2 {
		t.Errorf("JitterSamples = %d, want 2 (foreign PT excluded)", s.JitterSamples)
	}
	if s.Jitter != 0 {
		t.Errorf("J = %v, want 0", s.Jitter)
	}
	if s.LastTimestamp != 1480 {
		t.Errorf("LastTimestamp = %d", s.LastTimestamp)
	}
	if s.PayloadType != 0 || s.ClockRate != 8000 {
		t.Errorf("initial PT/clock must be kept, got %d/%d", s.PayloadType, s.ClockRate)
	}

	// The reference point is not moved by the foreign packet: change the foreign
	// packet's arrival so a wrongly-moved reference would give a different D.
	b := NewRTPAnalyzer()
	sb := feed(b, 14, []rtpSample{
		{0, 1, 1000, 0},
		{96, 2, 70000, 10 * time.Millisecond},
		{0, 3, 1320, 40 * time.Millisecond}, // 40ms = 320 ticks vs +320 => D=0
	})
	if sb.JitterSamples != 1 || sb.Jitter != 0 {
		t.Errorf("reference moved by foreign PT: samples=%d J=%v", sb.JitterSamples, sb.Jitter)
	}

	// Dynamic first, static later: stays unavailable.
	c := NewRTPAnalyzer()
	var sc []rtpSample
	sc = append(sc, rtpSample{96, 1, 0, 0})
	for i := 1; i < 6; i++ {
		sc = append(sc, rtpSample{0, uint16(i + 1), uint32(160 * i), time.Duration(i) * 20 * time.Millisecond})
	}
	if _, ok := feed(c, 15, sc).JitterMs(); ok {
		t.Error("stream starting with a dynamic PT must stay unavailable")
	}

	// Static first, then a different static PT: only initial-PT samples count.
	d := NewRTPAnalyzer()
	sd := feed(d, 16, []rtpSample{{0, 1, 0, 0}, {0, 2, 160, 20 * time.Millisecond}, {8, 3, 320, 40 * time.Millisecond}, {8, 4, 480, 60 * time.Millisecond}})
	if sd.JitterSamples != 1 {
		t.Errorf("PCMU->PCMA: samples=%d, want 1", sd.JitterSamples)
	}
}

func TestRTPJitter_LossLogicUnchangedByForeignPT(t *testing.T) {
	a := NewRTPAnalyzer()
	s := feed(a, 17, []rtpSample{{0, 1, 0, 0}, {96, 5, 0, 10 * time.Millisecond}})
	if s.LostPackets != 3 || s.LastSeq != 5 {
		t.Errorf("loss=%d lastSeq=%d, want 3/5", s.LostPackets, s.LastSeq)
	}
}

func TestRTPJitter_Deterministic(t *testing.T) {
	run := func() (float64, bool) {
		a := NewRTPAnalyzer()
		var samples []rtpSample
		for i := 0; i < 20; i++ {
			samples = append(samples, rtpSample{8, uint16(i + 1), uint32(160 * i), time.Duration(i*20+(i%3)) * time.Millisecond})
		}
		return feed(a, 18, samples).JitterMs()
	}
	m1, ok1 := run()
	for i := 0; i < 5; i++ {
		if m, ok := run(); m != m1 || ok != ok1 {
			t.Fatal("non-deterministic jitter")
		}
	}
}

func TestRTPStreamStats_AveragesOnlyAvailable(t *testing.T) {
	a := NewRTPAnalyzer()
	mk := func(ssrc uint32, pt uint8, wobbleMs int) {
		var samples []rtpSample
		for i := 0; i < 6; i++ {
			w := 0
			if i%2 == 1 {
				w = wobbleMs
			}
			samples = append(samples, rtpSample{pt, uint16(i + 1), uint32(160 * i), time.Duration(i*20+w) * time.Millisecond})
		}
		feed(a, ssrc, samples)
	}
	mk(20, 0, 1)
	mk(21, 0, 3)
	mk(22, 96, 50)
	_, _, _, _, avg := a.GetStreamStats()
	var want float64
	for _, k := range []uint32{20, 21} {
		ms, ok := a.streams[a.getStreamKey("10.0.0.1", "10.0.0.2", 4000, 4002, k)].JitterMs()
		if !ok {
			t.Fatal("expected available")
		}
		want += ms / 2
	}
	near(t, "avg", avg, want, 1e-12)
}
