package events

import "time"

// Recorder is the Emitter used by the analysis pipeline. It assigns dense IDs
// in emission order, stamps events that omit timestamp/packet information with
// the packet currently being analysed, and stores them in an Index.
//
// The pipeline calls SetCurrentPacket before running detectors on each packet;
// finalize-time emitters (run after the last packet) see the last packet as
// "current", so they must set Timestamp explicitly from their recorded history.
type Recorder struct {
	index   *Index
	nextID  uint64
	capture string

	curIndex uint64
	curTime  time.Time
	haveCur  bool

	rejected int // events with no usable capture timestamp
}

// NewRecorder creates a Recorder writing to index. capture labels the source
// capture on every event ("" for single-capture analysis).
func NewRecorder(index *Index, capture string) *Recorder {
	return &Recorder{index: index, nextID: 1, capture: capture}
}

// SetCurrentPacket records the ordinal and capture timestamp of the packet
// about to be analysed. Detectors that emit without a Timestamp/PacketRef get
// these values.
func (r *Recorder) SetCurrentPacket(index uint64, ts time.Time) {
	r.curIndex, r.curTime, r.haveCur = index, ts, true
}

// Emit implements Emitter.
func (r *Recorder) Emit(e Event) {
	if e.Timestamp.IsZero() {
		if !r.haveCur || r.curTime.IsZero() {
			// No capture time available: refusing to invent one (never wall clock).
			r.rejected++
			return
		}
		e.Timestamp = r.curTime
	}
	if len(e.Packets) == 0 && r.haveCur && e.Timestamp.Equal(r.curTime) {
		e.Packets = []PacketRef{{Index: r.curIndex, Timestamp: r.curTime}}
	}
	if e.Capture == "" {
		e.Capture = r.capture
	}
	e.ID = r.nextID
	r.nextID++
	r.index.Add(e)
}

// Index returns the underlying index.
func (r *Recorder) Index() *Index { return r.index }

// Rejected returns how many events were discarded for lacking a capture timestamp.
func (r *Recorder) Rejected() int { return r.rejected }
