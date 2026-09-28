package events

import (
	"sort"
	"time"
)

// DefaultMaxEvents bounds an Index created with NewIndex(0). Events are small
// (~250 B plus attrs), so 100k events is on the order of 30–40 MB worst case.
const DefaultMaxEvents = 100000

// Index is an in-memory, bounded, chronologically ordered store of Events.
//
// Ordering: events are kept sorted by (Timestamp, ID). Detectors mostly emit in
// packet order, but finalize-time emitters (e.g. "unanswered query") legitimately
// produce events timestamped in the past, so sorting is performed lazily on the
// first query after a write. Ties are broken by ID, which makes the order fully
// deterministic for a given capture.
//
// Bound: when Len() reaches the capacity, further Add calls are rejected and
// counted in Dropped(). Nothing is evicted — the earliest observations are the
// ones a correlation stage most needs to explain what happened first.
//
// Index is not safe for concurrent use; the analysis pipeline is single-threaded.
type Index struct {
	capacity int
	events   []Event
	sorted   bool
	byKind   map[Kind][]int // positions into events, valid when sorted
	dropped  int
}

// NewIndex creates an index holding at most capacity events (0 → DefaultMaxEvents).
func NewIndex(capacity int) *Index {
	if capacity <= 0 {
		capacity = DefaultMaxEvents
	}
	return &Index{capacity: capacity, sorted: true, byKind: make(map[Kind][]int)}
}

// Add stores e. Returns false if the index is full (the event is dropped).
func (ix *Index) Add(e Event) bool {
	if len(ix.events) >= ix.capacity {
		ix.dropped++
		return false
	}
	if ix.sorted && len(ix.events) > 0 {
		last := ix.events[len(ix.events)-1]
		if e.Timestamp.Before(last.Timestamp) || (e.Timestamp.Equal(last.Timestamp) && e.ID < last.ID) {
			ix.sorted = false
		}
	}
	ix.events = append(ix.events, e)
	if ix.sorted {
		ix.byKind[e.Kind] = append(ix.byKind[e.Kind], len(ix.events)-1)
	}
	return true
}

// Len returns the number of stored events.
func (ix *Index) Len() int { return len(ix.events) }

// Cap returns the maximum number of events the index will store.
func (ix *Index) Cap() int { return ix.capacity }

// Dropped returns how many events were rejected because the index was full.
func (ix *Index) Dropped() int { return ix.dropped }

// Events returns all events in chronological order. The slice is shared with
// the index and must not be modified.
func (ix *Index) Events() []Event {
	ix.ensureSorted()
	return ix.events
}

// ByTime returns events with start <= Timestamp <= end (inclusive both ends).
func (ix *Index) ByTime(start, end time.Time) []Event {
	ix.ensureSorted()
	lo, hi := ix.timeRange(start, end)
	return ix.events[lo:hi]
}

// ByKind returns all events of the given kind in chronological order.
func (ix *Index) ByKind(kind Kind) []Event {
	ix.ensureSorted()
	pos := ix.byKind[kind]
	if len(pos) == 0 {
		return nil
	}
	out := make([]Event, len(pos))
	for i, p := range pos {
		out[i] = ix.events[p]
	}
	return out
}

// ByKindAndTime returns events of kind with start <= Timestamp <= end.
func (ix *Index) ByKindAndTime(kind Kind, start, end time.Time) []Event {
	ix.ensureSorted()
	lo, hi := ix.timeRange(start, end)
	pos := ix.byKind[kind]
	// positions are ascending; binary-search the window.
	i := sort.SearchInts(pos, lo)
	var out []Event
	for ; i < len(pos) && pos[i] < hi; i++ {
		out = append(out, ix.events[pos[i]])
	}
	return out
}

// Counts returns the number of events per kind.
func (ix *Index) Counts() map[Kind]int {
	counts := make(map[Kind]int, len(ix.byKind))
	for _, e := range ix.events {
		counts[e.Kind]++
	}
	return counts
}

// timeRange returns [lo, hi) positions covering start <= ts <= end.
func (ix *Index) timeRange(start, end time.Time) (int, int) {
	n := len(ix.events)
	lo := sort.Search(n, func(i int) bool { return !ix.events[i].Timestamp.Before(start) })
	hi := sort.Search(n, func(i int) bool { return ix.events[i].Timestamp.After(end) })
	if hi < lo {
		hi = lo
	}
	return lo, hi
}

func (ix *Index) ensureSorted() {
	if ix.sorted {
		return
	}
	sort.SliceStable(ix.events, func(i, j int) bool {
		a, b := ix.events[i], ix.events[j]
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		return a.ID < b.ID
	})
	ix.byKind = make(map[Kind][]int)
	for i, e := range ix.events {
		ix.byKind[e.Kind] = append(ix.byKind[e.Kind], i)
	}
	ix.sorted = true
}
