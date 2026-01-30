package analyzer

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// WorkerPool manages parallel stream analysis
type WorkerPool struct {
	workerCount int
	taskQueue   chan *AnalysisTask
	resultQueue chan *AnalysisResult
	workers     []*Worker
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc

	// Shared analyzers (thread-safe)
	classifier    *AdvancedClassifier
	healthScorer  *HealthScorer
	issueDetector *IssueDetector

	// Statistics
	stats WorkerPoolStats
}

// WorkerPoolStats tracks worker pool performance
type WorkerPoolStats struct {
	TasksSubmitted    uint64
	TasksCompleted    uint64
	TasksFailed       uint64
	TotalProcessingMs int64
	AvgProcessingMs   float64
	ActiveWorkers     int32
	QueueDepth        int32
}

// AnalysisTask represents a stream to analyze
type AnalysisTask struct {
	Stream      *models.StreamData
	Priority    int // Higher = more urgent
	SubmittedAt time.Time
	Callback    func(*AnalysisResult)
}

// AnalysisResult contains the analysis output
type AnalysisResult struct {
	Stream           *models.StreamData
	Classification   ServiceClassification
	HealthScore      HealthScore
	Issues           []DetectedIssue
	ProcessingTimeMs int64
	Error            error
}

// Worker processes analysis tasks
type Worker struct {
	id       int
	pool     *WorkerPool
	taskChan chan *AnalysisTask
	quit     chan struct{}
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workerCount int) *WorkerPool {
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}

	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workerCount:   workerCount,
		taskQueue:     make(chan *AnalysisTask, workerCount*100),
		resultQueue:   make(chan *AnalysisResult, workerCount*100),
		workers:       make([]*Worker, workerCount),
		ctx:           ctx,
		cancel:        cancel,
		classifier:    NewAdvancedClassifier(),
		healthScorer:  NewHealthScorer(),
		issueDetector: NewIssueDetector(),
	}

	// Create workers
	for i := 0; i < workerCount; i++ {
		pool.workers[i] = &Worker{
			id:       i,
			pool:     pool,
			taskChan: make(chan *AnalysisTask, 10),
			quit:     make(chan struct{}),
		}
	}

	return pool
}

// Start begins processing tasks
func (wp *WorkerPool) Start() {
	for _, worker := range wp.workers {
		wp.wg.Add(1)
		go worker.run()
	}

	// Start dispatcher
	go wp.dispatch()
}

// Stop gracefully shuts down the worker pool
func (wp *WorkerPool) Stop() {
	wp.cancel()

	// Signal all workers to stop
	for _, worker := range wp.workers {
		close(worker.quit)
	}

	// Wait for workers to finish
	wp.wg.Wait()

	// Close channels
	close(wp.taskQueue)
	close(wp.resultQueue)
}

// Submit adds a task to the queue
func (wp *WorkerPool) Submit(task *AnalysisTask) {
	task.SubmittedAt = time.Now()
	atomic.AddUint64(&wp.stats.TasksSubmitted, 1)
	atomic.AddInt32(&wp.stats.QueueDepth, 1)

	select {
	case wp.taskQueue <- task:
	case <-wp.ctx.Done():
		return
	}
}

// SubmitBatch submits multiple tasks efficiently
func (wp *WorkerPool) SubmitBatch(tasks []*AnalysisTask) {
	for _, task := range tasks {
		wp.Submit(task)
	}
}

// Results returns the result channel for consuming results
func (wp *WorkerPool) Results() <-chan *AnalysisResult {
	return wp.resultQueue
}

// dispatch distributes tasks to workers
func (wp *WorkerPool) dispatch() {
	workerIndex := 0

	for {
		select {
		case <-wp.ctx.Done():
			return
		case task, ok := <-wp.taskQueue:
			if !ok {
				return
			}

			// Round-robin distribution
			worker := wp.workers[workerIndex]
			workerIndex = (workerIndex + 1) % wp.workerCount

			select {
			case worker.taskChan <- task:
			case <-wp.ctx.Done():
				return
			}
		}
	}
}

// run is the worker's main loop
func (w *Worker) run() {
	defer w.pool.wg.Done()

	for {
		select {
		case <-w.quit:
			return
		case <-w.pool.ctx.Done():
			return
		case task, ok := <-w.taskChan:
			if !ok {
				return
			}

			atomic.AddInt32(&w.pool.stats.ActiveWorkers, 1)
			result := w.processTask(task)
			atomic.AddInt32(&w.pool.stats.ActiveWorkers, -1)

			// Send result
			select {
			case w.pool.resultQueue <- result:
			case <-w.pool.ctx.Done():
				return
			}

			// Call callback if provided
			if task.Callback != nil {
				task.Callback(result)
			}
		}
	}
}

// processTask analyzes a single stream
func (w *Worker) processTask(task *AnalysisTask) *AnalysisResult {
	startTime := time.Now()
	atomic.AddInt32(&w.pool.stats.QueueDepth, -1)

	result := &AnalysisResult{
		Stream: task.Stream,
	}

	defer func() {
		if r := recover(); r != nil {
			result.Error = &AnalysisError{Message: "panic during analysis"}
			atomic.AddUint64(&w.pool.stats.TasksFailed, 1)
		}
	}()

	// Classify stream
	result.Classification = w.pool.classifier.ClassifyStream(task.Stream)

	// Score health
	result.HealthScore = w.pool.healthScorer.ScoreStream(task.Stream)

	// Detect issues (skip for healthy streams to save processing)
	if result.HealthScore.Score < 90 {
		result.Issues = w.pool.issueDetector.DetectIssues(task.Stream)
	}

	// Calculate processing time
	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
	atomic.AddInt64(&w.pool.stats.TotalProcessingMs, result.ProcessingTimeMs)
	atomic.AddUint64(&w.pool.stats.TasksCompleted, 1)

	return result
}

// AnalysisError represents an analysis error
type AnalysisError struct {
	Message string
}

func (e *AnalysisError) Error() string {
	return e.Message
}

// GetStats returns current worker pool statistics
func (wp *WorkerPool) GetStats() WorkerPoolStats {
	completed := atomic.LoadUint64(&wp.stats.TasksCompleted)
	totalMs := atomic.LoadInt64(&wp.stats.TotalProcessingMs)

	avgMs := float64(0)
	if completed > 0 {
		avgMs = float64(totalMs) / float64(completed)
	}

	return WorkerPoolStats{
		TasksSubmitted:    atomic.LoadUint64(&wp.stats.TasksSubmitted),
		TasksCompleted:    completed,
		TasksFailed:       atomic.LoadUint64(&wp.stats.TasksFailed),
		TotalProcessingMs: totalMs,
		AvgProcessingMs:   avgMs,
		ActiveWorkers:     atomic.LoadInt32(&wp.stats.ActiveWorkers),
		QueueDepth:        atomic.LoadInt32(&wp.stats.QueueDepth),
	}
}

// AnalyzeStreamsParallel analyzes multiple streams in parallel
func AnalyzeStreamsParallel(streams []*models.StreamData, workerCount int) []*AnalysisResult {
	if len(streams) == 0 {
		return nil
	}

	pool := NewWorkerPool(workerCount)
	pool.Start()
	defer pool.Stop()

	// Submit all tasks
	var resultsMu sync.Mutex
	results := make([]*AnalysisResult, 0, len(streams))
	var wg sync.WaitGroup

	for _, stream := range streams {
		wg.Add(1)
		task := &AnalysisTask{
			Stream: stream,
			Callback: func(result *AnalysisResult) {
				resultsMu.Lock()
				results = append(results, result)
				resultsMu.Unlock()
				wg.Done()
			},
		}
		pool.Submit(task)
	}

	// Wait for all results
	wg.Wait()

	return results
}

// PriorityQueue implements a priority queue for tasks
type PriorityQueue struct {
	tasks []*AnalysisTask
	mu    sync.Mutex
}

// NewPriorityQueue creates a new priority queue
func NewPriorityQueue() *PriorityQueue {
	return &PriorityQueue{
		tasks: make([]*AnalysisTask, 0),
	}
}

// Push adds a task to the queue
func (pq *PriorityQueue) Push(task *AnalysisTask) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	// Insert in priority order
	inserted := false
	for i, t := range pq.tasks {
		if task.Priority > t.Priority {
			pq.tasks = append(pq.tasks[:i], append([]*AnalysisTask{task}, pq.tasks[i:]...)...)
			inserted = true
			break
		}
	}

	if !inserted {
		pq.tasks = append(pq.tasks, task)
	}
}

// Pop removes and returns the highest priority task
func (pq *PriorityQueue) Pop() *AnalysisTask {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if len(pq.tasks) == 0 {
		return nil
	}

	task := pq.tasks[0]
	pq.tasks = pq.tasks[1:]
	return task
}

// Len returns the queue length
func (pq *PriorityQueue) Len() int {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return len(pq.tasks)
}
