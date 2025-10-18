// Package workers provides modern worker queue implementations for PCAP processing
package workers

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
)

// WorkerQueueType represents different queue implementation types
type WorkerQueueType int

const (
	// InMemoryQueue uses Go channels for local processing
	InMemoryQueue WorkerQueueType = iota

	// RedisQueue uses Redis as a distributed queue (future implementation)
	RedisQueue

	// NATSQueue uses NATS for distributed processing (future implementation)
	NATSQueue

	// RabbitMQQueue uses RabbitMQ for reliable message processing (future implementation)
	RabbitMQQueue
)

// PacketJob represents a packet processing job
type PacketJob struct {
	ID       string
	Packet   gopacket.Packet
	Metadata map[string]interface{}

	// Processing context
	Priority   int
	CreatedAt  time.Time
	Retries    int
	MaxRetries int
}

// JobResult represents the result of processing a packet job
type JobResult struct {
	JobID       string
	Success     bool
	Error       error
	Data        interface{}
	Duration    time.Duration
	ProcessedAt time.Time
}

// PacketProcessor defines the interface for processing packets
type PacketProcessor interface {
	ProcessPacket(ctx context.Context, job *PacketJob) (*JobResult, error)
}

// WorkerQueue defines the interface for worker queue implementations
type WorkerQueue interface {
	// Queue management
	Start(ctx context.Context) error
	Stop() error

	// Job management
	Enqueue(job *PacketJob) error
	EnqueueBatch(jobs []*PacketJob) error

	// Worker management
	SetWorkerCount(count int) error
	GetWorkerCount() int

	// Statistics
	GetStats() QueueStats

	// Health check
	IsHealthy() bool
}

// QueueStats provides queue performance metrics
type QueueStats struct {
	// Queue metrics
	QueuedJobs    int64 `json:"queued_jobs"`
	ProcessedJobs int64 `json:"processed_jobs"`
	FailedJobs    int64 `json:"failed_jobs"`

	// Worker metrics
	ActiveWorkers int `json:"active_workers"`
	IdleWorkers   int `json:"idle_workers"`

	// Performance metrics
	AvgProcessingTime time.Duration `json:"avg_processing_time"`
	JobsPerSecond     float64       `json:"jobs_per_second"`

	// Error metrics
	ErrorRate float64 `json:"error_rate"`
	RetryRate float64 `json:"retry_rate"`

	// Timestamps
	StartTime   time.Time `json:"start_time"`
	LastJobTime time.Time `json:"last_job_time"`
}

// InMemoryWorkerQueue implements WorkerQueue using Go channels
type InMemoryWorkerQueue struct {
	// Configuration
	workerCount int
	bufferSize  int
	processor   PacketProcessor

	// Channels
	jobChan    chan *PacketJob
	resultChan chan *JobResult
	stopChan   chan struct{}

	// Worker management
	workers  []*Worker
	workerWg sync.WaitGroup

	// Statistics
	stats      QueueStats
	statsMutex sync.RWMutex

	// State
	running bool
	mutex   sync.RWMutex
}

// Worker represents a single worker goroutine
type Worker struct {
	ID        int
	queue     *InMemoryWorkerQueue
	processor PacketProcessor

	// State
	active     bool
	lastJob    time.Time
	jobCount   int64
	errorCount int64
}

// NewInMemoryWorkerQueue creates a new in-memory worker queue
func NewInMemoryWorkerQueue(workerCount, bufferSize int, processor PacketProcessor) *InMemoryWorkerQueue {
	return &InMemoryWorkerQueue{
		workerCount: workerCount,
		bufferSize:  bufferSize,
		processor:   processor,
		jobChan:     make(chan *PacketJob, bufferSize),
		resultChan:  make(chan *JobResult, bufferSize),
		stopChan:    make(chan struct{}),
		workers:     make([]*Worker, workerCount),
		stats: QueueStats{
			StartTime: time.Now(),
		},
	}
}

// Start starts the worker queue
func (q *InMemoryWorkerQueue) Start(ctx context.Context) error {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if q.running {
		return fmt.Errorf("queue is already running")
	}

	// Start workers
	for i := 0; i < q.workerCount; i++ {
		worker := &Worker{
			ID:        i,
			queue:     q,
			processor: q.processor,
		}
		q.workers[i] = worker

		q.workerWg.Add(1)
		go worker.run(ctx)
	}

	// Start result collector
	go q.collectResults(ctx)

	q.running = true
	q.stats.StartTime = time.Now()

	log.Printf("Started worker queue with %d workers", q.workerCount)
	return nil
}

// Stop stops the worker queue
func (q *InMemoryWorkerQueue) Stop() error {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if !q.running {
		return fmt.Errorf("queue is not running")
	}

	// Signal stop
	close(q.stopChan)

	// Wait for workers to finish
	q.workerWg.Wait()

	// Close channels
	close(q.jobChan)
	close(q.resultChan)

	q.running = false
	log.Printf("Stopped worker queue")
	return nil
}

// Enqueue adds a job to the queue
func (q *InMemoryWorkerQueue) Enqueue(job *PacketJob) error {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	if !q.running {
		return fmt.Errorf("queue is not running")
	}

	select {
	case q.jobChan <- job:
		q.statsMutex.Lock()
		q.stats.QueuedJobs++
		q.statsMutex.Unlock()
		return nil
	default:
		return fmt.Errorf("queue is full")
	}
}

// EnqueueBatch adds multiple jobs to the queue
func (q *InMemoryWorkerQueue) EnqueueBatch(jobs []*PacketJob) error {
	for _, job := range jobs {
		if err := q.Enqueue(job); err != nil {
			return fmt.Errorf("failed to enqueue job %s: %w", job.ID, err)
		}
	}
	return nil
}

// SetWorkerCount dynamically adjusts the number of workers
func (q *InMemoryWorkerQueue) SetWorkerCount(count int) error {
	// For simplicity, this implementation requires a restart
	// A more sophisticated implementation could add/remove workers dynamically
	return fmt.Errorf("dynamic worker scaling not implemented - restart queue with new count")
}

// GetWorkerCount returns the current number of workers
func (q *InMemoryWorkerQueue) GetWorkerCount() int {
	return q.workerCount
}

// GetStats returns queue statistics
func (q *InMemoryWorkerQueue) GetStats() QueueStats {
	q.statsMutex.RLock()
	defer q.statsMutex.RUnlock()

	// Calculate derived metrics
	stats := q.stats

	// Calculate jobs per second
	elapsed := time.Since(stats.StartTime).Seconds()
	if elapsed > 0 {
		stats.JobsPerSecond = float64(stats.ProcessedJobs) / elapsed
	}

	// Calculate error rate
	total := stats.ProcessedJobs + stats.FailedJobs
	if total > 0 {
		stats.ErrorRate = float64(stats.FailedJobs) / float64(total)
	}

	// Count active/idle workers
	activeWorkers := 0
	for _, worker := range q.workers {
		if worker.active {
			activeWorkers++
		}
	}
	stats.ActiveWorkers = activeWorkers
	stats.IdleWorkers = q.workerCount - activeWorkers

	return stats
}

// IsHealthy checks if the queue is healthy
func (q *InMemoryWorkerQueue) IsHealthy() bool {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	if !q.running {
		return false
	}

	// Check if workers are responsive
	stats := q.GetStats()

	// Consider unhealthy if error rate is too high
	if stats.ErrorRate > 0.5 {
		return false
	}

	// Consider unhealthy if no jobs processed recently (if jobs are queued)
	if stats.QueuedJobs > 0 && time.Since(stats.LastJobTime) > 30*time.Second {
		return false
	}

	return true
}

// run executes the worker loop
func (w *Worker) run(ctx context.Context) {
	defer w.queue.workerWg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.queue.stopChan:
			return
		case job := <-w.queue.jobChan:
			if job == nil {
				return // Channel closed
			}

			w.processJob(ctx, job)
		}
	}
}

// processJob processes a single job
func (w *Worker) processJob(ctx context.Context, job *PacketJob) {
	w.active = true
	w.lastJob = time.Now()
	defer func() { w.active = false }()

	start := time.Now()
	result, err := w.processor.ProcessPacket(ctx, job)
	duration := time.Since(start)

	if result == nil {
		result = &JobResult{
			JobID: job.ID,
		}
	}

	result.Duration = duration
	result.ProcessedAt = time.Now()

	if err != nil {
		result.Success = false
		result.Error = err
		w.errorCount++

		w.queue.statsMutex.Lock()
		w.queue.stats.FailedJobs++
		w.queue.statsMutex.Unlock()
	} else {
		result.Success = true
		w.jobCount++

		w.queue.statsMutex.Lock()
		w.queue.stats.ProcessedJobs++
		w.queue.stats.LastJobTime = time.Now()

		// Update average processing time
		if w.queue.stats.ProcessedJobs == 1 {
			w.queue.stats.AvgProcessingTime = duration
		} else {
			// Exponential moving average
			alpha := 0.1
			w.queue.stats.AvgProcessingTime = time.Duration(
				float64(w.queue.stats.AvgProcessingTime)*(1-alpha) +
					float64(duration)*alpha,
			)
		}
		w.queue.statsMutex.Unlock()
	}

	// Send result
	select {
	case w.queue.resultChan <- result:
	default:
		// Result channel full, log warning
		log.Printf("Warning: result channel full, dropping result for job %s", job.ID)
	}
}

// collectResults collects and processes job results
func (q *InMemoryWorkerQueue) collectResults(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-q.stopChan:
			return
		case result := <-q.resultChan:
			if result == nil {
				return // Channel closed
			}

			// Process result (could be extended to handle retries, notifications, etc.)
			if !result.Success {
				log.Printf("Job %s failed: %v", result.JobID, result.Error)

				// Could implement retry logic here
			}
		}
	}
}

// QueueConfig holds configuration for worker queues
type QueueConfig struct {
	Type        WorkerQueueType `json:"type"`
	WorkerCount int             `json:"worker_count"`
	BufferSize  int             `json:"buffer_size"`

	// Redis configuration (for future use)
	RedisAddr     string `json:"redis_addr,omitempty"`
	RedisPassword string `json:"redis_password,omitempty"`
	RedisDB       int    `json:"redis_db,omitempty"`

	// NATS configuration (for future use)
	NATSAddr    string `json:"nats_addr,omitempty"`
	NATSSubject string `json:"nats_subject,omitempty"`

	// RabbitMQ configuration (for future use)
	RabbitMQURL   string `json:"rabbitmq_url,omitempty"`
	RabbitMQQueue string `json:"rabbitmq_queue,omitempty"`
}

// GetDefaultQueueConfig returns default queue configuration
func GetDefaultQueueConfig() *QueueConfig {
	return &QueueConfig{
		Type:        InMemoryQueue,
		WorkerCount: 4, // Conservative default
		BufferSize:  1000,
	}
}
