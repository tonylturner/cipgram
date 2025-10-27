package workers_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"cipgram/pkg/pcap/workers"
)

// MockPacketProcessor implements PacketProcessor for testing
type MockPacketProcessor struct {
	processFunc func(ctx context.Context, job *workers.PacketJob) (*workers.JobResult, error)
	callCount   int
}

func (m *MockPacketProcessor) ProcessPacket(ctx context.Context, job *workers.PacketJob) (*workers.JobResult, error) {
	m.callCount++
	if m.processFunc != nil {
		return m.processFunc(ctx, job)
	}

	// Default successful processing
	return &workers.JobResult{
		JobID:   job.ID,
		Success: true,
		Data:    fmt.Sprintf("processed_%s", job.ID),
	}, nil
}

func TestNewInMemoryWorkerQueue(t *testing.T) {
	processor := &MockPacketProcessor{}
	queue := workers.NewInMemoryWorkerQueue(2, 10, processor)

	if queue == nil {
		t.Fatal("Expected queue to be created")
	}

	if queue.GetWorkerCount() != 2 {
		t.Errorf("Expected 2 workers, got %d", queue.GetWorkerCount())
	}
}

func TestWorkerQueue_StartStop(t *testing.T) {
	processor := &MockPacketProcessor{}
	queue := workers.NewInMemoryWorkerQueue(2, 10, processor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test start
	err := queue.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start queue: %v", err)
	}

	if !queue.IsHealthy() {
		t.Error("Expected queue to be healthy after start")
	}

	// Test double start (should fail)
	err = queue.Start(ctx)
	if err == nil {
		t.Error("Expected error when starting already running queue")
	}

	// Test stop
	err = queue.Stop()
	if err != nil {
		t.Fatalf("Failed to stop queue: %v", err)
	}

	// Test double stop (should fail)
	err = queue.Stop()
	if err == nil {
		t.Error("Expected error when stopping already stopped queue")
	}
}

func TestWorkerQueue_EnqueueAndProcess(t *testing.T) {
	processor := &MockPacketProcessor{}
	queue := workers.NewInMemoryWorkerQueue(2, 10, processor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start queue: %v", err)
	}
	defer queue.Stop()

	// Create test job
	job := &workers.PacketJob{
		ID:        "test_job_1",
		Packet:    nil, // Mock packet
		CreatedAt: time.Now(),
	}

	// Enqueue job
	err = queue.Enqueue(job)
	if err != nil {
		t.Fatalf("Failed to enqueue job: %v", err)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Check stats
	stats := queue.GetStats()
	if stats.QueuedJobs != 1 {
		t.Errorf("Expected 1 queued job, got %d", stats.QueuedJobs)
	}

	// Wait a bit more for processing to complete
	time.Sleep(200 * time.Millisecond)

	stats = queue.GetStats()
	if stats.ProcessedJobs == 0 {
		t.Error("Expected at least 1 processed job")
	}

	if processor.callCount == 0 {
		t.Error("Expected processor to be called")
	}
}

func TestWorkerQueue_EnqueueBatch(t *testing.T) {
	processor := &MockPacketProcessor{}
	queue := workers.NewInMemoryWorkerQueue(2, 10, processor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start queue: %v", err)
	}
	defer queue.Stop()

	// Create batch of jobs
	jobs := []*workers.PacketJob{
		{ID: "batch_job_1", CreatedAt: time.Now()},
		{ID: "batch_job_2", CreatedAt: time.Now()},
		{ID: "batch_job_3", CreatedAt: time.Now()},
	}

	// Enqueue batch
	err = queue.EnqueueBatch(jobs)
	if err != nil {
		t.Fatalf("Failed to enqueue batch: %v", err)
	}

	// Wait for processing
	time.Sleep(300 * time.Millisecond)

	stats := queue.GetStats()
	if stats.QueuedJobs != 3 {
		t.Errorf("Expected 3 queued jobs, got %d", stats.QueuedJobs)
	}

	if processor.callCount < 3 {
		t.Errorf("Expected at least 3 processor calls, got %d", processor.callCount)
	}
}

func TestWorkerQueue_ErrorHandling(t *testing.T) {
	// Create processor that always fails
	processor := &MockPacketProcessor{
		processFunc: func(ctx context.Context, job *workers.PacketJob) (*workers.JobResult, error) {
			return nil, fmt.Errorf("processing failed for job %s", job.ID)
		},
	}

	queue := workers.NewInMemoryWorkerQueue(1, 5, processor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start queue: %v", err)
	}
	defer queue.Stop()

	// Enqueue job that will fail
	job := &workers.PacketJob{
		ID:        "failing_job",
		CreatedAt: time.Now(),
	}

	err = queue.Enqueue(job)
	if err != nil {
		t.Fatalf("Failed to enqueue job: %v", err)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	stats := queue.GetStats()
	if stats.FailedJobs == 0 {
		t.Error("Expected at least 1 failed job")
	}

	if stats.ErrorRate == 0 {
		t.Error("Expected non-zero error rate")
	}
}

func TestWorkerQueue_Stats(t *testing.T) {
	processor := &MockPacketProcessor{}
	queue := workers.NewInMemoryWorkerQueue(2, 10, processor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start queue: %v", err)
	}
	defer queue.Stop()

	// Get initial stats
	stats := queue.GetStats()
	if stats.StartTime.IsZero() {
		t.Error("Expected start time to be set")
	}

	if stats.ActiveWorkers < 0 || stats.ActiveWorkers > 2 {
		t.Errorf("Expected 0-2 active workers, got %d", stats.ActiveWorkers)
	}

	if stats.IdleWorkers < 0 || stats.IdleWorkers > 2 {
		t.Errorf("Expected 0-2 idle workers, got %d", stats.IdleWorkers)
	}

	if stats.ActiveWorkers+stats.IdleWorkers != 2 {
		t.Errorf("Expected total workers to be 2, got %d", stats.ActiveWorkers+stats.IdleWorkers)
	}
}

func TestWorkerQueue_FullQueue(t *testing.T) {
	// Create processor that takes a long time
	processor := &MockPacketProcessor{
		processFunc: func(ctx context.Context, job *workers.PacketJob) (*workers.JobResult, error) {
			time.Sleep(100 * time.Millisecond) // Slow processing
			return &workers.JobResult{
				JobID:   job.ID,
				Success: true,
			}, nil
		},
	}

	// Small buffer to test queue full condition
	queue := workers.NewInMemoryWorkerQueue(1, 2, processor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start queue: %v", err)
	}
	defer queue.Stop()

	// Fill the queue
	for i := 0; i < 3; i++ {
		job := &workers.PacketJob{
			ID:        fmt.Sprintf("job_%d", i),
			CreatedAt: time.Now(),
		}

		err = queue.Enqueue(job)
		if i < 2 && err != nil {
			t.Fatalf("Failed to enqueue job %d: %v", i, err)
		}
		if i >= 2 && err == nil {
			t.Error("Expected queue full error for job 3")
		}
	}
}

func TestWorkerQueue_ContextCancellation(t *testing.T) {
	processor := &MockPacketProcessor{
		processFunc: func(ctx context.Context, job *workers.PacketJob) (*workers.JobResult, error) {
			// Check if context is cancelled
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				return &workers.JobResult{
					JobID:   job.ID,
					Success: true,
				}, nil
			}
		},
	}

	queue := workers.NewInMemoryWorkerQueue(1, 5, processor)

	ctx, cancel := context.WithCancel(context.Background())

	err := queue.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start queue: %v", err)
	}

	// Enqueue a job
	job := &workers.PacketJob{
		ID:        "cancellation_test",
		CreatedAt: time.Now(),
	}

	err = queue.Enqueue(job)
	if err != nil {
		t.Fatalf("Failed to enqueue job: %v", err)
	}

	// Cancel context
	cancel()

	// Stop queue
	err = queue.Stop()
	if err != nil {
		t.Fatalf("Failed to stop queue: %v", err)
	}
}

func TestGetDefaultQueueConfig(t *testing.T) {
	config := workers.GetDefaultQueueConfig()

	if config == nil {
		t.Fatal("Expected config to be created")
	}

	if config.Type != workers.InMemoryQueue {
		t.Errorf("Expected InMemoryQueue type, got %v", config.Type)
	}

	if config.WorkerCount <= 0 {
		t.Errorf("Expected positive worker count, got %d", config.WorkerCount)
	}

	if config.BufferSize <= 0 {
		t.Errorf("Expected positive buffer size, got %d", config.BufferSize)
	}
}
