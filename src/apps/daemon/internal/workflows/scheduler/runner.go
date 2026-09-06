// Package scheduler handles cron-based task parsing, registering, and tick execution routines.
package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TaskFunc represents a parameterless runnable task context block.
type TaskFunc func(ctx context.Context) error

// Job describes details and scheduling triggers of a background job.
type Job struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Interval    time.Duration `json:"interval"`
	CronPattern string        `json:"cron_pattern"`
	RunFunc     TaskFunc
}

// Runner orchestrates spawning task loops on background goroutine schedules.
type Runner struct {
	mu          sync.Mutex
	jobs        map[string]*Job
	lifecycleMu sync.Mutex
	cancel      context.CancelFunc
	running     bool
	wg          sync.WaitGroup
}

// NewRunner instantiates a cron Job Schedule Runner.
func NewRunner() *Runner {
	return &Runner{
		jobs: make(map[string]*Job),
	}
}

// Register adds a custom schedule job configuration details into the active execution list.
func (r *Runner) Register(job *Job) error {
	if job.ID == "" {
		return fmt.Errorf("job ID cannot be empty")
	}
	if job.RunFunc == nil {
		return fmt.Errorf("job RunFunc cannot be nil")
	}
	if job.Interval <= 0 {
		job.Interval = time.Minute // default interval
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.jobs[job.ID]; exists {
		return fmt.Errorf("job with ID %s already registered", job.ID)
	}
	r.jobs[job.ID] = job
	return nil
}

// Start initiates tickers and active scheduler cycles.
func (r *Runner) Start(ctx context.Context) error {
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()

	if r.running {
		return fmt.Errorf("scheduler runner is already running")
	}

	ctx, r.cancel = context.WithCancel(ctx)
	r.running = true

	r.mu.Lock()
	jobs := make([]*Job, 0, len(r.jobs))
	for _, j := range r.jobs {
		jobs = append(jobs, j)
	}
	r.mu.Unlock()
	r.wg.Add(len(jobs))

	for _, job := range jobs {
		j := job // capture loop variable
		go func() {
			defer r.wg.Done()
			ticker := time.NewTicker(j.Interval)
			defer ticker.Stop()

			// Run immediately on start
			if err := j.RunFunc(ctx); err != nil {
				// Log error but continue
				_ = err
			}

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := j.RunFunc(ctx); err != nil {
						_ = err
					}
				}
			}
		}()
	}

	return nil
}

// Stop gracefully signals background tickers and executions to halt.
func (r *Runner) Stop() error {
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()

	if !r.running {
		return nil
	}
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	r.cancel = nil
	r.running = false
	return nil
}

// Unregister removes a job from the registry. Only effective before Start is called.
func (r *Runner) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.jobs[id]; !exists {
		return fmt.Errorf("job not found: %s", id)
	}
	delete(r.jobs, id)
	return nil
}
