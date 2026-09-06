package scheduler

import (
	"context"
	"errors"
	"sync"
	"time"
)

type JobType string

type SchedulableJob interface {
	ID() string
	Type() JobType
	Execute(ctx context.Context) error
}

type BudgetPolicy struct {
	MaxGlobalRunning int
	MaxPerType       map[JobType]int
	MaxQueueDepth    int
}

type Scheduler struct {
	policy       BudgetPolicy
	queue        chan SchedulableJob
	runningMu    sync.Mutex
	activeCount  int
	activeByType map[JobType]int
	activeJobs   map[string]context.CancelFunc
	stopChan     chan struct{}
	startOnce    sync.Once
	stopOnce     sync.Once
	stopped      bool
	parentCtx    context.Context
	wg           sync.WaitGroup
}

func NewScheduler(policy BudgetPolicy) *Scheduler {
	if policy.MaxPerType == nil {
		policy.MaxPerType = make(map[JobType]int)
	}
	return &Scheduler{
		policy:       policy,
		queue:        make(chan SchedulableJob, policy.MaxQueueDepth),
		activeByType: make(map[JobType]int),
		activeJobs:   make(map[string]context.CancelFunc),
		stopChan:     make(chan struct{}),
	}
}

func (s *Scheduler) Submit(job SchedulableJob) error {
	s.runningMu.Lock()
	parentCtx := s.parentCtx
	stopped := s.stopped
	s.runningMu.Unlock()
	if stopped {
		return errors.New("scheduler is stopped")
	}
	if parentCtx != nil {
		select {
		case <-parentCtx.Done():
			return errors.New("scheduler context is cancelled")
		default:
		}
	}

	select {
	case <-s.stopChan:
		return errors.New("scheduler is stopped")
	default:
	}

	select {
	case <-s.stopChan:
		return errors.New("scheduler is stopped")
	case s.queue <- job:
		return nil
	default:
		return errors.New("scheduler queue is full: backpressure applied")
	}
}

func (s *Scheduler) Start(ctx context.Context) {
	s.startOnce.Do(func() {
		s.runningMu.Lock()
		s.parentCtx = ctx
		s.runningMu.Unlock()
		s.wg.Add(1)
		go s.dispatchLoop(ctx)
	})
}

func (s *Scheduler) dispatchLoop(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case job := <-s.queue:
			if !s.waitForBudget(ctx, job.Type()) {
				return
			}

			jobCtx, cancel := context.WithCancel(ctx)
			s.runningMu.Lock()
			if s.stopped {
				s.runningMu.Unlock()
				cancel()
				return
			}
			s.activeJobs[job.ID()] = cancel
			s.activeCount++
			s.activeByType[job.Type()]++
			s.wg.Add(1)
			s.runningMu.Unlock()

			go func(j SchedulableJob, jc context.Context) {
				defer s.wg.Done()
				defer func() {
					cancel()
					s.runningMu.Lock()
					delete(s.activeJobs, j.ID())
					s.activeCount--
					s.activeByType[j.Type()]--
					s.runningMu.Unlock()
				}()
				_ = j.Execute(jc)
			}(job, jobCtx)
		}
	}
}

func (s *Scheduler) waitForBudget(ctx context.Context, t JobType) bool {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-s.stopChan:
			return false
		case <-ticker.C:
			s.runningMu.Lock()
			globalAllowed := s.activeCount < s.policy.MaxGlobalRunning
			typeLimit := s.policy.MaxPerType[t]
			typeAllowed := typeLimit == 0 || s.activeByType[t] < typeLimit
			s.runningMu.Unlock()

			if globalAllowed && typeAllowed {
				select {
				case <-ctx.Done():
					return false
				case <-s.stopChan:
					return false
				default:
					return true
				}
			}
		}
	}
}

func (s *Scheduler) Cancel(jobID string) bool {
	s.runningMu.Lock()
	cancel, exists := s.activeJobs[jobID]
	s.runningMu.Unlock()
	if exists {
		cancel()
		return true
	}
	return false
}

func (s *Scheduler) Stop() {
	s.stopOnce.Do(func() { close(s.stopChan) })

	s.runningMu.Lock()
	s.stopped = true
	for _, cancel := range s.activeJobs {
		cancel()
	}
	s.runningMu.Unlock()
	s.wg.Wait()
}

type FuncJob struct {
	id      string
	jobType JobType
	run     func(ctx context.Context) error
}

func NewFuncJob(id string, jobType JobType, run func(ctx context.Context) error) *FuncJob {
	return &FuncJob{id: id, jobType: jobType, run: run}
}

func (f *FuncJob) ID() string                        { return f.id }
func (f *FuncJob) Type() JobType                     { return f.jobType }
func (f *FuncJob) Execute(ctx context.Context) error { return f.run(ctx) }
