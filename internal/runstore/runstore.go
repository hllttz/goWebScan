package runstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"goscan/pkg/goscan"
)

type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusCanceled  Status = "canceled"
	StatusFailed    Status = "failed"
)

type Summary struct {
	Hosts       int `json:"hosts"`
	Ports       int `json:"ports"`
	Open        int `json:"open"`
	Closed      int `json:"closed"`
	Filtered    int `json:"filtered"`
	Unreachable int `json:"unreachable"`
	Unknown     int `json:"unknown"`
}

type ScanRun struct {
	ID         string        `json:"id"`
	Status     Status        `json:"status"`
	CreatedAt  time.Time     `json:"createdAt"`
	StartedAt  *time.Time    `json:"startedAt,omitempty"`
	FinishedAt *time.Time    `json:"finishedAt,omitempty"`
	Error      string        `json:"error,omitempty"`
	Summary    Summary       `json:"summary"`
	Report     goscan.Report `json:"report"`

	cancel context.CancelFunc
}

type Event struct {
	Seq  int64  `json:"seq"`
	Type string `json:"type"`
	Run  any    `json:"run,omitempty"`
	Host any    `json:"host,omitempty"`
	Data any    `json:"data,omitempty"`
}

type Store struct {
	mu          sync.RWMutex
	runs        map[string]*ScanRun
	events      map[string][]Event
	subscribers map[string]map[chan Event]struct{}
	nextSeq     map[string]int64
}

func New() *Store {
	return &Store{
		runs:        make(map[string]*ScanRun),
		events:      make(map[string][]Event),
		subscribers: make(map[string]map[chan Event]struct{}),
		nextSeq:     make(map[string]int64),
	}
}

func (s *Store) Create(cancel context.CancelFunc) ScanRun {
	run := &ScanRun{
		ID:        newID(),
		Status:    StatusPending,
		CreatedAt: time.Now(),
		Report:    goscan.Report{Targets: []goscan.HostResult{}},
		cancel:    cancel,
	}

	s.mu.Lock()
	s.runs[run.ID] = run
	s.mu.Unlock()
	s.Publish(run.ID, "created", map[string]string{"id": run.ID})
	return cloneRun(run)
}

func (s *Store) Start(id string) {
	now := time.Now()
	s.mu.Lock()
	run, ok := s.runs[id]
	if ok {
		run.Status = StatusRunning
		run.StartedAt = &now
	}
	s.mu.Unlock()
	if ok {
		s.Publish(id, "started", nil)
	}
}

func (s *Store) AddHostResult(id string, host goscan.HostResult) {
	s.mu.Lock()
	run, ok := s.runs[id]
	if ok {
		run.Report.Targets = append(run.Report.Targets, host)
		run.Summary = summarize(run.Report)
	}
	s.mu.Unlock()
	if ok {
		s.Publish(id, "host_result", host)
	}
}

func (s *Store) Finish(id string, report goscan.Report, err error) {
	now := time.Now()
	eventType := "completed"

	s.mu.Lock()
	run, ok := s.runs[id]
	if ok {
		run.FinishedAt = &now
		run.Report = report
		run.Summary = summarize(report)
		switch {
		case errors.Is(err, context.Canceled):
			run.Status = StatusCanceled
			run.Error = "scan canceled"
			eventType = "canceled"
		case err != nil:
			run.Status = StatusFailed
			run.Error = err.Error()
			eventType = "failed"
		default:
			run.Status = StatusCompleted
		}
	}
	s.mu.Unlock()
	if ok {
		s.Publish(id, eventType, nil)
		s.closeSubscribers(id)
	}
}

func (s *Store) Get(id string) (ScanRun, bool) {
	s.mu.RLock()
	run, ok := s.runs[id]
	s.mu.RUnlock()
	if !ok {
		return ScanRun{}, false
	}
	return cloneRun(run), true
}

func (s *Store) Cancel(id string) bool {
	s.mu.RLock()
	run, ok := s.runs[id]
	cancel := context.CancelFunc(nil)
	if ok {
		cancel = run.cancel
	}
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if cancel != nil {
		cancel()
	}
	s.Publish(id, "cancel_requested", nil)
	return true
}

func (s *Store) Subscribe(id string, after int64) (<-chan Event, []Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[id]; !ok {
		return nil, nil, false
	}
	ch := make(chan Event, 32)
	if s.subscribers[id] == nil {
		s.subscribers[id] = make(map[chan Event]struct{})
	}
	s.subscribers[id][ch] = struct{}{}

	history := make([]Event, 0)
	for _, event := range s.events[id] {
		if event.Seq > after {
			history = append(history, event)
		}
	}
	return ch, history, true
}

func (s *Store) Unsubscribe(id string, ch <-chan Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sub := range s.subscribers[id] {
		if sub == ch {
			delete(s.subscribers[id], sub)
			close(sub)
			return
		}
	}
}

func (s *Store) Publish(id, eventType string, data any) {
	s.mu.Lock()
	seq := s.nextSeq[id] + 1
	s.nextSeq[id] = seq
	event := Event{Seq: seq, Type: eventType}
	switch eventType {
	case "host_result":
		event.Host = data
	default:
		event.Data = data
	}
	s.events[id] = append(s.events[id], event)
	subs := make([]chan Event, 0, len(s.subscribers[id]))
	for ch := range s.subscribers[id] {
		subs = append(subs, ch)
	}
	s.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- event:
		default:
		}
	}
}

func (s *Store) closeSubscribers(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subscribers[id] {
		close(ch)
		delete(s.subscribers[id], ch)
	}
}

func summarize(report goscan.Report) Summary {
	summary := Summary{Hosts: len(report.Targets)}
	for _, host := range report.Targets {
		for _, port := range host.Ports {
			summary.Ports++
			switch port.State {
			case goscan.PortOpen:
				summary.Open++
			case goscan.PortClosed:
				summary.Closed++
			case goscan.PortFiltered:
				summary.Filtered++
			case goscan.PortUnreachable:
				summary.Unreachable++
			default:
				summary.Unknown++
			}
		}
	}
	return summary
}

func cloneRun(run *ScanRun) ScanRun {
	out := *run
	out.cancel = nil
	out.Report.Targets = append([]goscan.HostResult(nil), run.Report.Targets...)
	if out.Report.Targets == nil {
		out.Report.Targets = []goscan.HostResult{}
	}
	return out
}

func newID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(buf[:])
}
