package irc

import (
	"sync"
)

type StatsValues struct {
	Unknown   int // unregistered clients
	Total     int // registered clients, including invisible
	Max       int // high-water mark of registered clients
	Invisible int
	Operators int
}

// Stats tracks statistics for a running server
type Stats struct {
	StatsValues

	mutex sync.Mutex
}

// Adds an unregistered client
func (s *Stats) Add() {
	s.mutex.Lock()
	s.Unknown += 1
	s.mutex.Unlock()
}

// Activates a registered client, e.g., for the initial attach to a persistent client
func (s *Stats) AddRegistered(invisible, operator bool) {
	s.mutex.Lock()
	if invisible {
		s.Invisible += 1
	}
	if operator {
		s.Operators += 1
	}
	s.Total += 1
	s.setMax()
	s.mutex.Unlock()
}

// Transition a client from unregistered to registered
func (s *Stats) Register() {
	s.mutex.Lock()
	s.Unknown -= 1
	s.Total += 1
	s.setMax()
	s.mutex.Unlock()
}

func (s *Stats) setMax() {
	if s.Max < s.Total {
		s.Max = s.Total
	}
}

// Modify the Invisible count
func (s *Stats) ChangeInvisible(increment int) {
	s.mutex.Lock()
	s.Invisible += increment
	s.mutex.Unlock()
}

// Modify the Operator count
func (s *Stats) ChangeOperators(increment int) {
	s.mutex.Lock()
	s.Operators += increment
	s.mutex.Unlock()
}

// Remove a user from the server
func (s *Stats) Remove(registered, invisible, operator bool) {
	s.mutex.Lock()
	if registered {
		s.Total -= 1
	} else {
		s.Unknown -= 1
	}
	if invisible {
		s.Invisible -= 1
	}
	if operator {
		s.Operators -= 1
	}
	s.mutex.Unlock()
}

// GetStats retrives total, invisible and oper count
func (s *Stats) GetValues() (result StatsValues) {
	s.mutex.Lock()
	result = s.StatsValues
	s.mutex.Unlock()
	return
}
