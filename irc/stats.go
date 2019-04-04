package irc

import (
	"sync"
)

// Stats contains the numbers of total, invisible and operators on the server
type Stats struct {
	sync.RWMutex

	Total     int
	Invisible int
	Operators int
}

// ChangeTotal increments the total user count on server
func (s *Stats) ChangeTotal(i int) {
	s.Lock()
	defer s.Unlock()

	s.Total += i
}

// ChangeInvisible increments the invisible count
func (s *Stats) ChangeInvisible(i int) {
	s.Lock()
	defer s.Unlock()

	s.Invisible += i
}

// ChangeOperators increases the operator count
func (s *Stats) ChangeOperators(i int) {
	s.Lock()
	defer s.Unlock()

	s.Operators += i
}

// GetStats retrives total, invisible and oper count
func (s *Stats) GetStats() (int, int, int) {
	s.Lock()
	defer s.Unlock()

	return s.Total, s.Invisible, s.Operators
}
