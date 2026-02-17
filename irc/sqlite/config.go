package sqlite

import "time"

type Config struct {
	//Enabled  bool
	Timeout  time.Duration
	MaxConns int `yaml:"max-conns"`
}
