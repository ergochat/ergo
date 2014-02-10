package irc

import (
	"encoding/json"
	"os"
)

type Config struct {
	Name      string
	Listeners []ListenerConfig
	Password  string
	Operators []OperatorConfig
	Debug     map[string]bool
}

type OperatorConfig struct {
	Name     string
	Password string
}

type ListenerConfig struct {
	Address     string
	Key         string
	Certificate string
}

func (config *ListenerConfig) IsTLS() bool {
	return (config.Key != "") && (config.Certificate != "")
}

func LoadConfig() (config *Config, err error) {
	config = &Config{}

	file, err := os.Open("ergonomadic.json")
	if err != nil {
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(config)
	return
}
