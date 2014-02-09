package irc

import (
	"encoding/json"
	"os"
)

type Config struct {
	Name      string
	Listen    string
	Password  string
	Operators []OperatorConfig
	Debug     map[string]bool
}

type OperatorConfig struct {
	Name     string
	Password string
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
