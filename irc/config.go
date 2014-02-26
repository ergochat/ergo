package irc

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

func decodePassword(password string) []byte {
	if password == "" {
		return nil
	}
	bytes, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		log.Fatal(err)
	}
	return bytes
}

type Config struct {
	Debug     map[string]bool
	Listeners []ListenerConfig
	MOTD      string
	Name      string
	Operators []OperatorConfig
	Password  string
	directory string
}

func (conf *Config) Database() string {
	return filepath.Join(conf.directory, "ergonomadic.db")
}

func (conf *Config) PasswordBytes() []byte {
	return decodePassword(conf.Password)
}

func (conf *Config) OperatorsMap() map[string][]byte {
	operators := make(map[string][]byte)
	for _, opConf := range conf.Operators {
		operators[opConf.Name] = opConf.PasswordBytes()
	}
	return operators
}

type OperatorConfig struct {
	Name     string
	Password string
}

func (conf *OperatorConfig) PasswordBytes() []byte {
	return decodePassword(conf.Password)
}

type ListenerConfig struct {
	Net         string
	Address     string
	Key         string
	Certificate string
}

func (config *ListenerConfig) IsTLS() bool {
	return (config.Key != "") && (config.Certificate != "")
}

func LoadConfig(filename string) (config *Config, err error) {
	config = &Config{}

	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		return
	}

	config.directory = filepath.Dir(filename)
	config.MOTD = filepath.Join(config.directory, config.MOTD)
	for _, lconf := range config.Listeners {
		if lconf.Net == "" {
			lconf.Net = "tcp"
		}
	}
	return
}
