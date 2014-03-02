package irc

import (
	"code.google.com/p/gcfg"
	"encoding/base64"
	"errors"
	"log"
)

type PassConfig struct {
	Password string
}

func (conf *PassConfig) PasswordBytes() []byte {
	if conf.Password == "" {
		return nil
	}
	bytes, err := base64.StdEncoding.DecodeString(conf.Password)
	if err != nil {
		log.Fatal(err)
	}
	return bytes
}

type Config struct {
	Server struct {
		PassConfig
		Database string
		Listen   []string
		MOTD     string
		Name     string
	}

	Operator map[string]*PassConfig

	Debug struct {
		Net     bool
		Client  bool
		Channel bool
		Server  bool
	}
}

func (conf *Config) Operators() map[string][]byte {
	operators := make(map[string][]byte)
	for name, opConf := range conf.Operator {
		operators[name] = opConf.PasswordBytes()
	}
	return operators
}

func LoadConfig(filename string) (config *Config, err error) {
	config = &Config{}
	err = gcfg.ReadFileInto(config, filename)
	if err != nil {
		return
	}
	if config.Server.Name == "" {
		err = errors.New("server.name missing")
		return
	}
	if config.Server.Database == "" {
		err = errors.New("server.database missing")
		return
	}
	if len(config.Server.Listen) == 0 {
		err = errors.New("server.listen missing")
		return
	}
	return
}
