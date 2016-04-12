package irc

import (
	"errors"
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v2"
)

type PassConfig struct {
	Password string
}

func (conf *PassConfig) PasswordBytes() []byte {
	bytes, err := DecodePassword(conf.Password)
	if err != nil {
		log.Fatal("decode password error: ", err)
	}
	return bytes
}

type Config struct {
	Server struct {
		PassConfig
		Database string
		Listen   []string
		Wslisten string
		Log      string
		MOTD     string
		Name     string
	}

	Operator map[string]*PassConfig

	Theater map[string]*PassConfig
}

func (conf *Config) Operators() map[Name][]byte {
	operators := make(map[Name][]byte)
	for name, opConf := range conf.Operator {
		operators[NewName(name)] = opConf.PasswordBytes()
	}
	return operators
}

func (conf *Config) Theaters() map[Name][]byte {
	theaters := make(map[Name][]byte)
	for s, theaterConf := range conf.Theater {
		name := NewName(s)
		if !name.IsChannel() {
			log.Fatal("config uses a non-channel for a theater!")
		}
		theaters[name] = theaterConf.PasswordBytes()
	}
	return theaters
}

func LoadConfig(filename string) (config *Config, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	if config.Server.Name == "" {
		return nil, errors.New("Server name missing")
	}
	if config.Server.Database == "" {
		return nil, errors.New("Server database missing")
	}
	if len(config.Server.Listen) == 0 {
		return nil, errors.New("Server listening addresses missing")
	}
	return config, nil
}
