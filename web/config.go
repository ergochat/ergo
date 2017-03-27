// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package web

import (
	"crypto/tls"
	"errors"
	"io/ioutil"
	"log"

	"github.com/DanielOaks/oragono/irc"

	"gopkg.in/yaml.v2"
)

// TLSListenConfig defines configuration options for listening on TLS
type TLSListenConfig struct {
	Cert string
	Key  string
}

// Certificate returns the TLS certificate assicated with this TLSListenConfig
func (conf *TLSListenConfig) Config() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
	if err != nil {
		return nil, errors.New("tls cert+key: invalid pair")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, err
}

type Config struct {
	Host             string
	Listen           string
	TLSListenersConf map[string]*TLSListenConfig `yaml:"tls-listeners"`
	Log              string
}

func (conf *Config) TLSListeners() map[string]*tls.Config {
	tlsListeners := make(map[string]*tls.Config)
	for s, tlsListenersConf := range conf.TLSListenersConf {
		config, err := tlsListenersConf.Config()
		if err != nil {
			log.Fatal(err)
		}
		name, err := irc.CasefoldName(s)
		if err == nil {
			tlsListeners[name] = config
		} else {
			log.Println("Could not casefold TLS listener:", err.Error())
		}
	}
	return tlsListeners
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

	if config.Listen == "" {
		return nil, errors.New("Listening address missing")
	}

	return config, nil
}
