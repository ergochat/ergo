// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import "github.com/oragono/oragono/irc/isupport"

func (server *Server) ISupport() *isupport.List {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.isupport
}

func (server *Server) Limits() Limits {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.limits
}

func (server *Server) Password() []byte {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.password
}

func (server *Server) RecoverFromErrors() bool {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.recoverFromErrors
}

func (server *Server) ProxyAllowedFrom() []string {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.proxyAllowedFrom
}

func (server *Server) WebIRCConfig() []webircConfig {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.webirc
}

func (server *Server) DefaultChannelModes() Modes {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.defaultChannelModes
}

func (client *Client) Nick() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.nick
}

func (client *Client) NickMaskString() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.nickMaskString
}

func (client *Client) NickCasefolded() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.nickCasefolded
}

func (client *Client) Username() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.username
}

func (client *Client) Hostname() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.hostname
}

func (client *Client) Realname() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.realname
}

func (client *Client) Registered() bool {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.registered
}

func (client *Client) Destroyed() bool {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.isDestroyed
}

func (client *Client) HasMode(mode Mode) bool {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.flags[mode]
}

func (client *Client) Channels() (result []*Channel) {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	length := len(client.channels)
	result = make([]*Channel, length)
	i := 0
	for channel := range client.channels {
		result[i] = channel
		i++
	}
	return
}

func (channel *Channel) Name() string {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.name
}

func (channel *Channel) setName(name string) {
	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()
	channel.name = name
}

func (channel *Channel) NameCasefolded() string {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.nameCasefolded
}

func (channel *Channel) setNameCasefolded(nameCasefolded string) {
	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()
	channel.nameCasefolded = nameCasefolded
}

func (channel *Channel) Members() (result []*Client) {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.membersCache
}

func (channel *Channel) UserLimit() uint64 {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.userLimit
}

func (channel *Channel) setUserLimit(limit uint64) {
	channel.stateMutex.Lock()
	channel.userLimit = limit
	channel.stateMutex.Unlock()
}

func (channel *Channel) Key() string {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.key
}

func (channel *Channel) setKey(key string) {
	channel.stateMutex.Lock()
	channel.key = key
	channel.stateMutex.Unlock()
}

func (channel *Channel) HasMode(mode Mode) bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.flags[mode]
}

// set a channel mode, return whether it was already set
func (channel *Channel) setMode(mode Mode, enable bool) (already bool) {
	channel.stateMutex.Lock()
	already = (channel.flags[mode] == enable)
	if !already {
		if enable {
			channel.flags[mode] = true
		} else {
			delete(channel.flags, mode)
		}
	}
	channel.stateMutex.Unlock()
	return
}
