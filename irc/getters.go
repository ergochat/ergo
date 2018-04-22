// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"github.com/oragono/oragono/irc/isupport"
	"github.com/oragono/oragono/irc/modes"
	"sync/atomic"
)

func (server *Server) MaxSendQBytes() int {
	return int(atomic.LoadUint32(&server.maxSendQBytes))
}

func (server *Server) SetMaxSendQBytes(m int) {
	atomic.StoreUint32(&server.maxSendQBytes, uint32(m))
}

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

func (server *Server) DefaultChannelModes() modes.Modes {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.defaultChannelModes
}

func (server *Server) ChannelRegistrationEnabled() bool {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.channelRegistrationEnabled
}

func (server *Server) AccountConfig() *AccountConfig {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	if server.config == nil {
		return nil
	}
	return &server.config.Accounts
}

func (server *Server) FakelagConfig() *FakelagConfig {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	if server.config == nil {
		return nil
	}
	return &server.config.Fakelag
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

func (client *Client) Account() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.account
}

func (client *Client) AccountName() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	if client.accountName == "" {
		return "*"
	}
	return client.accountName
}

func (client *Client) SetAccountName(account string) (changed bool) {
	var casefoldedAccount string
	var err error
	if account != "" {
		if casefoldedAccount, err = CasefoldName(account); err != nil {
			return
		}
	}

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	changed = client.account != casefoldedAccount
	client.account = casefoldedAccount
	client.accountName = account
	return
}

func (client *Client) Authorized() bool {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.authorized
}

func (client *Client) SetAuthorized(authorized bool) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.authorized = authorized
}

func (client *Client) PreregNick() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.preregNick
}

func (client *Client) SetPreregNick(preregNick string) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.preregNick = preregNick
}

func (client *Client) HasMode(mode modes.Mode) bool {
	// client.flags has its own synch
	return client.flags.HasMode(mode)
}

func (client *Client) SetMode(mode modes.Mode, on bool) bool {
	return client.flags.SetMode(mode, on)
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
	defer channel.stateMutex.Unlock()
	channel.key = key
}

func (channel *Channel) Founder() string {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.registeredFounder
}
