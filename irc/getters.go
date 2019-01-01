// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"github.com/unendingPattern/oragono/irc/isupport"
	"github.com/unendingPattern/oragono/irc/modes"
	"math/rand"
	"time"
)

func (server *Server) Config() *Config {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.config
}

func (server *Server) ISupport() *isupport.List {
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.isupport
}

func (server *Server) Limits() Limits {
	return server.Config().Limits
}

func (server *Server) Password() []byte {
	return server.Config().Server.passwordBytes
}

func (server *Server) RecoverFromErrors() bool {
	return *server.Config().Debug.RecoverFromErrors
}

func (server *Server) ProxyAllowedFrom() []string {
	return server.Config().Server.ProxyAllowedFrom
}

func (server *Server) WebIRCConfig() []webircConfig {
	return server.Config().Server.WebIRC
}

func (server *Server) DefaultChannelModes() modes.Modes {
	return server.Config().Channels.defaultModes
}

func (server *Server) ChannelRegistrationEnabled() bool {
	return server.Config().Channels.Registration.Enabled
}

func (server *Server) AccountConfig() *AccountConfig {
	return &server.Config().Accounts
}

func (server *Server) FakelagConfig() *FakelagConfig {
	return &server.Config().Fakelag
}

func (server *Server) GetOperator(name string) (oper *Oper) {
	name, err := CasefoldName(name)
	if err != nil {
		return
	}
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	return server.config.operators[name]
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

func (client *Client) NickMaskCasefolded() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.nickMaskCasefolded
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

func (client *Client) ResumeToken() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.resumeToken
}

func (client *Client) Oper() *Oper {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.oper
}

func (client *Client) SetOper(oper *Oper) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.oper = oper
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

func (client *Client) WhoWas() (result WhoWas) {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()

	result.nicknameCasefolded = client.nickCasefolded
	result.nickname = client.nick
	result.username = client.username
	result.hostname = client.hostname
	result.realname = client.realname

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

func (channel *Channel) setUserLimit(limit int) {
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

func (channel *Channel) HighLights() string {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.highlights
}

func (channel *Channel) setHighLights(highlights string) {
	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()
	channel.highlights = highlights
}

func (channel *Channel) Founder() string {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.registeredFounder
}


func (server *Server) RandomUserAgent() string {
	var UserAgents = []string{
	"Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
	"Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
	"Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4325)",
	"Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",
	"Mozilla/45.0 (compatible; MSIE 6.0; Windows NT 5.1)",
	"Mozilla/4.08 (compatible; MSIE 6.0; Windows NT 5.1)",
	"Mozilla/4.01 (compatible; MSIE 6.0; Windows NT 5.1)",
	"Mozilla/4.0 (X11; MSIE 6.0; i686; .NET CLR 1.1.4322; .NET CLR 2.0.50727; FDM)",
	"Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 6.0)",
	"Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)",
	"Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.0)",
	"Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
	"Mozilla/4.0 (MSIE 6.0; Windows NT 5.1)",
	"Mozilla/4.0 (MSIE 6.0; Windows NT 5.0)",
	"Mozilla/4.0 (compatible;MSIE 6.0;Windows 98;Q312461)",
	"Mozilla/4.0 (Compatible; Windows NT 5.1; MSIE 6.0) (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
	"Mozilla/4.0 (compatible; U; MSIE 6.0; Windows NT 5.1) (Compatible; ; ; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
	"Mozilla/4.0 (compatible; U; MSIE 6.0; Windows NT 5.1)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; InfoPath.3; Tablet PC 2.0)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB6.5; QQDownload 534; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; SLCC2; .NET CLR 2.0.50727; Media Center PC 6.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729)",
	"Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)",
	"Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; el-GR)",
	"Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)",
	"Mozilla/5.0 (MSIE 7.0; Macintosh; U; SunOS; X11; gu; SV1; InfoPath.2; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648)",
	"Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; WOW64; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; c .NET CLR 3.0.04506; .NET CLR 3.5.30707; InfoPath.1; el-GR)",
	"Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; c .NET CLR 3.0.04506; .NET CLR 3.5.30707; InfoPath.1; el-GR)",
	"Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; fr-FR)",
	"Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; en-US)",
	"Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.2; WOW64; .NET CLR 2.0.50727)",
	"Mozilla/5.0 (compatible; MSIE 7.0; Windows 98; SpamBlockerUtility 6.3.91; SpamBlockerUtility 6.2.91; .NET CLR 4.1.89;GB)",
	"Mozilla/4.79 [en] (compatible; MSIE 7.0; Windows NT 5.0; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648)",
	"Mozilla/4.0 (Windows; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
	"Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)",
	"Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1)",
	"Mozilla/4.0 (compatible;MSIE 7.0;Windows NT 6.0)",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; Win64; x64; Trident/6.0; .NET4.0E; .NET4.0C)",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; SLCC2; .NET CLR 2.0.50727; InfoPath.3; .NET4.0C; .NET4.0E; .NET CLR 3.5.30729; .NET CLR 3.0.30729; MS-RTC LM 8)",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; MS-RTC LM 8; .NET4.0C; .NET4.0E; InfoPath.3)",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/6.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; chromeframe/12.0.742.100)",
	"Mozilla/4.0 (compatible; MSIE 5.50; Windows NT; SiteKiosk 4.9; SiteCoach 1.0)",
	"Mozilla/4.0 (compatible; MSIE 5.50; Windows NT; SiteKiosk 4.8; SiteCoach 1.0)",
	"Mozilla/4.0 (compatible; MSIE 5.50; Windows NT; SiteKiosk 4.8)",
	"Mozilla/4.0 (compatible; MSIE 5.50; Windows 98; SiteKiosk 4.8)",
	"Mozilla/4.0 (compatible; MSIE 5.50; Windows 95; SiteKiosk 4.8)",
	"Mozilla/4.0 (compatible;MSIE 5.5; Windows 98)",
	"Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.1)",
	"Mozilla/4.0 (compatible; MSIE 5.5;)",
	"Mozilla/4.0 (Compatible; MSIE 5.5; Windows NT5.0; Q312461; SV1; .NET CLR 1.1.4322; InfoPath.2)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT5)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 6.1; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 6.1; chromeframe/12.0.742.100; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30618)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.5)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.2; .NET CLR 1.1.4322; InfoPath.2; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; FDM)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.2; .NET CLR 1.1.4322) (Compatible; ; ; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.2; .NET CLR 1.1.4322)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
	"Mozilla/4.0 (compatible; MSIE 5.00; Windows 98)",
	"Mozilla/4.0(compatible; MSIE 5.0; Windows 98; DigExt)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT;)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; YComp 5.0.2.6)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; YComp 5.0.2.5)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; YComp 5.0.0.0)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; Hotbar 4.1.8.0)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; Hotbar 3.0)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; .NET CLR 1.0.3705)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 6.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.0.04506.648; .NET4.0C; .NET4.0E)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.9; .NET CLR 1.1.4322)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.2; .NET CLR 1.1.4322)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.0)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows 98;)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; YComp 5.0.2.4)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; Hotbar 3.0)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; DigExt; YComp 5.0.2.6; yplus 1.0)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; DigExt; YComp 5.0.2.6)",
	}

	rand.Seed(time.Now().Unix())
	return UserAgents[rand.Intn(len(UserAgents))]

}