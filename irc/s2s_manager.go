// Copyright (c) 2026 Ergo Developers
// released under the MIT license

package irc

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
	"github.com/ergochat/irc-go/ircmsg"
)

// S2SManager manages server-to-server linking, routing, and synchronization.
type S2SManager struct {
	sync.RWMutex
	server      *Server
	nodesBySID  map[string]*ServerNode
	nodesByName map[string]*ServerNode
	directLinks map[string]*ServerLink
	linkConfigs map[string]*LinkConfig
	ourNode     *ServerNode
	stopChan    chan struct{}
	stopped     bool
}

// NewS2SManager initializes a new S2SManager.
func NewS2SManager(server *Server, config *Config) *S2SManager {
	s2s := &S2SManager{
		server:      server,
		nodesBySID:  make(map[string]*ServerNode),
		nodesByName: make(map[string]*ServerNode),
		directLinks: make(map[string]*ServerLink),
		linkConfigs: make(map[string]*LinkConfig),
		stopChan:    make(chan struct{}),
	}

	ourSID := strings.ToUpper(config.Server.SID)
	if ourSID == "" {
		ourSID = "001"
	}
	server.sid = ourSID

	s2s.ourNode = &ServerNode{
		Name:           server.name,
		NameCasefolded: strings.ToLower(server.name),
		SID:            ourSID,
		Description:    server.name,
		HopCount:       0,
		IsLocal:        true,
		IsDirect:       false,
		Ctime:          server.ctime,
	}
	s2s.nodesBySID[ourSID] = s2s.ourNode
	s2s.nodesByName[s2s.ourNode.NameCasefolded] = s2s.ourNode

	s2s.ApplyConfig(config)
	return s2s
}

// ApplyConfig reloads link configurations and starts autoconnect loops.
func (s2s *S2SManager) ApplyConfig(config *Config) {
	s2s.Lock()
	defer s2s.Unlock()

	s2s.linkConfigs = make(map[string]*LinkConfig)
	for name, lcfg := range config.Server.Links {
		cfg := lcfg
		if cfg.Name == "" {
			cfg.Name = name
		}
		if cfg.Port == 0 {
			if cfg.TLS {
				cfg.Port = 6697
			} else {
				cfg.Port = 6667
			}
		}
		s2s.linkConfigs[strings.ToLower(cfg.Name)] = &cfg
		if cfg.SID != "" {
			s2s.linkConfigs[strings.ToUpper(cfg.SID)] = &cfg
		}

		if cfg.AutoConnect {
			go s2s.startOutboundConnector(&cfg)
		}
	}
}

// RegisterServer registers a new server node in the network graph.
func (s2s *S2SManager) RegisterServer(node *ServerNode) {
	s2s.Lock()
	defer s2s.Unlock()

	s2s.nodesBySID[node.SID] = node
	s2s.nodesByName[node.NameCasefolded] = node
	if node.IsDirect && node.NextHop != nil {
		s2s.directLinks[node.SID] = node.NextHop
	}
	s2s.server.logger.Info("s2s", "Registered server in graph", node.Name, node.SID, fmt.Sprintf("hops: %d", node.HopCount))
}

// GetServerBySID looks up a server node by its 3-character SID.
func (s2s *S2SManager) GetServerBySID(sid string) *ServerNode {
	s2s.RLock()
	defer s2s.RUnlock()
	return s2s.nodesBySID[strings.ToUpper(sid)]
}

// GetServerByName looks up a server node by its name.
func (s2s *S2SManager) GetServerByName(name string) *ServerNode {
	s2s.RLock()
	defer s2s.RUnlock()
	return s2s.nodesByName[strings.ToLower(name)]
}

// AllServers returns a list of all known servers in the graph.
func (s2s *S2SManager) AllServers() []*ServerNode {
	s2s.RLock()
	defer s2s.RUnlock()
	res := make([]*ServerNode, 0, len(s2s.nodesBySID))
	for _, node := range s2s.nodesBySID {
		res = append(res, node)
	}
	return res
}

// AllDirectLinks returns a list of all directly connected active links.
func (s2s *S2SManager) AllDirectLinks() []*ServerLink {
	s2s.RLock()
	defer s2s.RUnlock()
	res := make([]*ServerLink, 0, len(s2s.directLinks))
	for _, link := range s2s.directLinks {
		res = append(res, link)
	}
	return res
}

// FindLinkConfig searches for a configured link by SID or Name.
func (s2s *S2SManager) FindLinkConfig(sid, name string) *LinkConfig {
	s2s.RLock()
	defer s2s.RUnlock()
	if sid != "" {
		if cfg, ok := s2s.linkConfigs[strings.ToUpper(sid)]; ok {
			return cfg
		}
	}
	if name != "" {
		if cfg, ok := s2s.linkConfigs[strings.ToLower(name)]; ok {
			return cfg
		}
	}
	return nil
}

// Broadcast sends an IRC line to all direct links except the specified one.
func (s2s *S2SManager) Broadcast(line string, exceptLink *ServerLink) {
	for _, link := range s2s.AllDirectLinks() {
		if link != exceptLink && link.handshakeDone && !link.IsClosed() {
			link.SendLine(line)
		}
	}
}

// BroadcastMsg sends an ircmsg.Message to all direct links except the specified one.
func (s2s *S2SManager) BroadcastMsg(msg ircmsg.Message, exceptLink *ServerLink) {
	for _, link := range s2s.AllDirectLinks() {
		if link != exceptLink && link.handshakeDone && !link.IsClosed() {
			link.SendMsg(msg)
		}
	}
}

// SendToSID routes an ircmsg.Message towards a specific target server SID.
func (s2s *S2SManager) SendToSID(targetSID string, msg ircmsg.Message) bool {
	s2s.RLock()
	node := s2s.nodesBySID[strings.ToUpper(targetSID)]
	s2s.RUnlock()

	if node != nil && node.NextHop != nil && !node.NextHop.IsClosed() {
		return node.NextHop.SendMsg(msg)
	}
	return false
}

// BroadcastUID announces a newly registered local client across the network.
func (s2s *S2SManager) BroadcastUID(client *Client) {
	details := client.Details()
	ourSID := s2s.server.sid

	modesStr := "+" + client.modes.String()
	if modesStr == "+" {
		modesStr = "+i"
	}

	ipStr := client.IPString()
	if ipStr == "" {
		ipStr = "127.0.0.1"
	}

	realhost := client.RawHostname()
	if realhost == "" {
		realhost = "*"
	}
	account := details.account
	if account == "" {
		account = "*"
	}

	for _, link := range s2s.AllDirectLinks() {
		if !link.handshakeDone || link.IsClosed() {
			continue
		}
		if link.capabs.Has("EUID") {
			link.Send(ourSID, "EUID", details.nick, "1", fmt.Sprintf("%d", client.NickTS().Unix()), modesStr, details.username, details.hostname, ipStr, client.UID(), realhost, account, details.realname)
		} else {
			link.Send(ourSID, "UID", details.nick, "1", fmt.Sprintf("%d", client.NickTS().Unix()), modesStr, details.username, details.hostname, ipStr, client.UID(), details.realname)
		}
	}
}

// BroadcastNick propagates a local client nick change.
func (s2s *S2SManager) BroadcastNick(client *Client, newNick string) {
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, client.UID(), "NICK", newNick, fmt.Sprintf("%d", client.NickTS().Unix())), nil)
}

// BroadcastQuit propagates a local client quit.
func (s2s *S2SManager) BroadcastQuit(client *Client, message string) {
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, client.UID(), "QUIT", message), nil)
}

// BroadcastAway propagates a local client away status update.
func (s2s *S2SManager) BroadcastAway(client *Client, awayMessage string) {
	if awayMessage != "" {
		s2s.BroadcastMsg(ircmsg.MakeMessage(nil, client.UID(), "AWAY", awayMessage), nil)
	} else {
		s2s.BroadcastMsg(ircmsg.MakeMessage(nil, client.UID(), "AWAY"), nil)
	}
}

// BroadcastKill propagates a user kill.
func (s2s *S2SManager) BroadcastKill(killer interface{}, target *Client, reason string) {
	killerPrefix := s2s.server.sid
	if c, ok := killer.(*Client); ok {
		killerPrefix = c.UID()
	}
	path := fmt.Sprintf("%s!%s (%s)", s2s.server.name, s2s.server.name, reason)
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, killerPrefix, "KILL", target.UID(), path), nil)
}

// BroadcastJoin announces a local client joining a channel.
func (s2s *S2SManager) BroadcastJoin(client *Client, channel *Channel) {
	chanTS := fmt.Sprintf("%d", channel.CreatedTime().Unix())
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, client.UID(), "JOIN", chanTS, channel.Name(), "+"), nil)
}

// BroadcastPart announces a local client parting a channel.
func (s2s *S2SManager) BroadcastPart(client *Client, channel *Channel, message string) {
	if message != "" {
		s2s.BroadcastMsg(ircmsg.MakeMessage(nil, client.UID(), "PART", channel.Name(), message), nil)
	} else {
		s2s.BroadcastMsg(ircmsg.MakeMessage(nil, client.UID(), "PART", channel.Name()), nil)
	}
}

// BroadcastKick announces a user kick.
func (s2s *S2SManager) BroadcastKick(channel *Channel, kicker *Client, target *Client, reason string) {
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, kicker.UID(), "KICK", channel.Name(), target.UID(), reason), nil)
}

// BroadcastTopic announces a channel topic change.
func (s2s *S2SManager) BroadcastTopic(channel *Channel, client *Client, topic string) {
	topicTS := fmt.Sprintf("%d", channel.TopicSetTime().Unix())
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, client.UID(), "TB", channel.Name(), topicTS, channel.TopicSetBy(), topic), nil)
}

// BroadcastTMode announces a channel mode change.
func (s2s *S2SManager) BroadcastTMode(channel *Channel, source interface{}, changes modes.ModeChanges) {
	if len(changes) == 0 {
		return
	}
	srcStr := s2s.server.sid
	if c, ok := source.(*Client); ok {
		srcStr = c.UID()
	} else if s, ok := source.(string); ok {
		srcStr = s
	}

	chanTS := fmt.Sprintf("%d", channel.CreatedTime().Unix())
	changeStrs := changes.Strings()
	params := append([]string{chanTS, channel.Name()}, changeStrs...)
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, srcStr, "TMODE", params...), nil)
}

// BroadcastChannelMsg routes a channel message (PRIVMSG/NOTICE) across server links.
func (s2s *S2SManager) BroadcastChannelMsg(channel *Channel, from *Client, command string, msg utils.SplitMessage, exceptLink *ServerLink) {
	outMsg := ircmsg.MakeMessage(nil, from.UID(), command, channel.Name(), msg.Message)
	s2s.BroadcastMsg(outMsg, exceptLink)
}

// SendDirectMsg routes a private message from a client to a remote client.
func (s2s *S2SManager) SendDirectMsg(from *Client, to *Client, command string, msg utils.SplitMessage) {
	if to.Link() != nil && !to.Link().IsClosed() {
		outMsg := ircmsg.MakeMessage(nil, from.UID(), command, to.UID(), msg.Message)
		to.Link().SendMsg(outMsg)
	}
}

// BroadcastInvite forwards an invitation across the network.
func (s2s *S2SManager) BroadcastInvite(source *Client, target *Client, channel *Channel) {
	if target.Link() != nil && !target.Link().IsClosed() {
		chanTS := fmt.Sprintf("%d", channel.CreatedTime().Unix())
		target.Link().Send(source.UID(), "INVITE", target.UID(), channel.Name(), chanTS)
	}
}

// BroadcastKnock forwards a knock request across the network.
func (s2s *S2SManager) BroadcastKnock(source *Client, channel *Channel) {
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, source.UID(), "KNOCK", channel.Name()), nil)
}

// BroadcastWallops sends a wallops message to all server links.
func (s2s *S2SManager) BroadcastWallops(source *Client, text string) {
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, source.UID(), "WALLOPS", text), nil)
}

// BroadcastOperwall sends an operwall message to all server links.
func (s2s *S2SManager) BroadcastOperwall(source *Client, text string) {
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, source.UID(), "OPERWALL", text), nil)
}

// BroadcastSave sends a SAVE collision resolution command across the network.
func (s2s *S2SManager) BroadcastSave(targetUID string, ts int64) {
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, s2s.server.sid, "SAVE", targetUID, fmt.Sprintf("%d", ts)), nil)
}

// BroadcastEncap broadcasts an ENCAP command to a specific target or all servers.
func (s2s *S2SManager) BroadcastEncap(target string, subcommand string, params ...string) {
	allParams := append([]string{target, subcommand}, params...)
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, s2s.server.sid, "ENCAP", allParams...), nil)
}

// ConnectLink attempts an immediate connection to a configured peer link.
func (s2s *S2SManager) ConnectLink(nameOrSID string) error {
	cfg := s2s.FindLinkConfig(nameOrSID, nameOrSID)
	if cfg == nil {
		return fmt.Errorf("no link configuration found for %s", nameOrSID)
	}

	s2s.RLock()
	existingLink := s2s.directLinks[cfg.SID]
	s2s.RUnlock()
	if existingLink != nil && !existingLink.IsClosed() {
		return fmt.Errorf("link to %s (%s) is already connected", cfg.Name, cfg.SID)
	}

	go s2s.startOutboundConnector(cfg)
	return nil
}

// DropLink disconnects a link by name or SID.
func (s2s *S2SManager) DropLink(nameOrSID string, reason string) error {
	s2s.RLock()
	node := s2s.nodesBySID[strings.ToUpper(nameOrSID)]
	if node == nil {
		node = s2s.nodesByName[strings.ToLower(nameOrSID)]
	}
	s2s.RUnlock()

	if node == nil {
		return fmt.Errorf("server %s not found in network graph", nameOrSID)
	}

	if node.IsLocal {
		return fmt.Errorf("cannot drop local server")
	}

	if node.IsDirect && node.NextHop != nil {
		node.NextHop.Close(reason)
		return nil
	}

	// Routed node: send SQUIT command towards uplink
	if reason == "" {
		reason = "Operator SQUIT"
	}
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, s2s.server.sid, "SQUIT", node.SID, reason), nil)
	s2s.HandleServerSplit(node.SID, reason)
	return nil
}

// HandleNetsplit cleans up all remote servers and clients reachable via a disconnected direct link.
func (s2s *S2SManager) HandleNetsplit(lostLink *ServerLink, reason string) {
	s2s.Lock()

	// Find all server nodes routed through this link
	var lostSIDs []string
	var lostNodes []*ServerNode
	for sid, node := range s2s.nodesBySID {
		if node.NextHop == lostLink || node.SID == lostLink.remoteSID {
			lostSIDs = append(lostSIDs, sid)
			lostNodes = append(lostNodes, node)
		}
	}

	// Remove from graph
	for _, sid := range lostSIDs {
		node := s2s.nodesBySID[sid]
		delete(s2s.nodesBySID, sid)
		if node != nil {
			delete(s2s.nodesByName, node.NameCasefolded)
		}
	}
	delete(s2s.directLinks, lostLink.remoteSID)

	s2s.Unlock()

	// Find all remote clients belonging to lost servers and clean them up
	var clientsToQuit []*Client
	for _, c := range s2s.server.clients.AllClients() {
		if c.IsRemote() {
			for _, lostSID := range lostSIDs {
				if c.ServerSID() == lostSID {
					clientsToQuit = append(clientsToQuit, c)
					break
				}
			}
		}
	}

	splitMsg := fmt.Sprintf("%s %s", s2s.server.name, lostLink.remoteName)
	for _, client := range clientsToQuit {
		mask := client.NickMaskString()
		for session := range client.Friends() {
			session.Send(nil, mask, "QUIT", splitMsg)
		}
		for _, ch := range client.Channels() {
			ch.Quit(client)
		}
		s2s.server.clients.Remove(client)
		s2s.server.stats.Remove(true, client.HasMode(modes.Invisible), client.HasMode(modes.Operator))
	}

	// Broadcast SQUIT to any other remaining direct links
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, s2s.server.sid, "SQUIT", lostLink.remoteSID, reason), lostLink)
}

// HandleServerSplit cleans up a specific routed server and its clients.
func (s2s *S2SManager) HandleServerSplit(targetSID string, reason string) {
	s2s.Lock()
	node := s2s.nodesBySID[targetSID]
	if node == nil {
		s2s.Unlock()
		return
	}
	delete(s2s.nodesBySID, targetSID)
	delete(s2s.nodesByName, node.NameCasefolded)
	s2s.Unlock()

	var clientsToQuit []*Client
	for _, c := range s2s.server.clients.AllClients() {
		if c.IsRemote() && c.ServerSID() == targetSID {
			clientsToQuit = append(clientsToQuit, c)
		}
	}

	splitMsg := fmt.Sprintf("%s %s", s2s.server.name, node.Name)
	for _, client := range clientsToQuit {
		mask := client.NickMaskString()
		for session := range client.Friends() {
			session.Send(nil, mask, "QUIT", splitMsg)
		}
		for _, ch := range client.Channels() {
			ch.Quit(client)
		}
		s2s.server.clients.Remove(client)
		s2s.server.stats.Remove(true, client.HasMode(modes.Invisible), client.HasMode(modes.Operator))
	}
}

// RunInboundLink hands off an accepted connection to ServerLink.
func (s2s *S2SManager) RunInboundLink(session *Session, firstLine string, firstMsg ircmsg.Message) {
	// Tear down the temporary client without closing the socket, which is now
	// owned by the server link.
	client := session.client
	client.registrationTimer.Stop()
	session.client = nil
	client.destroy(session)

	link := NewServerLink(s2s.server, session.socket.conn, nil, true)
	go link.WriteLoop()

	// Process first message (PASS)
	if err := s2s.HandleLine(link, firstLine, firstMsg); err != nil {
		link.server.logger.Error("s2s", "Inbound link handshake error", err.Error())
		link.conn.WriteLine([]byte(FormatErrorMsg(err.Error())))
		link.Close(err.Error())
		return
	}

	link.ReadLoop()
}

// startOutboundConnector dials a configured link and maintains connection.
func (s2s *S2SManager) startOutboundConnector(cfg *LinkConfig) {
	addr := net.JoinHostPort(cfg.Hostname, strconv.Itoa(cfg.Port))
	dialTimeout := 10 * time.Second

	for {
		select {
		case <-s2s.stopChan:
			return
		default:
		}

		s2s.server.logger.Info("s2s", "Attempting outbound link connection to", cfg.Name, addr)

		var netConn net.Conn
		var err error
		if cfg.TLS {
			tlsConfig := &tls.Config{
				ServerName:         cfg.Hostname,
				InsecureSkipVerify: true,
			}
			netConn, err = tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, "tcp", addr, tlsConfig)
		} else {
			netConn, err = net.DialTimeout("tcp", addr, dialTimeout)
		}

		if err != nil {
			s2s.server.logger.Warning("s2s", "Failed to connect to link", cfg.Name, err.Error())
			time.Sleep(10 * time.Second)
			continue
		}

		wConn := &utils.WrappedConn{Conn: netConn}
		streamConn := NewIRCStreamConn(wConn)
		link := NewServerLink(s2s.server, streamConn, cfg, false)

		// Send initial outbound handshake
		sendPass := "*"
		if cfg.SendPassword != "" {
			sendPass = cfg.SendPassword
		}
		link.SendLine(fmt.Sprintf("PASS %s TS 6 :%s", sendPass, s2s.server.sid))
		link.SendLine("CAPAB :QS EX CHW IE ENCAP EUID TB KNOCK")
		link.SendLine(fmt.Sprintf("SERVER %s 1 :%s", s2s.server.name, s2s.server.name))
		link.SendLine(fmt.Sprintf("SVINFO 6 6 0 :%d", time.Now().Unix()))

		go link.WriteLoop()
		link.ReadLoop()

		time.Sleep(10 * time.Second)
	}
}

// Shutdown closes all server links.
func (s2s *S2SManager) Shutdown() {
	s2s.Lock()
	if s2s.stopped {
		s2s.Unlock()
		return
	}
	s2s.stopped = true
	close(s2s.stopChan)
	links := make([]*ServerLink, 0, len(s2s.directLinks))
	for _, link := range s2s.directLinks {
		links = append(links, link)
	}
	s2s.Unlock()

	for _, link := range links {
		link.Close("Server shutting down")
	}
}
