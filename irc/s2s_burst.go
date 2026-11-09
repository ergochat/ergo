// Copyright (c) 2026 Ergo Developers
// released under the MIT license

package irc

import (
	"fmt"
	"strings"
	"time"

	"github.com/ergochat/ergo/irc/modes"
)

// BurstState bursts our network state to a newly established link.
func (s2s *S2SManager) BurstState(link *ServerLink) {
	server := s2s.server
	ourSID := server.sid

	server.logger.Info("s2s", "Bursting network state to link", link.remoteName, link.remoteSID)

	// 1. Burst routed servers (excluding ourselves and the peer directly connected)
	for _, node := range s2s.AllServers() {
		if node.SID == ourSID || node.SID == link.remoteSID {
			continue
		}
		// Send :ourSID SID <name> <hopcount+1> <sid> :<desc>
		link.Send(ourSID, "SID", node.Name, fmt.Sprintf("%d", node.HopCount+1), node.SID, node.Description)
	}

	// 2. Burst all known clients on our network
	useEUID := link.capabs.Has("EUID")
	for _, client := range server.clients.AllClients() {
		if client.UID() == "" {
			client.uid = server.uidGen.Next()
			client.serverSID = ourSID
			client.nickTS = client.ctime
			server.clients.Lock()
			server.clients.byUID[client.uid] = client
			server.clients.Unlock()
		}

		hopCount := 1
		if client.IsRemote() {
			hopCount = 2
		}

		modesStr := "+" + client.modes.String()
		if modesStr == "+" {
			modesStr = "+i"
		}

		details := client.Details()
		ipStr := client.IPString()
		if ipStr == "" {
			ipStr = "127.0.0.1"
		}

		originSID := client.ServerSID()
		if originSID == "" {
			originSID = ourSID
		}

		if useEUID {
			realhost := client.RawHostname()
			if realhost == "" {
				realhost = "*"
			}
			account := details.account
			if account == "" {
				account = "*"
			}
			link.Send(originSID, "EUID", details.nick, fmt.Sprintf("%d", hopCount), fmt.Sprintf("%d", client.NickTS().Unix()), modesStr, details.username, details.hostname, ipStr, client.UID(), realhost, account, details.realname)
		} else {
			link.Send(originSID, "UID", details.nick, fmt.Sprintf("%d", hopCount), fmt.Sprintf("%d", client.NickTS().Unix()), modesStr, details.username, details.hostname, ipStr, client.UID(), details.realname)
		}

		// Burst away state if client is away
		if isAway, awayMsg := client.Away(); isAway {
			link.Send(client.UID(), "AWAY", awayMsg)
		}
	}

	// 3. Burst all channels
	for _, ch := range server.channels.Channels() {
		s2s.BurstChannel(link, ch)
	}

	// 4. Send end-of-burst PING to mark burst completion once PONG is received
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	link.lastPingSent = time.Now()
	link.lastPingNonce = nonce
	link.Send(ourSID, "PING", ourSID, link.remoteSID)

	server.logger.Info("s2s", "Finished initial burst to", link.remoteName)
}

// BurstChannel bursts a single channel, its members, banmasks, and topic to a link.
func (s2s *S2SManager) BurstChannel(link *ServerLink, ch *Channel) {
	ourSID := s2s.server.sid
	chname := ch.Name()
	createdTS := fmt.Sprintf("%d", ch.CreatedTime().Unix())

	// Format channel modes
	ch.stateMutex.RLock()
	modeStrs := ch.modeStrings(nil)
	var modeArgs []string
	if len(modeStrs) > 0 {
		modeArgs = modeStrs
	} else {
		modeArgs = []string{"+"}
	}

	// Build member list with TS6 prefixes
	var membersWithPrefixes []string
	for client, data := range ch.members {
		prefix := ""
		if data.modes.HasMode(modes.ChannelOperator) {
			prefix += "@"
		}
		if data.modes.HasMode(modes.Halfop) {
			prefix += "%"
		}
		if data.modes.HasMode(modes.Voice) {
			prefix += "+"
		}
		membersWithPrefixes = append(membersWithPrefixes, prefix+client.UID())
	}
	ch.stateMutex.RUnlock()

	// Send SJOIN (split into chunks if needed to avoid exceeding line length)
	if len(membersWithPrefixes) == 0 {
		params := append([]string{createdTS, chname}, modeArgs...)
		params = append(params, "")
		link.Send(ourSID, "SJOIN", params...)
	} else {
		chunkSize := 15
		for i := 0; i < len(membersWithPrefixes); i += chunkSize {
			end := i + chunkSize
			if end > len(membersWithPrefixes) {
				end = len(membersWithPrefixes)
			}
			chunk := membersWithPrefixes[i:end]
			membersStr := strings.Join(chunk, " ")

			var params []string
			if i == 0 {
				params = append([]string{createdTS, chname}, modeArgs...)
			} else {
				params = []string{createdTS, chname, "+"}
			}
			params = append(params, membersStr)
			link.Send(ourSID, "SJOIN", params...)
		}
	}

	// Burst ban lists
	ch.stateMutex.RLock()
	bans := ch.lists[modes.BanMask].Masks()
	excepts := ch.lists[modes.ExceptMask].Masks()
	invites := ch.lists[modes.InviteMask].Masks()
	ch.stateMutex.RUnlock()

	var banList, exceptList, inviteList []string
	for mask := range bans {
		banList = append(banList, mask)
	}
	for mask := range excepts {
		exceptList = append(exceptList, mask)
	}
	for mask := range invites {
		inviteList = append(inviteList, mask)
	}

	if len(banList) > 0 {
		link.Send(ourSID, "BMASK", createdTS, chname, "b", strings.Join(banList, " "))
	}
	if len(exceptList) > 0 && link.capabs.Has("EX") {
		link.Send(ourSID, "BMASK", createdTS, chname, "e", strings.Join(exceptList, " "))
	}
	if len(inviteList) > 0 && link.capabs.Has("IE") {
		link.Send(ourSID, "BMASK", createdTS, chname, "I", strings.Join(inviteList, " "))
	}

	// Burst topic
	topic := ch.Topic()
	if topic != "" {
		topicTS := fmt.Sprintf("%d", ch.TopicSetTime().Unix())
		topicSetBy := ch.TopicSetBy()
		if topicSetBy == "" {
			topicSetBy = s2s.server.name
		}
		link.Send(ourSID, "TB", chname, topicTS, topicSetBy, topic)
	}
}
