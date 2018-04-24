package irc

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
)

// Constants
type DnsblActionType uint

const (
	DnsblRequireSaslReply DnsblActionType = iota
	DnsblAllowReply
	DnsblBlockReply
	DnsblNotifyReply
	DnsblUnknownReply
)

// LookupBlacklistEntry performs a lookup on the dnsbl on the client IP
func (server *Server) LookupBlacklistEntry(list *DnsblListEntry, client *Client) []string {
	res, err := net.LookupHost(fmt.Sprintf("%s.%s", utils.ReverseAddress(client.IP()), list.Host))

	var entries []string
	if err != nil {
		// An error may indicate that the A record was not found
		return entries
	}

	if len(res) > 0 {
		for _, addr := range res {
			octet := strings.Split(addr, ".")
			if len(octet) > 0 {
				entries = append(entries, octet[len(octet)-1])
			}
		}
	}

	return entries
}

// ProcessBlacklist does
func (server *Server) ProcessBlacklist(client *Client) {

	if !server.DnsblConfig().Enabled || len(server.DnsblConfig().Lists) == 0 {
		// do nothing if dnsbl is disabled, empty lists is treated as if dnsbl was disabled
		return
	}

	lists := server.DnsblConfig().Lists

	type DnsblTypeResponse struct {
		Host       string
		ActionType DnsblActionType
		Reason     string
	}
	var items = []DnsblTypeResponse{}
	for _, list := range lists {
		response := DnsblTypeResponse{
			Host:       list.Host,
			ActionType: list.ActionType,
			Reason:     list.Reason,
		}
		// update action/reason if matched with new ...
		for _, entry := range server.LookupBlacklistEntry(&list, client) {
			if reply, exists := list.Reply[entry]; exists {
				response.ActionType, response.Reason = list.ActionType, reply.Reason
			}
			items = append(items, response)
		}
	}

	// Sorts in the following order: require-sasl, allow, block, notify
	sort.Slice(items, func(i, j int) bool {
		return items[i].ActionType > items[j].ActionType
	})

	if len(items) > 0 {
		item := items[0]
		switch item.ActionType {
		case DnsblRequireSaslReply:
			dnsblSendServiceMessage(server, fmt.Sprintf("Connecting client %s matched %s, requiring SASL to proceed", client.IP(), item.Host))
			client.SetRequireSasl(true, item.Reason)

		case DnsblBlockReply:
			dnsblSendServiceMessage(server, fmt.Sprintf("Connecting client %s matched %s - killing", client.IP(), item.Host))
			client.Quit(strings.Replace(item.Reason, "{ip}", client.IPString(), -1))

		case DnsblNotifyReply:
			dnsblSendServiceMessage(server, fmt.Sprintf("Connecting client %s matched %s", client.IP(), item.Host))

		case DnsblAllowReply:
			dnsblSendServiceMessage(server, fmt.Sprintf("Allowing host %s [%s]", client.IP(), item.Host))
		}
	}

	return
}

func ConnectionRequiresSasl(client *Client) bool {
	sasl, reason := client.RequireSasl()

	if !sasl {
		return false
	}

	if client.Account() == "" {
		dnsblSendServiceMessage(client.server, fmt.Sprintf("Connecting client %s and did not authenticate through SASL - blocking connection", client.IP()))
		client.Quit(strings.Replace(reason, "{ip}", client.IPString(), -1))
		return true
	}

	dnsblSendServiceMessage(client.server, fmt.Sprintf("Connecting client %s authenticated through SASL - allowing", client.IP()))

	return false
}

func dnsblSendServiceMessage(server *Server, message string) {
	channel := server.DnsblConfig().Channel
	if channel != "" {
		server.serviceNotifyChannel(server.name, channel, message)
	}
	server.snomasks.Send(sno.Dnsbl, message)
}
