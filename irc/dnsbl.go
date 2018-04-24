package irc

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/oragono/oragono/irc/sno"
)

// Constants
const (
	DnsblRequireSaslReply uint = iota
	DnsblAllowReply
	DnsblBlockReply
	DnsblNotifyReply
	DnsblUnknownReply
)

// ReverseAddress returns IPv4 addresses reversed
func ReverseAddress(ip net.IP) string {
	// This is a IPv4 address
	if ip.To4() != nil {
		address := strings.Split(ip.String(), ".")

		for i, j := 0, len(address)-1; i < j; i, j = i+1, j-1 {
			address[i], address[j] = address[j], address[i]
		}

		return strings.Join(address, ".")
	}

	// fallback to returning the String of IP if it is not an IPv4 address
	return ip.String()
}

// LookupBlacklistEntry performs a lookup on the dnsbl on the client IP
func (server *Server) LookupBlacklistEntry(list *DnsblListEntry, client *Client) []string {
	res, err := net.LookupHost(fmt.Sprintf("%s.%s", ReverseAddress(client.IP()), list.Host))

	var entries []string
	if err != nil {
		server.logger.Info("dnsbl-lookup", fmt.Sprintf("DNSBL loopup failed: %s", err))
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

	channel := server.DnsblConfig().Channel
	lists := server.DnsblConfig().Lists

	type DnsblTypeResponse struct {
		Host       string
		ActionType uint
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
			client.sendServerMessage("", channel, sno.Dnsbl, fmt.Sprintf("Connecting client %s matched %s, requiring SASL to proceed", client.IP(), item.Host))
			client.SetRequireSasl(true, item.Reason)

		case DnsblBlockReply:
			client.sendServerMessage("", channel, sno.Dnsbl, fmt.Sprintf("Connecting client %s matched %s - killing", client.IP(), item.Host))
			client.Quit(strings.Replace(item.Reason, "{ip}", client.IPString(), -1))

		case DnsblNotifyReply:
			client.sendServerMessage("", channel, sno.Dnsbl, fmt.Sprintf("Connecting client %s matched %s", client.IP(), item.Host))

		case DnsblAllowReply:
			client.sendServerMessage("", channel, sno.Dnsbl, fmt.Sprintf("Allowing host %s [%s]", client.IP(), item.Host))
		}
	}

	return
}

func connectionRequiresSasl(client *Client) bool {
	sasl, reason := client.RequireSasl()

	if !sasl {
		return false
	}

	channel := client.server.DnsblConfig().Channel

	if client.Account() == "" {
		//client.sendServerMessage("", channel, sno.Dnsbl, fmt.Sprintf("Connecting client %s and did not authenticate through SASL - blocking connection", client.IP()))
		client.Quit(strings.Replace(reason, "{ip}", client.IPString(), -1))
		return true
	}

	client.sendServerMessage("", channel, sno.Dnsbl, fmt.Sprintf("Connecting client %s authenticated through SASL - allowing", client.IP()))

	return false
}

func (client *Client) sendServerMessage(pseudo string, channel string, mask sno.Mask, message string) {
	/*
	   This causes an out of bounds error - possibly in client.Send() - investigate further
	   	if pseudo == "" {
	   		pseudo = client.server.name
	   	}

	   	if channel != "" {
	   		client.Send(nil, pseudo, "PRIVMSG", channel, message)
	   	}
	*/
	client.server.snomasks.Send(mask, message)
}
