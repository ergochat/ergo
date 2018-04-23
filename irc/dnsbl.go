package irc

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/oragono/oragono/irc/sno"
)

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

func LastIpOctet(addr string) string {
	address := strings.Split(addr, ".")

	return address[len(address)-1]
}

func (server *Server) LookupBlacklistEntry(list *DnsblListEntry, client *Client) []string {
	res, err := net.LookupHost(fmt.Sprintf("%s.%s", ReverseAddress(client.IP()), list.Host))

	var entries []string
	if err != nil {
		server.logger.Info("dnsbl-lookup", fmt.Sprintf("DNSBL loopup failed: %s", err))
		return entries
	}

	if len(res) > 0 {
		for _, addr := range res {
			entries = append(entries, LastIpOctet(addr))
		}
	}

	return entries
}

func sendDnsblMessage(client *Client, message string) {
	/*fmt.Printf(client.server.DnsblConfig().Channel)
	if channel := client.server.DnsblConfig().Channel; channel != "" {
		fmt.Printf(channel)
		client.Send(nil, client.server.name, "PRIVMSG", channel, message)
	}
	*/
	client.server.snomasks.Send(sno.Dnsbl, message)
}

// ProcessBlacklist does
func (server *Server) ProcessBlacklist(client *Client) {

	if !server.DnsblConfig().Enabled || len(server.DnsblConfig().Lists) == 0 {
		// do nothing if dnsbl is disabled, empty lists is treated as if dnsbl was disabled
		return
	}

	type DnsblTypeResponse struct {
		Host   string
		Action string
		Reason string
	}
	var items = []DnsblTypeResponse{}
	for _, list := range server.DnsblConfig().Lists {
		response := DnsblTypeResponse{
			Host:   list.Host,
			Action: list.Action,
			Reason: list.Reason,
		}
		// update action/reason if matched with new ...
		for _, entry := range server.LookupBlacklistEntry(&list, client) {
			if reply, exists := list.Reply[entry]; exists {
				response.Action, response.Reason = reply.Action, reply.Reason
			}
			items = append(items, response)
		}
	}

	// Sort responses so that require-sasl blocks come first. Otherwise A>B (allow>block, allow>notify, block>notify)
	// so that responses come in this order:
	// - require-sasl
	// - allow
	// - block
	// - notify
	sort.Slice(items, func(i, j int) bool {
		if items[i].Action == "require-sasl" {
			return true
		}
		return items[i].Action > items[j].Action
	})

	if len(items) > 0 {
		item := items[0]
		switch item.Action {
		case "require-sasl":
			sendDnsblMessage(client, fmt.Sprintf("Connecting client %s matched %s, requiring SASL to proceed", client.IP(), item.Host))
			client.SetRequireSasl(true, item.Reason)

		case "block":
			sendDnsblMessage(client, fmt.Sprintf("Connecting client %s matched %s - killing", client.IP(), item.Host))
			client.Quit(strings.Replace(item.Reason, "{ip}", client.IPString(), -1))

		case "notify":
			sendDnsblMessage(client, fmt.Sprintf("Connecting client %s matched %s", client.IP(), item.Host))

		case "allow":
			sendDnsblMessage(client, fmt.Sprintf("Allowing host %s [%s]", client.IP(), item.Host))
		}
	}

	return
}

func connectionRequiresSasl(client *Client) bool {
	sasl, reason := client.RequireSasl()

	if !sasl {
		return false
	}

	if client.Account() == "" {
		sendDnsblMessage(client, fmt.Sprintf("Connecting client %s and did not authenticate through SASL - blocking connection", client.IP()))
		client.Quit(strings.Replace(reason, "{ip}", client.IPString(), -1))
		return true
	}

	sendDnsblMessage(client, fmt.Sprintf("Connecting client %s authenticated through SASL - allowing", client.IP()))

	return false
}
