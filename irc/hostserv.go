// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

const hostservHelp = `HostServ lets you manage your vhost (i.e., the string displayed
in place of your client's hostname/IP).

To see in-depth help for a specific HostServ command, try:
    $b/HS HELP <command>$b

Here are the commands you can use:
%s`

var (
	errVHostBadCharacters = errors.New("Vhost contains prohibited characters")
	errVHostTooLong       = errors.New("Vhost is too long")
	// ascii only for now
	defaultValidVhostRegex = regexp.MustCompile(`^[0-9A-Za-z.\-_/]+$`)
)

func hostservEnabled(config *Config) bool {
	return config.Accounts.VHosts.Enabled
}

func hostservRequestsEnabled(config *Config) bool {
	return config.Accounts.VHosts.Enabled && config.Accounts.VHosts.UserRequests.Enabled
}

var (
	hostservCommands = map[string]*serviceCommand{
		"on": {
			handler: hsOnOffHandler,
			help: `Syntax: $bON$b

ON enables your vhost, if you have one approved.`,
			helpShort:    `$bON$b enables your vhost, if you have one approved.`,
			authRequired: true,
			enabled:      hostservEnabled,
		},
		"off": {
			handler: hsOnOffHandler,
			help: `Syntax: $bOFF$b

OFF disables your vhost, if you have one approved.`,
			helpShort:    `$bOFF$b disables your vhost, if you have one approved.`,
			authRequired: true,
			enabled:      hostservEnabled,
		},
		"request": {
			handler: hsRequestHandler,
			help: `Syntax: $bREQUEST <vhost>$b

REQUEST requests that a new vhost by assigned to your account. The request must
then be approved by a server operator.`,
			helpShort:    `$bREQUEST$b requests a new vhost, pending operator approval.`,
			authRequired: true,
			enabled:      hostservRequestsEnabled,
			minParams:    1,
		},
		"status": {
			handler: hsStatusHandler,
			help: `Syntax: $bSTATUS [user]$b

STATUS displays your current vhost, if any, and the status of your most recent
request for a new one. A server operator can view someone else's status.`,
			helpShort: `$bSTATUS$b shows your vhost and request status.`,
			enabled:   hostservEnabled,
		},
		"set": {
			handler: hsSetHandler,
			help: `Syntax: $bSET <user> <vhost>$b

SET sets a user's vhost, bypassing the request system.`,
			helpShort: `$bSET$b sets a user's vhost.`,
			capabs:    []string{"vhosts"},
			enabled:   hostservEnabled,
			minParams: 2,
		},
		"del": {
			handler: hsSetHandler,
			help: `Syntax: $bDEL <user>$b

DEL deletes a user's vhost.`,
			helpShort: `$bDEL$b deletes a user's vhost.`,
			capabs:    []string{"vhosts"},
			enabled:   hostservEnabled,
			minParams: 1,
		},
		"waiting": {
			handler: hsWaitingHandler,
			help: `Syntax: $bWAITING$b

WAITING shows a list of pending vhost requests, which can then be approved
or rejected.`,
			helpShort: `$bWAITING$b shows a list of pending vhost requests.`,
			capabs:    []string{"vhosts"},
			enabled:   hostservEnabled,
		},
		"approve": {
			handler: hsApproveHandler,
			help: `Syntax: $bAPPROVE <user>$b

APPROVE approves a user's vhost request.`,
			helpShort: `$bAPPROVE$b approves a user's vhost request.`,
			capabs:    []string{"vhosts"},
			enabled:   hostservEnabled,
			minParams: 1,
		},
		"reject": {
			handler: hsRejectHandler,
			help: `Syntax: $bREJECT <user> [<reason>]$b

REJECT rejects a user's vhost request, optionally giving them a reason
for the rejection.`,
			helpShort: `$bREJECT$b rejects a user's vhost request.`,
			capabs:    []string{"vhosts"},
			enabled:   hostservEnabled,
			minParams: 1,
			maxParams: 2,
		},
	}
)

// hsNotice sends the client a notice from HostServ
func hsNotice(rb *ResponseBuffer, text string) {
	rb.Add(nil, "HostServ", "NOTICE", rb.target.Nick(), text)
}

// hsNotifyChannel notifies the designated channel of new vhost activity
func hsNotifyChannel(server *Server, message string) {
	chname := server.AccountConfig().VHosts.UserRequests.Channel
	channel := server.channels.Get(chname)
	if channel == nil {
		return
	}
	chname = channel.Name()
	for _, client := range channel.Members() {
		client.Send(nil, "HostServ", "PRIVMSG", chname, message)
	}
}

func hsOnOffHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	enable := false
	if command == "on" {
		enable = true
	}

	_, err := server.accounts.VHostSetEnabled(client, enable)
	if err != nil {
		hsNotice(rb, client.t("An error occurred"))
	} else if enable {
		hsNotice(rb, client.t("Successfully enabled your vhost"))
	} else {
		hsNotice(rb, client.t("Successfully disabled your vhost"))
	}
}

func hsRequestHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	vhost := params[0]
	if validateVhost(server, vhost, false) != nil {
		hsNotice(rb, client.t("Invalid vhost"))
		return
	}

	accountName := client.Account()
	account, err := server.accounts.LoadAccount(client.Account())
	if err != nil {
		hsNotice(rb, client.t("An error occurred"))
		return
	}
	elapsed := time.Now().Sub(account.VHost.LastRequestTime)
	remainingTime := server.AccountConfig().VHosts.UserRequests.Cooldown - elapsed
	// you can update your existing request, but if you were rejected,
	// you can't spam a replacement request
	if account.VHost.RequestedVHost == "" && remainingTime > 0 {
		hsNotice(rb, fmt.Sprintf(client.t("You must wait an additional %v before making another request"), remainingTime))
		return
	}

	_, err = server.accounts.VHostRequest(accountName, vhost)
	if err != nil {
		hsNotice(rb, client.t("An error occurred"))
	} else {
		hsNotice(rb, fmt.Sprintf(client.t("Your vhost request will be reviewed by an administrator")))
		chanMsg := fmt.Sprintf("Account %s requests vhost %s", accountName, vhost)
		hsNotifyChannel(server, chanMsg)
		// TODO send admins a snomask of some kind
	}
}

func hsStatusHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var accountName string
	if len(params) > 0 {
		if !client.HasRoleCapabs("vhosts") {
			hsNotice(rb, client.t("Command restricted"))
			return
		}
		accountName = params[0]
	} else {
		accountName = client.Account()
		if accountName == "" {
			hsNotice(rb, client.t("You're not logged into an account"))
			return
		}
	}

	account, err := server.accounts.LoadAccount(accountName)
	if err != nil {
		if err != errAccountDoesNotExist {
			server.logger.Warning("internal", "error loading account info", accountName, err.Error())
		}
		hsNotice(rb, client.t("No such account"))
		return
	}

	if account.VHost.ApprovedVHost != "" {
		hsNotice(rb, fmt.Sprintf(client.t("Account %s has vhost: %s"), accountName, account.VHost.ApprovedVHost))
		if !account.VHost.Enabled {
			hsNotice(rb, fmt.Sprintf(client.t("This vhost is currently disabled, but can be enabled with /HS ON")))
		}
	} else {
		hsNotice(rb, fmt.Sprintf(client.t("Account %s has no vhost"), accountName))
	}
	if account.VHost.RequestedVHost != "" {
		hsNotice(rb, fmt.Sprintf(client.t("A request is pending for vhost: %s"), account.VHost.RequestedVHost))
	}
	if account.VHost.RejectedVHost != "" {
		hsNotice(rb, fmt.Sprintf(client.t("A request was previously made for vhost: %s"), account.VHost.RejectedVHost))
		hsNotice(rb, fmt.Sprintf(client.t("It was rejected for reason: %s"), account.VHost.RejectionReason))
	}
}

func validateVhost(server *Server, vhost string, oper bool) error {
	ac := server.AccountConfig()
	if len(vhost) > ac.VHosts.MaxLength {
		return errVHostTooLong
	}
	if !ac.VHosts.ValidRegexp.MatchString(vhost) {
		return errVHostBadCharacters
	}
	return nil
}

func hsSetHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	user := params[0]
	var vhost string

	if command == "set" {
		vhost = params[1]
		if validateVhost(server, vhost, true) != nil {
			hsNotice(rb, client.t("Invalid vhost"))
			return
		}
	}
	// else: command == "del", vhost == ""

	_, err := server.accounts.VHostSet(user, vhost)
	if err != nil {
		hsNotice(rb, client.t("An error occurred"))
	} else if vhost != "" {
		hsNotice(rb, client.t("Successfully set vhost"))
	} else {
		hsNotice(rb, client.t("Successfully cleared vhost"))
	}
}

func hsWaitingHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	requests, total := server.accounts.VHostListRequests(10)
	hsNotice(rb, fmt.Sprintf(client.t("There are %d pending requests for vhosts (%d displayed)"), total, len(requests)))
	for i, request := range requests {
		hsNotice(rb, fmt.Sprintf(client.t("%d. User %s requests vhost: %s"), i+1, request.Account, request.RequestedVHost))
	}
}

func hsApproveHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	user := params[0]

	vhostInfo, err := server.accounts.VHostApprove(user)
	if err != nil {
		hsNotice(rb, client.t("An error occurred"))
	} else {
		hsNotice(rb, fmt.Sprintf(client.t("Successfully approved vhost request for %s"), user))
		chanMsg := fmt.Sprintf("Oper %s approved vhost %s for account %s", client.Nick(), vhostInfo.ApprovedVHost, user)
		hsNotifyChannel(server, chanMsg)
		for _, client := range server.accounts.AccountToClients(user) {
			client.Notice(client.t("Your vhost request was approved by an administrator"))
		}
	}
}

func hsRejectHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var reason string
	user := params[0]
	if len(params) > 1 {
		reason = params[1]
	}

	vhostInfo, err := server.accounts.VHostReject(user, reason)
	if err != nil {
		hsNotice(rb, client.t("An error occurred"))
	} else {
		hsNotice(rb, fmt.Sprintf(client.t("Successfully rejected vhost request for %s"), user))
		chanMsg := fmt.Sprintf("Oper %s rejected vhost %s for account %s, with the reason: %v", client.Nick(), vhostInfo.RejectedVHost, user, reason)
		hsNotifyChannel(server, chanMsg)
		for _, client := range server.accounts.AccountToClients(user) {
			if reason == "" {
				client.Notice("Your vhost request was rejected by an administrator")
			} else {
				client.Notice(fmt.Sprintf(client.t("Your vhost request was rejected by an administrator. The reason given was: %s"), reason))
			}
		}
	}
}
