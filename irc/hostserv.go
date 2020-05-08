// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"

	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
)

const (
	hostservHelp = `HostServ lets you manage your vhost (i.e., the string displayed
in place of your client's hostname/IP).`
	hsNickMask = "HostServ!HostServ@localhost"
)

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
			helpShort:         `$bREJECT$b rejects a user's vhost request.`,
			capabs:            []string{"vhosts"},
			enabled:           hostservEnabled,
			minParams:         1,
			maxParams:         2,
			unsplitFinalParam: true,
		},
		"forbid": {
			handler: hsForbidHandler,
			help: `Syntax: $bFORBID <user>$b

FORBID prevents a user from using any vhost, including ones on the offer list.`,
			helpShort: `$bFORBID$b prevents a user from using vhosts.`,
			capabs:    []string{"vhosts"},
			enabled:   hostservEnabled,
			minParams: 1,
			maxParams: 1,
		},
		"permit": {
			handler: hsForbidHandler,
			help: `Syntax: $bPERMIT <user>$b

PERMIT undoes FORBID, allowing the user to TAKE vhosts again.`,
			helpShort: `$bPERMIT$b allows a user to use vhosts again.`,
			capabs:    []string{"vhosts"},
			enabled:   hostservEnabled,
			minParams: 1,
			maxParams: 1,
		},
		"offerlist": {
			handler: hsOfferListHandler,
			help: `Syntax: $bOFFERLIST$b

OFFERLIST lists vhosts that can be chosen without requiring operator approval;
to use one of the listed vhosts, take it with /HOSTSERV TAKE.`,
			helpShort: `$bOFFERLIST$b lists vhosts that can be taken without operator approval.`,
			enabled:   hostservEnabled,
			minParams: 0,
			maxParams: 0,
		},
		"take": {
			handler: hsTakeHandler,
			help: `Syntax: $bTAKE$b <vhost>

TAKE sets your vhost to one of the vhosts in the server's offer list; to see
the offered vhosts, use /HOSTSERV OFFERLIST.`,
			helpShort:    `$bTAKE$b sets your vhost to one of the options from the offer list.`,
			enabled:      hostservEnabled,
			authRequired: true,
			minParams:    1,
			maxParams:    1,
		},
		"setcloaksecret": {
			handler: hsSetCloakSecretHandler,
			help: `Syntax: $bSETCLOAKSECRET$b <secret> [code]

SETCLOAKSECRET can be used to set or rotate the cloak secret. You should use
a cryptographically strong secret. To prevent accidental modification, a
verification code is required; invoking the command without a code will
display the necessary code.`,
			helpShort: `$bSETCLOAKSECRET$b modifies the IP cloaking secret.`,
			capabs:    []string{"vhosts", "rehash"},
			minParams: 1,
			maxParams: 2,
		},
	}
)

// hsNotice sends the client a notice from HostServ
func hsNotice(rb *ResponseBuffer, text string) {
	rb.Add(nil, hsNickMask, "NOTICE", rb.target.Nick(), text)
}

// hsNotifyChannel notifies the designated channel of new vhost activity
func hsNotifyChannel(server *Server, message string) {
	chname := server.Config().Accounts.VHosts.UserRequests.Channel
	channel := server.channels.Get(chname)
	if channel == nil {
		return
	}
	chname = channel.Name()
	for _, client := range channel.Members() {
		client.Send(nil, hsNickMask, "PRIVMSG", chname, message)
	}
}

func hsOnOffHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	enable := false
	if command == "on" {
		enable = true
	}

	_, err := server.accounts.VHostSetEnabled(client, enable)
	if err == errNoVhost {
		hsNotice(rb, client.t(err.Error()))
	} else if err != nil {
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
	_, err := server.accounts.VHostRequest(accountName, vhost, time.Duration(server.Config().Accounts.VHosts.UserRequests.Cooldown))
	if err != nil {
		if throttled, ok := err.(*vhostThrottleExceeded); ok {
			hsNotice(rb, fmt.Sprintf(client.t("You must wait an additional %v before making another request"), throttled.timeRemaining))
		} else if err == errVhostsForbidden {
			hsNotice(rb, client.t("An administrator has denied you the ability to use vhosts"))
		} else {
			hsNotice(rb, client.t("An error occurred"))
		}
	} else {
		hsNotice(rb, client.t("Your vhost request will be reviewed by an administrator"))
		chanMsg := fmt.Sprintf("Account %s requests vhost %s", accountName, vhost)
		hsNotifyChannel(server, chanMsg)
		server.snomasks.Send(sno.LocalVhosts, chanMsg)
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

	if account.VHost.Forbidden {
		hsNotice(rb, client.t("An administrator has denied you the ability to use vhosts"))
		return
	}

	if account.VHost.ApprovedVHost != "" {
		hsNotice(rb, fmt.Sprintf(client.t("Account %[1]s has vhost: %[2]s"), accountName, account.VHost.ApprovedVHost))
		if !account.VHost.Enabled {
			hsNotice(rb, client.t("This vhost is currently disabled, but can be enabled with /HS ON"))
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
	config := server.Config()
	if len(vhost) > config.Accounts.VHosts.MaxLength {
		return errVHostTooLong
	}
	if !config.Accounts.VHosts.ValidRegexp.MatchString(vhost) {
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
	hsNotice(rb, fmt.Sprintf(client.t("There are %[1]d pending requests for vhosts (%[2]d displayed)"), total, len(requests)))
	for i, request := range requests {
		hsNotice(rb, fmt.Sprintf(client.t("%[1]d. User %[2]s requests vhost: %[3]s"), i+1, request.Account, request.RequestedVHost))
	}
}

func hsApproveHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	user := params[0]

	vhostInfo, err := server.accounts.VHostApprove(user)
	if err != nil {
		hsNotice(rb, client.t("An error occurred"))
	} else {
		hsNotice(rb, fmt.Sprintf(client.t("Successfully approved vhost request for %s"), user))
		chanMsg := fmt.Sprintf("Oper %[1]s approved vhost %[2]s for account %[3]s", client.Nick(), vhostInfo.ApprovedVHost, user)
		hsNotifyChannel(server, chanMsg)
		server.snomasks.Send(sno.LocalVhosts, chanMsg)
		for _, client := range server.accounts.AccountToClients(user) {
			client.Send(nil, hsNickMask, "NOTICE", client.Nick(), client.t("Your vhost request was approved by an administrator"))
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
		server.snomasks.Send(sno.LocalVhosts, chanMsg)
		for _, client := range server.accounts.AccountToClients(user) {
			if reason == "" {
				client.Send(nil, hsNickMask, "NOTICE", client.Nick(), client.t("Your vhost request was rejected by an administrator"))
			} else {
				client.Send(nil, hsNickMask, "NOTICE", client.Nick(), fmt.Sprintf(client.t("Your vhost request was rejected by an administrator. The reason given was: %s"), reason))
			}
		}
	}
}

func hsForbidHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	user := params[0]
	forbidden := command == "forbid"

	_, err := server.accounts.VHostForbid(user, forbidden)
	if err == errAccountDoesNotExist {
		hsNotice(rb, client.t("No such account"))
	} else if err != nil {
		hsNotice(rb, client.t("An error occurred"))
	} else {
		if forbidden {
			hsNotice(rb, fmt.Sprintf(client.t("User %s is no longer allowed to use vhosts"), user))
		} else {
			hsNotice(rb, fmt.Sprintf(client.t("User %s is now allowed to use vhosts"), user))
		}
	}
}

func hsOfferListHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	vhostConfig := server.Config().Accounts.VHosts
	if len(vhostConfig.OfferList) == 0 {
		if vhostConfig.UserRequests.Enabled {
			hsNotice(rb, client.t("The server does not offer any vhosts, but you can request one with /HOSTSERV REQUEST"))
		} else {
			hsNotice(rb, client.t("The server does not offer any vhosts"))
		}
	} else {
		hsNotice(rb, client.t("The following vhosts are available and can be chosen with /HOSTSERV TAKE:"))
		for _, vhost := range vhostConfig.OfferList {
			hsNotice(rb, vhost)
		}
	}
}

func hsTakeHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	config := server.Config()
	vhost := params[0]
	found := false
	for _, offered := range config.Accounts.VHosts.OfferList {
		if offered == vhost {
			found = true
		}
	}
	if !found {
		hsNotice(rb, client.t("That vhost isn't being offered by the server"))
		return
	}

	account := client.Account()
	_, err := server.accounts.VHostTake(account, vhost, time.Duration(config.Accounts.VHosts.UserRequests.Cooldown))
	if err != nil {
		if throttled, ok := err.(*vhostThrottleExceeded); ok {
			hsNotice(rb, fmt.Sprintf(client.t("You must wait an additional %v before taking a vhost"), throttled.timeRemaining))
		} else if err == errVhostsForbidden {
			hsNotice(rb, client.t("An administrator has denied you the ability to use vhosts"))
		} else {
			hsNotice(rb, client.t("An error occurred"))
		}
	} else {
		hsNotice(rb, client.t("Successfully set vhost"))
		server.snomasks.Send(sno.LocalVhosts, fmt.Sprintf("Client %s (account %s) took vhost %s", client.Nick(), account, vhost))
	}
}

func hsSetCloakSecretHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	secret := params[0]
	expectedCode := utils.ConfirmationCode(secret, server.ctime)
	if len(params) == 1 || params[1] != expectedCode {
		hsNotice(rb, ircfmt.Unescape(client.t("$bWarning: changing the cloak secret will invalidate stored ban/invite/exception lists.$b")))
		hsNotice(rb, fmt.Sprintf(client.t("To confirm, run this command: %s"), fmt.Sprintf("/HS SETCLOAKSECRET %s %s", secret, expectedCode)))
		return
	}
	StoreCloakSecret(server.store, secret)
	hsNotice(rb, client.t("Rotated the cloak secret; you must rehash or restart the server for it to take effect"))
}
