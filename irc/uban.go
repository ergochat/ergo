// Copyright (c) 2021 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ergochat/irc-go/ircmsg"

	"github.com/ergochat/ergo/irc/custime"
	"github.com/ergochat/ergo/irc/flatip"
	"github.com/ergochat/ergo/irc/sno"
	"github.com/ergochat/ergo/irc/utils"
)

func consumeDuration(params []string, rb *ResponseBuffer) (duration time.Duration, requireSASL bool, remainingParams []string, err error) {
	remainingParams = params
	for {
		if duration == 0 && 2 <= len(remainingParams) && strings.ToLower(remainingParams[0]) == "duration" {
			duration, err = custime.ParseDuration(remainingParams[1])
			if err != nil {
				rb.Notice(rb.session.client.t("Invalid time duration for NS SUSPEND"))
				return
			}
			remainingParams = remainingParams[2:]
			continue
		}
		if !requireSASL && 1 <= len(remainingParams) && strings.ToLower(remainingParams[0]) == "require-sasl" {
			requireSASL = true
			remainingParams = remainingParams[1:]
			continue
		}
		break
	}
	return
}

// a UBAN target is one of these syntactically unambiguous entities:
// an IP, a CIDR, a NUH mask, or an account name
type ubanType uint

const (
	ubanCIDR ubanType = iota
	ubanNickmask
	ubanNick
)

// tagged union, i guess
type ubanTarget struct {
	banType ubanType

	cidr       flatip.IPNet
	matcher    *regexp.Regexp
	nickOrMask string
}

func parseUbanTarget(param string) (target ubanTarget, err error) {
	if utils.SafeErrorParam(param) == "*" {
		err = errInvalidParams
		return
	}

	ipnet, ipErr := flatip.ParseToNormalizedNet(param)
	if ipErr == nil {
		target.banType = ubanCIDR
		target.cidr = ipnet
		return
	}

	if strings.IndexByte(param, '!') != -1 || strings.IndexByte(param, '@') != -1 {
		canonicalized, cErr := CanonicalizeMaskWildcard(param, false, nil)
		if cErr != nil {
			err = errInvalidParams
			return
		}
		re, reErr := utils.CompileGlob(canonicalized, false)
		if reErr != nil {
			err = errInvalidParams
			return
		}
		target.banType = ubanNickmask
		target.nickOrMask = canonicalized
		target.matcher = re
		return
	}

	if _, cErr := CasefoldName(param); cErr == nil {
		target.banType = ubanNick
		target.nickOrMask = param
		return
	}

	err = errInvalidParams
	return
}

// UBAN <subcommand> [target] [DURATION <duration>] [reason...]
func ubanHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	subcommand := strings.ToLower(msg.Params[0])
	params := msg.Params[1:]
	var target ubanTarget
	if subcommand != "list" {
		if len(msg.Params) == 1 {
			rb.Add(nil, client.server.name, "FAIL", "UBAN", "INVALID_PARAMS", client.t("Not enough parameters"))
			return false
		}
		var parseErr error
		target, parseErr = parseUbanTarget(params[0])
		if parseErr != nil {
			rb.Add(nil, client.server.name, "FAIL", "UBAN", "INVALID_PARAMS", client.t("Couldn't parse ban target"))
			return false
		}
		params = params[1:]
	}

	switch subcommand {
	case "add":
		return ubanAddHandler(client, target, params, rb)
	case "del", "remove", "rm":
		return ubanDelHandler(client, target, params, rb)
	case "list":
		return ubanListHandler(client, params, rb)
	case "info":
		return ubanInfoHandler(client, target, params, rb)
	default:
		rb.Add(nil, server.name, "FAIL", "UBAN", "UNKNOWN_COMMAND", client.t("Unknown command"))
		return false
	}
}

func sessionsForCIDR(server *Server, cidr flatip.IPNet, exclude *Session, requireSASL bool) (sessions []*Session, nicks []string) {
	for _, client := range server.clients.AllClients() {
		if requireSASL && client.Account() != "" {
			continue
		}
		for _, session := range client.Sessions() {
			seen := false
			if session != exclude && cidr.Contains(flatip.FromNetIP(session.IP())) {
				sessions = append(sessions, session)
				if !seen {
					seen = true
					nicks = append(nicks, session.client.Nick())
				}
			}
		}
	}
	return
}

func ubanAddHandler(client *Client, target ubanTarget, params []string, rb *ResponseBuffer) bool {
	duration, requireSASL, params, err := consumeDuration(params, rb)
	if err != nil {
		return false
	}

	operReason := strings.Join(params, " ")

	switch target.banType {
	case ubanCIDR:
		err = ubanAddCIDR(client, target, duration, requireSASL, operReason, rb)
	case ubanNickmask:
		err = ubanAddNickmask(client, target, duration, operReason, rb)
	case ubanNick:
		err = ubanAddAccount(client, target, duration, operReason, rb)
	}
	if err == nil {
		announceUban(client, true, target, duration, requireSASL, operReason)
	}
	return false
}

func announceUban(client *Client, add bool, target ubanTarget, duration time.Duration, requireSASL bool, operReason string) {
	oper := client.Oper()
	if oper == nil {
		return
	}
	operName := oper.Name

	var buf strings.Builder
	fmt.Fprintf(&buf, "Operator %s", operName)

	if add {
		buf.WriteString(" added")
	} else {
		buf.WriteString(" removed")
	}
	switch target.banType {
	case ubanCIDR:
		buf.WriteString(" an IP-based")
	case ubanNickmask:
		buf.WriteString(" a NUH-mask")
	case ubanNick:
		buf.WriteString(" an account suspension")
	}
	buf.WriteString(" UBAN against ")
	switch target.banType {
	case ubanCIDR:
		buf.WriteString(target.cidr.String())
	case ubanNickmask, ubanNick:
		buf.WriteString(target.nickOrMask)
	}
	if duration != 0 {
		fmt.Fprintf(&buf, " [duration: %v]", duration)
	}
	if requireSASL {
		buf.WriteString(" [require-SASL]")
	}
	if operReason != "" {
		fmt.Fprintf(&buf, " [reason: %s]", operReason)
	}
	line := buf.String()
	client.server.snomasks.Send(sno.LocalXline, line)
	client.server.logger.Info("opers", line)
}

func ubanAddCIDR(client *Client, target ubanTarget, duration time.Duration, requireSASL bool, operReason string, rb *ResponseBuffer) (err error) {
	err = client.server.dlines.AddNetwork(target.cidr, duration, requireSASL, "", operReason, client.Oper().Name)
	if err == nil {
		rb.Notice(fmt.Sprintf(client.t("Successfully added UBAN for %s"), target.cidr.HumanReadableString()))
	} else {
		client.server.logger.Error("internal", "ubanAddCIDR failed", err.Error())
		rb.Notice(client.t("An error occurred"))
		return
	}

	sessions, nicks := sessionsForCIDR(client.server, target.cidr, rb.session, requireSASL)
	for _, session := range sessions {
		session.client.Quit("You have been banned from this server", session)
		session.client.destroy(session)
	}

	if len(sessions) != 0 {
		rb.Notice(fmt.Sprintf(client.t("Killed %[1]d active client(s) from %[2]s, associated with %[3]d nickname(s):"), len(sessions), target.cidr.String(), len(nicks)))
		for _, line := range utils.BuildTokenLines(400, nicks, " ") {
			rb.Notice(line)
		}
	}
	return
}

func ubanAddNickmask(client *Client, target ubanTarget, duration time.Duration, operReason string, rb *ResponseBuffer) (err error) {
	err = client.server.klines.AddMask(target.nickOrMask, duration, "", operReason, client.Oper().Name)
	if err == nil {
		rb.Notice(fmt.Sprintf(client.t("Successfully added UBAN for %s"), target.nickOrMask))
	} else {
		client.server.logger.Error("internal", "ubanAddNickmask failed", err.Error())
		rb.Notice(client.t("An error occurred"))
		return
	}

	var killed []string
	var alwaysOn []string
	for _, mcl := range client.server.clients.AllClients() {
		if mcl != client && target.matcher.MatchString(mcl.NickMaskCasefolded()) {
			if !mcl.AlwaysOn() {
				killed = append(killed, mcl.Nick())
				mcl.Quit("You have been banned from this server", nil)
				mcl.destroy(nil)
			} else {
				alwaysOn = append(alwaysOn, mcl.Nick())
			}
		}
	}
	if len(killed) != 0 {
		rb.Notice(fmt.Sprintf(client.t("Killed %d clients:"), len(killed)))
		for _, line := range utils.BuildTokenLines(400, killed, " ") {
			rb.Notice(line)
		}
	}
	if len(alwaysOn) != 0 {
		rb.Notice(fmt.Sprintf(client.t("Warning: %d clients matched this rule, but were not killed due to being always-on:"), len(alwaysOn)))
		for _, line := range utils.BuildTokenLines(400, alwaysOn, " ") {
			rb.Notice(line)
		}
		rb.Notice(client.t("You can suspend their accounts instead; try /UBAN ADD <nickname>"))
	}
	return
}

func ubanAddAccount(client *Client, target ubanTarget, duration time.Duration, operReason string, rb *ResponseBuffer) (err error) {
	account := target.nickOrMask
	// TODO this doesn't enumerate all sessions if ForceNickEqualsAccount is disabled
	var sessionData []SessionData
	if mcl := client.server.clients.Get(account); mcl != nil {
		sessionData, _ = mcl.AllSessionData(nil, true)
	}

	err = client.server.accounts.Suspend(account, duration, client.Oper().Name, operReason)
	switch err {
	case nil:
		rb.Notice(fmt.Sprintf(client.t("Successfully suspended account %s"), account))
		if len(sessionData) != 0 {
			rb.Notice(fmt.Sprintf(client.t("Disconnected %d client(s) associated with the account, using the following IPs:"), len(sessionData)))
			for i, d := range sessionData {
				rb.Notice(fmt.Sprintf("%d. %s", i+1, d.ip.String()))
			}
		}
	case errAccountDoesNotExist:
		rb.Notice(client.t("No such account"))
	default:
		rb.Notice(client.t("An error occurred"))
	}
	return
}

func ubanDelHandler(client *Client, target ubanTarget, params []string, rb *ResponseBuffer) bool {
	var err error
	var targetString string
	switch target.banType {
	case ubanCIDR:
		if target.cidr.PrefixLen == 128 {
			client.server.connectionLimiter.ResetThrottle(target.cidr.IP)
			rb.Notice(fmt.Sprintf(client.t("Reset throttle for IP: %s"), target.cidr.IP.String()))
		}
		targetString = target.cidr.HumanReadableString()
		err = client.server.dlines.RemoveNetwork(target.cidr)
	case ubanNickmask:
		targetString = target.nickOrMask
		err = client.server.klines.RemoveMask(target.nickOrMask)
	case ubanNick:
		targetString = target.nickOrMask
		err = client.server.accounts.Unsuspend(target.nickOrMask)
	}
	if err == nil {
		rb.Notice(fmt.Sprintf(client.t("Successfully removed ban on %s"), targetString))
		announceUban(client, false, target, 0, false, "")
	} else {
		rb.Notice(fmt.Sprintf(client.t("Could not remove ban: %v"), err))
	}
	return false
}

func ubanListHandler(client *Client, params []string, rb *ResponseBuffer) bool {
	allDlines := client.server.dlines.AllBans()
	rb.Notice(fmt.Sprintf(client.t("There are %d active IP/network ban(s) (DLINEs)"), len(allDlines)))
	for key, info := range allDlines {
		rb.Notice(formatBanForListing(client, key, info))
	}
	rb.Notice(client.t("Some IPs may also be prevented from connecting by the connection limiter and/or throttler"))

	allKlines := client.server.klines.AllBans()
	rb.Notice(fmt.Sprintf(client.t("There are %d active ban(s) on nick-user-host masks (KLINEs)"), len(allKlines)))
	for key, info := range allKlines {
		rb.Notice(formatBanForListing(client, key, info))
	}

	listAccountSuspensions(client, rb, client.server.name)

	return false
}

func ubanInfoHandler(client *Client, target ubanTarget, params []string, rb *ResponseBuffer) bool {
	switch target.banType {
	case ubanCIDR:
		ubanInfoCIDR(client, target, rb)
	case ubanNickmask:
		ubanInfoNickmask(client, target, rb)
	case ubanNick:
		ubanInfoNick(client, target, rb)
	}
	return false
}

func ubanInfoCIDR(client *Client, target ubanTarget, rb *ResponseBuffer) {
	if target.cidr.PrefixLen == 128 {
		netName, status := client.server.connectionLimiter.Status(target.cidr.IP)
		if status.Exempt {
			rb.Notice(fmt.Sprintf(client.t("IP %s is exempt from connection limits"), target.cidr.IP.String()))
		} else {
			rb.Notice(fmt.Sprintf(client.t("Network %[1]s has %[2]d active connections out of a maximum of %[3]d"), netName, status.Count, status.MaxCount))
			rb.Notice(fmt.Sprintf(client.t("Network %[1]s has had %[2]d connection attempts in the past %[3]v, out of a maximum of %[4]d"), netName, status.Throttle, status.ThrottleDuration, status.MaxPerWindow))
		}
	}

	str := target.cidr.HumanReadableString()
	isBanned, banInfo := client.server.dlines.CheckIP(target.cidr.IP)
	if isBanned {
		rb.Notice(formatBanForListing(client, str, banInfo))
	} else {
		rb.Notice(fmt.Sprintf(client.t("There is no active IP ban against %s"), str))
	}

	sessions, nicks := sessionsForCIDR(client.server, target.cidr, nil, false)
	if len(sessions) != 0 {
		rb.Notice(fmt.Sprintf(client.t("There are %[1]d active client(s) from %[2]s, associated with %[3]d nickname(s):"), len(sessions), target.cidr.String(), len(nicks)))
		for _, line := range utils.BuildTokenLines(400, nicks, " ") {
			rb.Notice(line)
		}
	}
}

func ubanInfoNickmask(client *Client, target ubanTarget, rb *ResponseBuffer) {
	isBanned, info := client.server.klines.ContainsMask(target.nickOrMask)
	if isBanned {
		rb.Notice(formatBanForListing(client, target.nickOrMask, info))
	} else {
		rb.Notice(fmt.Sprintf(client.t("No ban exists for %[1]s"), target.nickOrMask))
	}

	affectedCount := 0
	alwaysOnCount := 0
	for _, mcl := range client.server.clients.AllClients() {
		matches := false
		for _, mask := range mcl.AllNickmasks() {
			if target.matcher.MatchString(mask) {
				matches = true
				break
			}
		}
		if matches {
			if mcl.AlwaysOn() {
				alwaysOnCount++
			} else {
				affectedCount++
			}
		}
	}

	rb.Notice(fmt.Sprintf(client.t("Adding this mask would affect %[1]d clients (an additional %[2]d clients are exempt due to always-on)"), affectedCount, alwaysOnCount))
}

func ubanInfoNick(client *Client, target ubanTarget, rb *ResponseBuffer) {
	mcl := client.server.clients.Get(target.nickOrMask)
	if mcl != nil {
		details := mcl.Details()
		sessions := mcl.Sessions()
		ip := mcl.IP()
		sendIPBanWarning := false
		if details.account == "" {
			rb.Notice(fmt.Sprintf(client.t("Client %[1]s is unauthenticated and connected from %[2]s"), details.nick, ip.String()))
			sendIPBanWarning = true
		} else {
			rb.Notice(fmt.Sprintf(client.t("Client %[1]s is logged into account %[2]s and has %[3]d active clients (see /NICKSERV CLIENTS LIST %[4]s for more info"), details.nick, details.accountName, len(mcl.Sessions()), details.nick))
			if !ip.IsLoopback() && len(sessions) == 1 {
				rb.Notice(fmt.Sprintf(client.t("Client %[1]s is associated with IP %[2]s"), details.nick, ip.String()))
				sendIPBanWarning = true
			}
		}
		if sendIPBanWarning {
			rb.Notice(client.t("Warning: banning this IP or a network that contains it may affect other users. Use /UBAN INFO on the candidate IP or network for more information."))
		}
	} else {
		rb.Notice(fmt.Sprintf(client.t("No client is currently using that nickname")))
	}

	account, err := client.server.accounts.LoadAccount(target.nickOrMask)
	if err != nil {
		if err == errAccountDoesNotExist {
			rb.Notice(fmt.Sprintf(client.t("There is no account registered for %s"), target.nickOrMask))
		} else {
			rb.Notice(fmt.Sprintf(client.t("Couldn't load account: %v"), err.Error()))
		}
		return
	}
	if account.Verified {
		if account.Suspended == nil {
			rb.Notice(fmt.Sprintf(client.t("Account %[1]s is in good standing; see /NICKSERV INFO %[2]s for more details"), target.nickOrMask, target.nickOrMask))
		} else {
			rb.Notice(fmt.Sprintf(client.t("Account %[1]s has been suspended: %[2]s"), target.nickOrMask, suspensionToString(client, *account.Suspended)))
		}
	} else {
		rb.Notice(fmt.Sprintf(client.t("Account %[1]s was created, but has not been verified"), target.nickOrMask))
	}
}
