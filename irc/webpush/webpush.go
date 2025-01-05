// Copyright (c) 2024 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// Released under the MIT license
// Some portions of this code are:
// Copyright (c) 2021-2024 Simon Ser <contact@emersion.fr>
// Originally released under the AGPLv3, relicensed to the Ergo project under the MIT license

package webpush

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/ergochat/irc-go/ircmsg"
	webpush "github.com/ergochat/webpush-go/v2"

	"github.com/ergochat/ergo/irc/utils"
)

// alias some public types and names from webpush-go
type VAPIDKeys = webpush.VAPIDKeys
type Keys = webpush.Keys

var (
	GenerateVAPIDKeys = webpush.GenerateVAPIDKeys
)

// Urgency is a uint8 representation of urgency to save a few
// bytes on channel sizes.
type Urgency uint8

const (
	// UrgencyVeryLow requires device state: on power and Wi-Fi
	UrgencyVeryLow Urgency = iota // "very-low"
	// UrgencyLow requires device state: on either power or Wi-Fi
	UrgencyLow // "low"
	// UrgencyNormal excludes device state: low battery
	UrgencyNormal // "normal"
	// UrgencyHigh admits device state: low battery
	UrgencyHigh // "high"
)

var (
	// PingMessage is a valid IRC message that we can send to test that the subscription
	// is valid (i.e. responds to POSTs with a 20x). We do not expect that the client will
	// actually connect to IRC and send PONG (although it might be nice to have a way to
	// hint to a client that they should reconnect to renew their subscription?)
	PingMessage = []byte("PING webpush")
)

func convertUrgency(u Urgency) webpush.Urgency {
	switch u {
	case UrgencyVeryLow:
		return webpush.UrgencyVeryLow
	case UrgencyLow:
		return webpush.UrgencyLow
	case UrgencyNormal:
		return webpush.UrgencyNormal
	case UrgencyHigh:
		return webpush.UrgencyHigh
	default:
		return webpush.UrgencyNormal // shouldn't happen
	}
}

var httpClient webpush.HTTPClient = makeExternalOnlyClient()

var (
	Err404 = errors.New("endpoint returned a 404, indicating that the push subscription is no longer valid")

	errInvalidKey = errors.New("invalid key format")
)

func DecodeSubscriptionKeys(keysParam string) (keys webpush.Keys, err error) {
	// The keys parameter is tag-encoded, with each tag value being URL-safe base64 encoded:
	// * One public key with the name p256dh set to the client's P-256 ECDH public key.
	// * One shared key with the name auth set to a 16-byte client-generated authentication secret.
	// since we don't have a separate tag parser implementation, wrap it in a fake IRC line for parsing:
	fakeIRCLine := fmt.Sprintf("@%s PING", keysParam)
	ircMsg, err := ircmsg.ParseLine(fakeIRCLine)
	if err != nil {
		return
	}
	_, auth := ircMsg.GetTag("auth")
	_, p256 := ircMsg.GetTag("p256dh")
	return webpush.DecodeSubscriptionKeys(auth, p256)
}

func MakePushMessage(command, nuh, accountName, target string, msg utils.SplitMessage) ([]byte, error) {
	var messageForPush string
	if msg.Is512() {
		messageForPush = msg.Message
	} else {
		messageForPush = msg.Split[0].Message
	}

	ircMsg := ircmsg.MakeMessage(nil, nuh, command, target, messageForPush)
	ircMsg.SetTag("time", msg.Time.Format(utils.IRCv3TimestampFormat))
	if accountName != "*" {
		ircMsg.SetTag("account", accountName)
	}

	if line, err := ircMsg.LineBytesStrict(false, 512); err == nil {
		// strip final \r\n
		return line[:len(line)-2], nil
	} else {
		return nil, err
	}
}

func SendWebPush(ctx context.Context, endpoint string, keys Keys, vapidKeys *VAPIDKeys, urgency Urgency, subscriber string, msg []byte) error {
	wpsub := webpush.Subscription{
		Endpoint: endpoint,
		Keys:     keys,
	}

	options := webpush.Options{
		HTTPClient: httpClient,
		VAPIDKeys:  vapidKeys,
		Subscriber: subscriber,
		TTL:        7 * 24 * 60 * 60, // seconds
		Urgency:    convertUrgency(urgency),
		RecordSize: 2048,
	}

	resp, err := webpush.SendNotification(ctx, msg, &wpsub, &options)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return Err404
	} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
		return nil
	} else {
		return fmt.Errorf("HTTP error: %v", resp.Status)
	}
}
