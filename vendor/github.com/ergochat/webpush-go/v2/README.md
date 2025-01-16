# webpush-go

[![GoDoc](https://godoc.org/github.com/ergochat/webpush-go?status.svg)](https://godoc.org/github.com/ergochat/webpush-go)

Web Push API Encryption with VAPID support.

This library is a fork of [SherClockHolmes/webpush-go](https://github.com/SherClockHolmes/webpush-go). See CHANGELOG.md for details on migrating from the upstream library.

```bash
go get -u github.com/ergochat/webpush-go/v2
```

## Example

For a full example, refer to the code in the [example](example/) directory.

```go
package main

import (
	"encoding/json"

	webpush "github.com/ergochat/webpush-go/v2"
)

func main() {
	// Decode subscription
	s := &webpush.Subscription{}
	json.Unmarshal([]byte("<YOUR_SUBSCRIPTION>"), s)
	vapidKeys := new(webpush.VAPIDKeys)
	json.Unmarshal([]byte("<YOUR_VAPID_KEYS">), vapidKeys)

	// Send Notification
	resp, err := webpush.SendNotification([]byte("Test"), s, &webpush.Options{
		Subscriber:      "example@example.com",
		VAPIDKeys:       vapidKeys,
		TTL:             3600, // seconds
	})
	if err != nil {
		// TODO: Handle error
	}
	defer resp.Body.Close()
}
```

### Generating VAPID Keys

Use the helper method `GenerateVAPIDKeys` to generate the VAPID key pair.

```golang
vapidKeys, err := webpush.GenerateVAPIDKeys()
if err != nil {
	// TODO: Handle error
}
```

## Development

1. Install [Go 1.20+](https://golang.org/)
2. `go mod vendor`
3. `go test`

#### For other language implementations visit:

[WebPush Libs](https://github.com/web-push-libs)
