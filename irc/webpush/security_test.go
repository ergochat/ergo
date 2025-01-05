package webpush

import (
	"errors"
	"testing"
)

func TestExternalOnlyHTTPClient(t *testing.T) {
	client := makeExternalOnlyClient()

	for _, url := range []string{
		"https://127.0.0.2/test",
		"https://127.0.0.2:8201",
		"https://127.0.0.2:8201/asdf",
	} {
		_, err := client.Get(url)
		if err == nil || !errors.Is(err, errInternalIP) {
			t.Errorf("%s was not forbidden as expected (got %v)", url, err)
		}
	}
}
