// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package passwd

import (
	"testing"
)

var UnsaltedPasswords = map[string]string{
	"test1":     "JDJhJDA0JFFwZ1V0RWZTMFVaMkFrdlRrTG9FZk9FNEZWbWkvVEhsdGFnSXlIUC5wVmpYTkNERFJPNlcu",
	"test2":     "JDJhJDA0JHpQTGNqczlIanc3V2NFQ3JEOVlTM09aNkRTbGRsQzRyNmt3Q01aSUs2Y2xyWURVODZ1V0px",
	"supernomo": "JDJhJDA0JHdJekhnQmk1VXQ4WUphL0pIL0tXQWVKVXJ6dXcvRDJ3WFljWW9XOGhzNllIbW1DRlFkL1VL",
}

func TestUnsaltedPassword(t *testing.T) {
	for password, hash := range UnsaltedPasswords {
		generatedHash, err := GenerateEncodedPassword(password)
		if err != nil {
			t.Errorf("Could not hash password for [%s]: %s", password, err.Error())
		}

		hashBytes, err := DecodePasswordHash(hash)
		if err != nil {
			t.Errorf("Could not decode hash for [%s]: %s", password, err.Error())
		}

		generatedHashBytes, err := DecodePasswordHash(generatedHash)
		if err != nil {
			t.Errorf("Could not decode generated hash for [%s]: %s", password, err.Error())
		}

		passwordBytes := []byte(password)

		if ComparePassword(hashBytes, passwordBytes) != nil {
			t.Errorf("Stored hash for [%s] did not match", password)
		}
		if ComparePassword(generatedHashBytes, passwordBytes) != nil {
			t.Errorf("Generated hash for [%s] did not match", password)
		}
	}
}

func TestUnsaltedPasswordFailures(t *testing.T) {
	_, err := GenerateEncodedPassword("")
	if err != ErrEmptyPassword {
		t.Error("Generating empty password did not fail as expected!")
	}

	_, err = DecodePasswordHash("")
	if err != ErrEmptyPassword {
		t.Error("Decoding empty password hash did not fail as expected!")
	}
}
