// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package passwd

import (
	"encoding/base64"
	"testing"
)

type SaltedPasswordTest struct {
	ManagerSalt string
	Salt        string
	Hash        string
	Password    string
}

var SaltedPasswords = []SaltedPasswordTest{
	{
		ManagerSalt: "3TPITDVf/NGb4OlCyV1uZNW1H7zy3BFos+Dsu7dj",
		Salt:        "b6oVqshJUfcm1zWEtqwKqUVylqLONAZfqt17ns+Y",
		Hash:        "JDJhJDE0JFYuT28xOFFNZldaaTI1UWpzNENMeHVKdm5vS1lkL2tFL1lFVkQ2a0loUEY2Vzk3UTZSVDVP",
		Password:    "test",
	},
	{
		ManagerSalt: "iNGeNEfuPihM8kYDZ/C6qAJ0JERKeKkUYp6wYDU0",
		Salt:        "U7TA6k6VLSLHfdjSsQH0vc3Jqq6cUezJNyd0DC9c",
		Hash:        "JDJhJDE0JEguY2Rva3VOTVRrNm1VeGdXWjAwamViMGNvV0xYZFdHcTZjenFCRWE3Ymt2N1JiSFJDZlYy",
		Password:    "test2",
	},
	{
		ManagerSalt: "ghKJaaSNTjuFmgLRqrgY4FGfx8wXEGOBE02PZvbv",
		Salt:        "NO/mtrMhGjX1FGDGdpGrDJIi4jxsb0aFa7ybId7r",
		Hash:        "JDJhJDE0JEI0M055Z2NDcjNUanB5ZEJ5MzUybi5FT3o4Y1MyNXp2c1NDVS9hS0hOcUxSRDZTWmUxTnN5",
		Password:    "supermono",
	},
}

func TestSaltedPassword(t *testing.T) {
	// check newly-generated password
	managerSalt, err := NewSalt()
	if err != nil {
		t.Error("Could not generate manager salt")
	}

	salt, err := NewSalt()
	if err != nil {
		t.Error("Could not generate salt")
	}

	manager := NewSaltedManager(managerSalt)

	passHash, err := manager.GenerateFromPassword(salt, "this is a test password")
	if err != nil {
		t.Error("Could not generate from password")
	}

	if manager.CompareHashAndPassword(passHash, salt, "this is a test password") != nil {
		t.Error("Generated password does not match")
	}

	// check our stored passwords
	for i, info := range SaltedPasswords {
		// decode strings to bytes
		managerSalt, err = base64.StdEncoding.DecodeString(info.ManagerSalt)
		if err != nil {
			t.Errorf("Could not decode manager salt for test %d", i)
		}

		salt, err := base64.StdEncoding.DecodeString(info.Salt)
		if err != nil {
			t.Errorf("Could not decode salt for test %d", i)
		}

		hash, err := base64.StdEncoding.DecodeString(info.Hash)
		if err != nil {
			t.Errorf("Could not decode hash for test %d", i)
		}

		// make sure our test values are still correct
		manager := NewSaltedManager(managerSalt)
		if manager.CompareHashAndPassword(hash, salt, info.Password) != nil {
			t.Errorf("Password does not match for [%s]", info.Password)
		}
	}
}
