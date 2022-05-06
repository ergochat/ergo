package irc

import (
	"testing"
)

func TestAccept(t *testing.T) {
	var am AcceptManager
	am.Initialize()

	alice := new(Client)
	bob := new(Client)
	eve := new(Client)

	// must not panic:
	am.Unaccept(eve, bob)

	assertEqual(am.MaySendTo(alice, bob), false)
	assertEqual(am.MaySendTo(bob, alice), false)
	assertEqual(am.MaySendTo(alice, eve), false)
	assertEqual(am.MaySendTo(eve, alice), false)
	assertEqual(am.MaySendTo(bob, eve), false)
	assertEqual(am.MaySendTo(eve, bob), false)

	am.Accept(alice, bob)

	assertEqual(am.MaySendTo(alice, bob), false)
	assertEqual(am.MaySendTo(bob, alice), true)
	assertEqual(am.MaySendTo(alice, eve), false)
	assertEqual(am.MaySendTo(eve, alice), false)
	assertEqual(am.MaySendTo(bob, eve), false)
	assertEqual(am.MaySendTo(eve, bob), false)

	am.Accept(bob, alice)

	assertEqual(am.MaySendTo(alice, bob), true)
	assertEqual(am.MaySendTo(bob, alice), true)
	assertEqual(am.MaySendTo(alice, eve), false)
	assertEqual(am.MaySendTo(eve, alice), false)
	assertEqual(am.MaySendTo(bob, eve), false)
	assertEqual(am.MaySendTo(eve, bob), false)

	am.Accept(bob, eve)

	assertEqual(am.MaySendTo(alice, bob), true)
	assertEqual(am.MaySendTo(bob, alice), true)
	assertEqual(am.MaySendTo(alice, eve), false)
	assertEqual(am.MaySendTo(eve, alice), false)
	assertEqual(am.MaySendTo(bob, eve), false)
	assertEqual(am.MaySendTo(eve, bob), true)

	am.Accept(eve, bob)

	assertEqual(am.MaySendTo(alice, bob), true)
	assertEqual(am.MaySendTo(bob, alice), true)
	assertEqual(am.MaySendTo(alice, eve), false)
	assertEqual(am.MaySendTo(eve, alice), false)
	assertEqual(am.MaySendTo(bob, eve), true)
	assertEqual(am.MaySendTo(eve, bob), true)

	am.Unaccept(eve, bob)

	assertEqual(am.MaySendTo(alice, bob), true)
	assertEqual(am.MaySendTo(bob, alice), true)
	assertEqual(am.MaySendTo(alice, eve), false)
	assertEqual(am.MaySendTo(eve, alice), false)
	assertEqual(am.MaySendTo(bob, eve), false)
	assertEqual(am.MaySendTo(eve, bob), true)

	am.Remove(alice)

	assertEqual(am.MaySendTo(alice, bob), false)
	assertEqual(am.MaySendTo(bob, alice), false)
	assertEqual(am.MaySendTo(alice, eve), false)
	assertEqual(am.MaySendTo(eve, alice), false)
	assertEqual(am.MaySendTo(bob, eve), false)
	assertEqual(am.MaySendTo(eve, bob), true)

	am.Remove(bob)

	assertEqual(am.MaySendTo(alice, bob), false)
	assertEqual(am.MaySendTo(bob, alice), false)
	assertEqual(am.MaySendTo(alice, eve), false)
	assertEqual(am.MaySendTo(eve, alice), false)
	assertEqual(am.MaySendTo(bob, eve), false)
	assertEqual(am.MaySendTo(eve, bob), false)
}

func TestAcceptInternal(t *testing.T) {
	var am AcceptManager
	am.Initialize()

	alice := new(Client)
	bob := new(Client)
	eve := new(Client)

	am.Accept(alice, bob)
	am.Accept(bob, alice)
	am.Accept(bob, eve)
	am.Remove(alice)
	am.Remove(bob)

	// assert that there is no memory leak
	for _, client := range []*Client{alice, bob, eve} {
		assertEqual(len(am.clientToAccepted[client]), 0)
		assertEqual(len(am.clientToAccepters[client]), 0)
	}
}
