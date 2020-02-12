package ircmatch

import enfa "github.com/goshuirc/e-nfa"

// Matcher represents an object that can match IRC strings.
type Matcher struct {
	internalENFA *enfa.ENFA
}

// MakeMatch creates a Matcher.
func MakeMatch(globTemplate string) Matcher {
	var newmatch Matcher

	// assemble internal enfa
	newmatch.internalENFA = enfa.NewENFA(0, false)

	var currentState int
	var lastWasStar bool
	for _, char := range globTemplate {
		if char == '*' {
			if lastWasStar {
				continue
			}
			newmatch.internalENFA.AddTransition(currentState, "*", currentState)
			lastWasStar = true
			continue
		} else if char == '?' {
			newmatch.internalENFA.AddState(currentState+1, false)
			newmatch.internalENFA.AddTransition(currentState, "?", currentState+1)
			currentState++
		} else {
			newmatch.internalENFA.AddState(currentState+1, false)
			newmatch.internalENFA.AddTransition(currentState, string(char), currentState+1)
			currentState++
		}

		lastWasStar = false
	}

	// create end state
	newmatch.internalENFA.AddState(currentState+1, true)
	newmatch.internalENFA.AddTransition(currentState, "", currentState+1)

	return newmatch
}

// Match returns true if the given string matches this glob.
func (menfa *Matcher) Match(search string) bool {
	var searchChars []string
	for _, char := range search {
		searchChars = append(searchChars, string(char))
	}

	isMatch := menfa.internalENFA.VerifyInputs(searchChars)
	menfa.internalENFA.Reset()
	return isMatch
}
