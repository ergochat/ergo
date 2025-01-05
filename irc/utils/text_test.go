// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"strings"
	"testing"
)

const (
	monteCristo = `Both the count and Baptistin had told the truth when they announced to Morcerf the proposed visit of the major, which had served Monte Cristo as a pretext for declining Albert's invitation. Seven o'clock had just struck, and M. Bertuccio, according to the command which had been given him, had two hours before left for Auteuil, when a cab stopped at the door, and after depositing its occupant at the gate, immediately hurried away, as if ashamed of its employment. The visitor was about fifty-two years of age, dressed in one of the green surtouts, ornamented with black frogs, which have so long maintained their popularity all over Europe. He wore trousers of blue cloth, boots tolerably clean, but not of the brightest polish, and a little too thick in the soles, buckskin gloves, a hat somewhat resembling in shape those usually worn by the gendarmes, and a black cravat striped with white, which, if the proprietor had not worn it of his own free will, might have passed for a halter, so much did it resemble one. Such was the picturesque costume of the person who rang at the gate, and demanded if it was not at No. 30 in the Avenue des Champs-Elysees that the Count of Monte Cristo lived, and who, being answered by the porter in the affirmative, entered, closed the gate after him, and began to ascend the steps.`
)

func TestTokenLineBuilder(t *testing.T) {
	lineLen := 400
	var tl TokenLineBuilder
	tl.Initialize(lineLen, " ")
	for _, token := range strings.Fields(monteCristo) {
		tl.Add(token)
	}

	lines := tl.Lines()
	if len(lines) != 4 {
		t.Errorf("expected 4 lines, got %d", len(lines))
	}
	for _, line := range lines {
		if len(line) > lineLen {
			t.Errorf("line length %d exceeds maximum of %d", len(line), lineLen)
		}
	}

	joined := strings.Join(lines, " ")
	if joined != monteCristo {
		t.Errorf("text incorrectly split into lines: %s instead of %s", joined, monteCristo)
	}
}

func TestBuildTokenLines(t *testing.T) {
	val := BuildTokenLines(512, []string{"a", "b", "c"}, ",")
	assertEqual(val, []string{"a,b,c"}, t)

	val = BuildTokenLines(10, []string{"abcd", "efgh", "ijkl"}, ",")
	assertEqual(val, []string{"abcd,efgh", "ijkl"}, t)
}

func TestTLBuilderAddParts(t *testing.T) {
	var tl TokenLineBuilder
	tl.Initialize(20, " ")
	tl.Add("bob")
	tl.AddParts("@", "alice")
	tl.AddParts("@", "ErgoBot__")
	assertEqual(tl.Lines(), []string{"bob @alice", "@ErgoBot__"}, t)
}

func BenchmarkTokenLines(b *testing.B) {
	tokens := strings.Fields(monteCristo)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var tl TokenLineBuilder
		tl.Initialize(400, " ")
		for _, tok := range tokens {
			tl.Add(tok)
		}
		tl.Lines()
	}
}

func TestCombinedValue(t *testing.T) {
	var split = SplitMessage{
		Split: []MessagePair{
			{"hi", false},
			{"hi", false},
			{" again", true},
			{"you", false},
		},
	}
	assertEqual(split.CombinedValue(), "hi\nhi again\nyou", t)
}
