// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"reflect"
	"strings"
	"testing"
)

const (
	threeMusketeers = "In the meantime D’Artagnan, who had plunged into a bypath, continued his route and reached St. Cloud; but instead of following the main street he turned behind the château, reached a sort of retired lane, and found himself soon in front of the pavilion named. It was situated in a very private spot. A high wall, at the angle of which was the pavilion, ran along one side of this lane, and on the other was a little garden connected with a poor cottage which was protected by a hedge from passers-by."

	monteCristo = `Both the count and Baptistin had told the truth when they announced to Morcerf the proposed visit of the major, which had served Monte Cristo as a pretext for declining Albert's invitation. Seven o'clock had just struck, and M. Bertuccio, according to the command which had been given him, had two hours before left for Auteuil, when a cab stopped at the door, and after depositing its occupant at the gate, immediately hurried away, as if ashamed of its employment. The visitor was about fifty-two years of age, dressed in one of the green surtouts, ornamented with black frogs, which have so long maintained their popularity all over Europe. He wore trousers of blue cloth, boots tolerably clean, but not of the brightest polish, and a little too thick in the soles, buckskin gloves, a hat somewhat resembling in shape those usually worn by the gendarmes, and a black cravat striped with white, which, if the proprietor had not worn it of his own free will, might have passed for a halter, so much did it resemble one. Such was the picturesque costume of the person who rang at the gate, and demanded if it was not at No. 30 in the Avenue des Champs-Elysees that the Count of Monte Cristo lived, and who, being answered by the porter in the affirmative, entered, closed the gate after him, and began to ascend the steps.`
)

func assertWrapCorrect(text string, lineWidth int, allowSplitWords bool, t *testing.T) {
	lines := WordWrap(text, lineWidth)

	reconstructed := strings.Join(lines, "")
	if text != reconstructed {
		t.Errorf("text %v does not match original %v", text, reconstructed)
	}

	for _, line := range lines {
		if len(line) > lineWidth {
			t.Errorf("line too long: %d, %v", len(line), line)
		}
	}

	if !allowSplitWords {
		origWords := strings.Fields(text)
		var newWords []string
		for _, line := range lines {
			newWords = append(newWords, strings.Fields(line)...)
		}

		if !reflect.DeepEqual(origWords, newWords) {
			t.Errorf("words %v do not match wrapped words %v", origWords, newWords)
		}
	}

}

func TestWordWrap(t *testing.T) {
	assertWrapCorrect("jackdaws love my big sphinx of quartz", 12, false, t)
	// long word that will necessarily be split:
	assertWrapCorrect("jackdawslovemybigsphinxofquartz", 12, true, t)

	assertWrapCorrect(threeMusketeers, 40, true, t)
	assertWrapCorrect(monteCristo, 20, false, t)
}

func BenchmarkWordWrap(b *testing.B) {
	for i := 0; i < b.N; i++ {
		WordWrap(threeMusketeers, 40)
		WordWrap(monteCristo, 60)
	}
}
