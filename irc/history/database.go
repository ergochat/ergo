// Copyright (c) 2025 Shivaram Lingamneni
// released under the MIT license

package history

import (
	"io"
	"time"
)

// Database is an interface for persistent history storage backends.
type Database interface {
	// Close closes the database connection and releases resources.
	io.Closer

	// AddChannelItem adds a history item for a channel.
	// target is the casefolded channel name.
	// account is the sender's casefolded account name ("" for no account).
	AddChannelItem(target string, item Item, account string) error

	// AddDirectMessage adds a history item for a direct message.
	// All identifiers are casefolded; account identifiers are "" for no account.
	AddDirectMessage(sender, senderAccount, recipient, recipientAccount string, item Item) error

	// DeleteMsgid deletes a message by its msgid.
	// accountName is the unfolded account name, or "*" to skip
	// account validation
	DeleteMsgid(msgid, accountName string) error

	// MakeSequence creates a Sequence for querying history.
	// target is the primary target (channel or account), casefolded.
	// correspondent is the casefolded DM correspondent (empty for channels).
	// cutoff is the earliest time to include in results.
	MakeSequence(target, correspondent string, cutoff time.Time) Sequence

	// ListChannels returns the timestamp of the latest message in each
	// of the given channels (specified as casefolded names).
	ListChannels(cfchannels []string) (results []TargetListing, err error)

	// ListCorrespondents lists the DM correspondents associated with an account,
	// in order to implement CHATHISTORY TARGETS.
	ListCorrespondents(cftarget string, start, end time.Time, limit int) ([]TargetListing, error)

	// these are for theoretical GDPR compliance, not actual chat functionality,
	// and are not essential:

	// Forget enqueues an account (casefolded) for message deletion.
	// This is used for GDPR-style "right to be forgotten" requests.
	// The actual deletion happens asynchronously.
	Forget(account string)

	// Export exports all messages for an account (casefolded) to the given writer.
	Export(account string, writer io.Writer)
}

type noopDatabase struct{}

// NewNoopDatabase returns a Database implementation that does nothing.
func NewNoopDatabase() Database {
	return noopDatabase{}
}

func (n noopDatabase) Close() error {
	return nil
}

func (n noopDatabase) AddChannelItem(target string, item Item, account string) error {
	return nil
}

func (n noopDatabase) AddDirectMessage(sender, senderAccount, recipient, recipientAccount string, item Item) error {
	return nil
}

func (n noopDatabase) DeleteMsgid(msgid, accountName string) error {
	return nil
}

func (n noopDatabase) Forget(account string) {
	// no-op
}

func (n noopDatabase) Export(account string, writer io.Writer) {
	// no-op
}

func (n noopDatabase) ListChannels(cfchannels []string) (results []TargetListing, err error) {
	return nil, nil
}

func (n noopDatabase) ListCorrespondents(target string, start, end time.Time, limit int) (results []TargetListing, err error) {
	return nil, nil
}

func (n noopDatabase) MakeSequence(target, correspondent string, cutoff time.Time) Sequence {
	return noopSequence{}
}

// noopSequence is a no-op implementation of Sequence.
// XXX: this should never be accessed, because if persistent history is disabled,
// we should always be working with a bufferSequence instead. But we might as well
// be defensive in case there's an edge case where (noopDatabase).MakeSequence ends
// up getting called.
type noopSequence struct{}

func (n noopSequence) Between(start, end Selector, limit int) (results []Item, err error) {
	return nil, nil
}

func (n noopSequence) Around(start Selector, limit int) (results []Item, err error) {
	return nil, nil
}

func (n noopSequence) Cutoff() time.Time {
	return time.Time{}
}

func (n noopSequence) Ephemeral() bool {
	return true
}
