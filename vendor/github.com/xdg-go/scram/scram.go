// Copyright 2018 by David A. Golden. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package scram

import (
	"crypto/sha1"
	"crypto/sha256"
	"hash"
)

// HashGeneratorFcn abstracts a factory function that returns a hash.Hash
// value to be used for SCRAM operations.  Generally, one would use the
// provided package variables, `scram.SHA1` and `scram.SHA256`, for the most
// common forms of SCRAM.
type HashGeneratorFcn func() hash.Hash

// SHA1 is a function that returns a crypto/sha1 hasher and should be used to
// create Client objects configured for SHA-1 hashing.
var SHA1 HashGeneratorFcn = func() hash.Hash { return sha1.New() }

// SHA256 is a function that returns a crypto/sha256 hasher and should be used
// to create Client objects configured for SHA-256 hashing.
var SHA256 HashGeneratorFcn = func() hash.Hash { return sha256.New() }

// NewClientUnprepped acts like NewClient, except none of the arguments will
// be normalized via SASLprep.  This is not generally recommended, but is
// provided for users that may have custom normalization needs.
func (f HashGeneratorFcn) NewClientUnprepped(username, password, authzID string) (*Client, error) {
	return newClient(username, password, authzID, f), nil
}

// NewServer constructs a SCRAM server component based on a given hash.Hash
// factory receiver.  To be maximally generic, it uses dependency injection to
// handle credential lookup, which is the process of turning a username string
// into a struct with stored credentials for authentication.
func (f HashGeneratorFcn) NewServer(cl CredentialLookup) (*Server, error) {
	return newServer(cl, f)
}
