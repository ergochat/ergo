// Copyright (c) 2019 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"sync"

	"github.com/oragono/oragono/irc/utils"
)

// implements draft/resume, in particular the issuing, management, and verification
// of resume tokens with two components: a unique ID and a secret key

type resumeTokenPair struct {
	client *Client
	secret string
}

type ResumeManager struct {
	sync.Mutex // level 2

	resumeIDtoCreds map[string]resumeTokenPair
	server          *Server
}

func (rm *ResumeManager) Initialize(server *Server) {
	rm.resumeIDtoCreds = make(map[string]resumeTokenPair)
	rm.server = server
}

// GenerateToken generates a resume token for a client. If the client has
// already been assigned one, it returns "".
func (rm *ResumeManager) GenerateToken(client *Client) (token string, id string) {
	id = utils.GenerateSecretToken()
	secret := utils.GenerateSecretToken()

	rm.Lock()
	defer rm.Unlock()

	if client.ResumeID() != "" {
		return
	}

	client.SetResumeID(id)
	rm.resumeIDtoCreds[id] = resumeTokenPair{
		client: client,
		secret: secret,
	}

	return id + secret, id
}

// VerifyToken looks up the client corresponding to a resume token, returning
// nil if there is no such client or the token is invalid. If successful,
// the token is consumed and cannot be used to resume again.
func (rm *ResumeManager) VerifyToken(newClient *Client, token string) (oldClient *Client, id string) {
	if len(token) != 2*utils.SecretTokenLength {
		return
	}

	rm.Lock()
	defer rm.Unlock()

	id = token[:utils.SecretTokenLength]
	pair, ok := rm.resumeIDtoCreds[id]
	if !ok {
		return
	}
	// disallow resume of an unregistered client; this prevents the use of
	// resume as an auth bypass
	if !pair.client.Registered() {
		return
	}

	if utils.SecretTokensMatch(pair.secret, token[utils.SecretTokenLength:]) {
		oldClient = pair.client // success!
		// consume the token, ensuring that at most one resume can succeed
		delete(rm.resumeIDtoCreds, id)
		// old client is henceforth resumeable under new client's creds (possibly empty)
		newResumeID := newClient.ResumeID()
		oldClient.SetResumeID(newResumeID)
		if newResumeID != "" {
			if newResumeCreds, ok := rm.resumeIDtoCreds[newResumeID]; ok {
				newResumeCreds.client = oldClient
				rm.resumeIDtoCreds[newResumeID] = newResumeCreds
			}
		}
		// new client no longer "owns" newResumeID, remove the association
		newClient.SetResumeID("")
	}
	return
}

// Delete stops tracking a client's resume token.
func (rm *ResumeManager) Delete(client *Client) {
	rm.Lock()
	defer rm.Unlock()

	currentID := client.ResumeID()
	if currentID != "" {
		delete(rm.resumeIDtoCreds, currentID)
	}
}
