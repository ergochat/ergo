// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

// viewing and modifying accounts, registered channels, dlines, rehashing, etc

package irc

import (
	"encoding/json"
	"net/http"
	"time"

	"fmt"

	"github.com/gorilla/mux"
)

const restErr = "{\"error\":\"An unknown error occurred\"}"

// restAPIServer is used to keep a link to the current running server since this is the best
// way to do it, given how HTTP handlers dispatch and work.
var restAPIServer *Server

type restStatusResp struct {
	Clients  int `json:"clients"`
	Opers    int `json:"opers"`
	Channels int `json:"channels"`
}

type restDLinesResp struct {
	DLines map[string]IPBanInfo `json:"dlines"`
}

type restAcct struct {
	Name         string
	RegisteredAt time.Time `json:"registered-at"`
	Clients      int
}

type restAccountsResp struct {
	Accounts map[string]restAcct
}

func restStatus(w http.ResponseWriter, r *http.Request) {
	rs := restStatusResp{
		Clients:  restAPIServer.clients.Count(),
		Opers:    len(restAPIServer.operators),
		Channels: len(restAPIServer.channels),
	}
	b, err := json.Marshal(rs)
	if err != nil {
		fmt.Fprintln(w, restErr)
	} else {
		fmt.Fprintln(w, string(b))
	}
}

func restDLines(w http.ResponseWriter, r *http.Request) {
	rs := restDLinesResp{
		DLines: restAPIServer.dlines.AllBans(),
	}
	b, err := json.Marshal(rs)
	if err != nil {
		fmt.Fprintln(w, restErr)
	} else {
		fmt.Fprintln(w, string(b))
	}
}

func restAccounts(w http.ResponseWriter, r *http.Request) {
	rs := restAccountsResp{
		Accounts: make(map[string]restAcct),
	}

	// get accts
	for key, info := range restAPIServer.accounts {
		rs.Accounts[key] = restAcct{
			Name:         info.Name,
			RegisteredAt: info.RegisteredAt,
			Clients:      len(info.Clients),
		}
	}

	b, err := json.Marshal(rs)
	if err != nil {
		fmt.Fprintln(w, restErr)
	} else {
		fmt.Fprintln(w, string(b))
	}
}

func (s *Server) startRestAPI() {
	// so handlers can ref it later
	restAPIServer = s

	// start router
	r := mux.NewRouter()
	r.HandleFunc("/status", restStatus)
	r.HandleFunc("/status/dlines", restDLines)
	r.HandleFunc("/status/accounts", restAccounts)

	// start api
	go http.ListenAndServe(s.restAPI.Listen, r)
}
