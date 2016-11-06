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

type restVersionResp struct {
	Version string `json:"version"`
}

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
	Accounts map[string]restAcct `json:"accounts"`
}

type restRehashResp struct {
	Successful bool      `json:"successful"`
	Error      string    `json:"error"`
	Time       time.Time `json:"time"`
}

func restVersion(w http.ResponseWriter, r *http.Request) {
	rs := restVersionResp{
		Version: SemVer,
	}
	b, err := json.Marshal(rs)
	if err != nil {
		fmt.Fprintln(w, restErr)
	} else {
		fmt.Fprintln(w, string(b))
	}
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

func restGetDLines(w http.ResponseWriter, r *http.Request) {
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

func restGetAccounts(w http.ResponseWriter, r *http.Request) {
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

func restRehash(w http.ResponseWriter, r *http.Request) {
	err := restAPIServer.rehash()

	rs := restRehashResp{
		Successful: err == nil,
		Time:       time.Now(),
	}
	if err != nil {
		rs.Error = err.Error()
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

	// GET methods
	rg := r.Methods("GET").Subrouter()
	rg.HandleFunc("/version", restVersion)
	rg.HandleFunc("/status", restStatus)
	rg.HandleFunc("/dlines", restGetDLines)
	rg.HandleFunc("/accounts", restGetAccounts)

	// PUT methods
	rp := r.Methods("POST").Subrouter()
	rp.HandleFunc("/rehash", restRehash)

	// start api
	go http.ListenAndServe(s.restAPI.Listen, r)
}
