package irc

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
	"github.com/tidwall/buntdb"
)

func newAPIHandler(server *Server) http.Handler {
	api := &ergoAPI{
		server: server,
		mux:    http.NewServeMux(),
	}

	api.mux.HandleFunc("POST /v1/rehash", api.handleRehash)
	api.mux.HandleFunc("POST /v1/check_auth", api.handleCheckAuth)
	api.mux.HandleFunc("POST /v1/saregister", api.handleSaregister)
	api.mux.HandleFunc("POST /v1/account_details", api.handleAccountDetails)
	api.mux.HandleFunc("POST /v1/ns_info", api.handleNsInfo)
	api.mux.HandleFunc("GET /v1/account_list", api.handleAccountList)
	api.mux.HandleFunc("GET /v1/healthcheck", api.handleHealthCheck)

	return api
}

type ergoAPI struct {
	server *Server
	mux    *http.ServeMux
}

func (a *ergoAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer a.server.HandlePanic(nil)
	defer a.server.logger.Debug("api", r.URL.Path)

	if a.checkBearerAuth(r.Header.Get("Authorization")) {
		a.mux.ServeHTTP(w, r)
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func (a *ergoAPI) checkBearerAuth(authHeader string) (authorized bool) {
	if authHeader == "" {
		return false
	}
	c := a.server.Config()
	if !c.API.Enabled {
		return false
	}
	spaceIdx := strings.IndexByte(authHeader, ' ')
	if spaceIdx < 0 {
		return false
	}
	if !strings.EqualFold("Bearer", authHeader[:spaceIdx]) {
		return false
	}
	providedTokenBytes := []byte(authHeader[spaceIdx+1:])
	for _, tokenBytes := range c.API.bearerTokenBytes {
		if subtle.ConstantTimeCompare(tokenBytes, providedTokenBytes) == 1 {
			return true
		}
	}
	return false
}

func (a *ergoAPI) decodeJSONRequest(request any, w http.ResponseWriter, r *http.Request) (err error) {
	err = json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to deserialize json request: %v", err), http.StatusBadRequest)
	}
	return err
}

func (a *ergoAPI) writeJSONResponse(response any, w http.ResponseWriter, r *http.Request) {
	j, err := json.Marshal(response)
	if err == nil {
		j = append(j, '\n') // less annoying in curl output
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(j)
	} else {
		a.server.logger.Error("internal", "failed to serialize API response", r.URL.Path, err.Error())
		http.Error(w, fmt.Sprintf("failed to serialize json response: %v", err), http.StatusInternalServerError)
	}
}

type apiGenericResponse struct {
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"errorCode,omitempty"`
}

func (a *ergoAPI) handleRehash(w http.ResponseWriter, r *http.Request) {
	var response apiGenericResponse
	err := a.server.rehash()
	if err == nil {
		response.Success = true
	} else {
		response.Success = false
		response.Error = err.Error()
	}
	a.writeJSONResponse(response, w, r)
}

type apiCheckAuthResponse struct {
	apiGenericResponse
	AccountName string `json:"accountName,omitempty"`
}

func (a *ergoAPI) handleCheckAuth(w http.ResponseWriter, r *http.Request) {
	var request AuthScriptInput
	if err := a.decodeJSONRequest(&request, w, r); err != nil {
		return
	}

	var response apiCheckAuthResponse

	// try passphrase if present

	if request.AccountName != "" && request.Passphrase != "" {
		// TODO this only checks the internal database, not auth-script;
		// it's a little weird to use both auth-script and the API but we should probably handle it
		account, err := a.server.accounts.checkPassphrase(request.AccountName, request.Passphrase)
		switch err {
		case nil:
			// success, no error
			response.Success = true
			response.AccountName = account.Name
		case errAccountDoesNotExist, errAccountInvalidCredentials, errAccountUnverified, errAccountSuspended:
			// fail, no error
			response.Success = false
		default:
			response.Success = false
			response.Error = err.Error()
		}
	}

	// try certfp if present
	if !response.Success && request.Certfp != "" {
		// TODO support cerftp
	}

	a.writeJSONResponse(response, w, r)
}

type apiSaregisterRequest struct {
	AccountName string `json:"accountName"`
	Passphrase  string `json:"passphrase"`
}

func (a *ergoAPI) handleSaregister(w http.ResponseWriter, r *http.Request) {
	var request apiSaregisterRequest
	if err := a.decodeJSONRequest(&request, w, r); err != nil {
		return
	}

	var response apiGenericResponse
	err := a.server.accounts.SARegister(request.AccountName, request.Passphrase)
	if err == nil {
		response.Success = true
	} else {
		response.Success = false
		response.Error = err.Error()
		switch err {
		case errAccountAlreadyRegistered, errAccountAlreadyVerified, errNameReserved:
			response.ErrorCode = "ACCOUNT_EXISTS"
		case errAccountBadPassphrase:
			response.ErrorCode = "INVALID_PASSPHRASE"
		default:
			response.ErrorCode = "UNKNOWN_ERROR"
		}
	}

	a.writeJSONResponse(response, w, r)
}

type apiAccountDetailsResponse struct {
	apiGenericResponse
	AccountName string `json:"accountName,omitempty"`
	Email       string `json:"email,omitempty"`
}

type apiAccountDetailsRequest struct {
	AccountName string `json:"accountName"`
}

func (a *ergoAPI) handleAccountDetails(w http.ResponseWriter, r *http.Request) {
	var request apiAccountDetailsRequest
	if err := a.decodeJSONRequest(&request, w, r); err != nil {
		return
	}

	var response apiAccountDetailsResponse

	// TODO could probably use better error handling and more details

	if request.AccountName != "" {
		accountData, err := a.server.accounts.LoadAccount(request.AccountName)
		if err == nil {
			if !accountData.Verified {
				err = errAccountUnverified
			} else if accountData.Suspended != nil {
				err = errAccountSuspended
			}
		}

		switch err {
		case nil:
			response.AccountName = accountData.Name
			response.Email = accountData.Settings.Email
			response.Success = true
		case errAccountDoesNotExist, errAccountUnverified, errAccountSuspended:
			response.Success = false
		default:
			response.Success = false
			response.ErrorCode = "UNKNOWN_ERROR"
			response.Error = err.Error()
		}
	} else {
		response.Success = false
		response.ErrorCode = "INVALID_REQUEST"
	}

	a.writeJSONResponse(response, w, r)
}

type apiNsInfoRequest struct {
	Nick string `json:"nick"`
}

type apiNsInfoResponse struct {
	apiGenericResponse
	AccountName  string   `json:"accountName,omitempty"`
	RegisteredAt string   `json:"registeredAt,omitempty"`
	Channels     []string `json:"channels,omitempty"`
	ChannelCount int      `json:"channelCount,omitempty"`
}

func (a *ergoAPI) handleNsInfo(w http.ResponseWriter, r *http.Request) {
	var request apiNsInfoRequest
	if err := a.decodeJSONRequest(&request, w, r); err != nil {
		return
	}

	var response apiNsInfoResponse

	if request.Nick != "" {
		// Look up the account associated with this nick
		accountName := a.server.accounts.NickToAccount(request.Nick)
		if accountName == "" {
			response.Success = false
			a.writeJSONResponse(response, w, r)
			return
		}

		// Load the account details
		accountData, err := a.server.accounts.LoadAccount(accountName)
		if err != nil {
			response.Success = false
			a.writeJSONResponse(response, w, r)
			return
		}

		// Get the channels registered to this account
		channels := a.server.channels.ChannelsForAccount(accountName)

		// Populate the response
		response.Success = true
		response.AccountName = accountData.Name
		response.RegisteredAt = accountData.RegisteredAt.Format("Mon, 02 Jan 2006 15:04:05 UTC")
		response.Channels = channels
		response.ChannelCount = len(channels)
	} else {
		response.Success = false
		response.ErrorCode = "INVALID_REQUEST"
	}

	a.writeJSONResponse(response, w, r)
}

type apiAccountListRequest struct {
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
	Filter string `json:"filter,omitempty"`
}

type apiAccountListResponse struct {
	Accounts   []apiAccountDetailsResponse `json:"accounts"`
	TotalCount int                         `json:"totalCount"`
}

func (a *ergoAPI) handleAccountList(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Limit  int    `json:"limit,omitempty"`
		Filter string `json:"filter,omitempty"`
	}
	if err := a.decodeJSONRequest(&request, w, r); err != nil {
		return
	}

	var response apiAccountListResponse
	var accounts []string

	// Get all account names
	accountNamePrefix := fmt.Sprintf(keyAccountName, "")
	a.server.store.View(func(tx *buntdb.Tx) error {
		return tx.AscendGreaterOrEqual("", accountNamePrefix, func(key, value string) bool {
			if !strings.HasPrefix(key, accountNamePrefix) {
				return false
			}
			accounts = append(accounts, value)
			return true
		})
	})

	response.TotalCount = len(accounts)

	// Apply filtering if requested
	if request.Filter != "" {
		filtered := make([]string, 0, len(accounts))
		cfFilter, _ := CasefoldName(request.Filter)
		for _, account := range accounts {
			cfAccount, _ := CasefoldName(account)
			if strings.Contains(cfAccount, cfFilter) || strings.Contains(account, request.Filter) {
				filtered = append(filtered, account)
			}
		}
		accounts = filtered
		response.TotalCount = len(accounts) // update total count after filter
	}

	// Apply limit if requested
	if request.Limit > 0 && request.Limit < len(accounts) {
		accounts = accounts[:request.Limit]
	}

	// Load account details
	response.Accounts = make([]apiAccountDetailsResponse, len(accounts))
	for i, account := range accounts {
		accountData, err := a.server.accounts.LoadAccount(account)
		if err != nil {
			response.Accounts[i] = apiAccountDetailsResponse{
				apiGenericResponse: apiGenericResponse{
					Success: false,
					Error:   err.Error(),
				},
			}
			continue
		}

		response.Accounts[i] = apiAccountDetailsResponse{
			apiGenericResponse: apiGenericResponse{
				Success: true,
			},
			AccountName: accountData.Name,
			Email:       accountData.Settings.Email,
		}
	}

	a.writeJSONResponse(response, w, r)
}




type healthCheckResponse struct {
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	StartTime string `json:"start_time"`
	Users     struct {
		Total     int `json:"total"`
		Invisible int `json:"invisible"`
		Operators int `json:"operators"`
		Unknown   int `json:"unknown"`
		Max       int `json:"max"`
	} `json:"users"`
	Channels int `json:"channels"`
	Servers  int `json:"servers"`
}

func (a *ergoAPI) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	server := a.server
	stats := server.stats.GetValues()

	response := healthCheckResponse{
		Version:   Ver,
		GoVersion: runtime.Version(),
		StartTime: server.ctime.Format(time.RFC3339),
	}

	response.Users.Total = stats.Total
	response.Users.Invisible = stats.Invisible
	response.Users.Operators = stats.Operators
	response.Users.Unknown = stats.Unknown
	response.Users.Max = stats.Max

	response.Channels = server.channels.Len()
	response.Servers = 1

	a.writeJSONResponse(response, w, r)
}
