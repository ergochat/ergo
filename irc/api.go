package irc

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"slices"
	"strings"

	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/sno"
	"github.com/ergochat/ergo/irc/utils"
)

func newAPIHandler(server *Server) http.Handler {
	api := &ergoAPI{
		server: server,
		mux:    http.NewServeMux(),
	}

	// server-level functionality:
	api.mux.HandleFunc("POST /v1/rehash", api.handleRehash)
	api.mux.HandleFunc("POST /v1/status", api.handleStatus)
	api.mux.HandleFunc("POST /v1/list", api.handleList)
	api.mux.HandleFunc("POST /v1/defcon", api.handleDefcon)

	// use Ergo as a source of truth for authentication in other services:
	api.mux.HandleFunc("POST /v1/check_auth", api.handleCheckAuth)
	api.mux.HandleFunc("POST /v1/whois", api.handleWhois)

	// legacy names for /v1/ns endpoints:
	api.mux.HandleFunc("POST /v1/saregister", api.handleSaregister)
	api.mux.HandleFunc("POST /v1/account_details", api.handleAccountDetails)
	api.mux.HandleFunc("POST /v1/account_list", api.handleAccountList)

	// /v1/ns: nickserv functionality
	api.mux.HandleFunc("POST /v1/ns/info", api.handleAccountDetails)
	api.mux.HandleFunc("POST /v1/ns/list", api.handleAccountList)
	api.mux.HandleFunc("POST /v1/ns/passwd", api.handleNsPasswd)
	api.mux.HandleFunc("POST /v1/ns/saregister", api.handleSaregister)
	api.mux.HandleFunc("POST /v1/ns/saget", api.handleNsSaget)
	api.mux.HandleFunc("POST /v1/ns/saset", api.handleNsSaset)

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

type defconRequestResponse struct {
	apiGenericResponse
	Defcon int `json:"defcon"`
}

func (a *ergoAPI) handleDefcon(w http.ResponseWriter, r *http.Request) {
	var changeRequested uint32
	var request defconRequestResponse
	// ignore errors or invalid values
	if err := json.NewDecoder(r.Body).Decode(&request); err == nil {
		if 1 <= request.Defcon && request.Defcon <= 5 {
			changeRequested = uint32(request.Defcon)
		}
	}
	if changeRequested != 0 {
		a.server.SetDefcon(changeRequested)
		message := fmt.Sprintf("API set DEFCON level to %d", changeRequested)
		a.server.logger.Info("server", message)
		a.server.snomasks.Send(sno.LocalAnnouncements, message)
	}
	a.writeJSONResponse(
		defconRequestResponse{
			apiGenericResponse: apiGenericResponse{Success: true},
			Defcon:             int(a.server.Defcon()),
		}, w, r,
	)
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

	var account ClientAccount
	var err error

	// try whatever credentials are present
	if request.AccountName != "" && request.Passphrase != "" {
		account, err = a.server.accounts.checkPassphrase(request.AccountName, request.Passphrase)
	} else if request.Certfp != "" {
		account, err = a.server.accounts.checkCertOrCookieAuth(nil, request.Certfp, nil, nil, "")
	} else {
		err = errAccountInvalidCredentials
	}

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

func (a *ergoAPI) handleNsPasswd(w http.ResponseWriter, r *http.Request) {
	var request apiSaregisterRequest
	if err := a.decodeJSONRequest(&request, w, r); err != nil {
		return
	}

	var response apiGenericResponse
	err := a.server.accounts.setPassword(request.AccountName, request.Passphrase, true)
	switch err {
	case nil:
		response.Success = true
	case errAccountDoesNotExist:
		response.ErrorCode = "ACCOUNT_DOES_NOT_EXIST"
	case errAccountBadPassphrase, errEmptyCredentials:
		response.ErrorCode = "INVALID_PASSPHRASE"
	case errCredsExternallyManaged:
		response.ErrorCode = "CREDENTIALS_EXTERNALLY_MANAGED"
	default:
		a.server.logger.Error("api", "could not change user password:", err.Error())
		response.ErrorCode = "UNKNOWN_ERROR"
	}

	a.writeJSONResponse(response, w, r)
}

// convert to/from the "default"/"off"/"on" vocabulary used by the
// /v1/ns/saget and /v1/ns/saset API endpoints
func apiPersistentStatusToString(status PersistentStatus) string {
	switch status {
	case PersistentDisabled:
		return "off"
	case PersistentMandatory:
		return "on"
	default:
		return "default"
	}
}

func apiPersistentStatusFromString(status string) (PersistentStatus, error) {
	switch strings.ToLower(status) {
	case "default":
		return PersistentUnspecified, nil
	case "off":
		return PersistentDisabled, nil
	case "on":
		return PersistentMandatory, nil
	default:
		return PersistentUnspecified, errInvalidParams
	}
}

// convert to/from the "commands-only"/"on" vocabulary used by the
// /v1/ns/saget and /v1/ns/saset API endpoints
func apiReplayJoinsToString(status ReplayJoinsSetting) string {
	switch status {
	case ReplayJoinsAlways:
		return "on"
	default:
		return "commands-only"
	}
}

func apiReplayJoinsFromString(status string) (ReplayJoinsSetting, error) {
	switch strings.ToLower(status) {
	case "commands-only":
		return ReplayJoinsCommandsOnly, nil
	case "on":
		return ReplayJoinsAlways, nil
	default:
		return ReplayJoinsCommandsOnly, errInvalidParams
	}
}

type apiAccountSettingsRequest struct {
	AccountName string `json:"accountName"`
}

type apiAccountSettingsResponse struct {
	apiGenericResponse
	AlwaysOn    string `json:"alwaysOn,omitempty"`
	AutoAway    string `json:"autoAway,omitempty"`
	Email       string `json:"email,omitempty"`
	ReplayJoins string `json:"replayJoins,omitempty"`
}

// accountSettingsErrorCode maps an error from loading or modifying account
// settings to the machine-readable errorCode conventions shared by
// /v1/ns/saget and /v1/ns/saset.
func accountSettingsErrorCode(err error) string {
	switch err {
	case errAccountDoesNotExist:
		return "ACCOUNT_DOES_NOT_EXIST"
	case errAccountUnverified:
		return "ACCOUNT_UNVERIFIED"
	case errAccountSuspended:
		return "ACCOUNT_SUSPENDED"
	default:
		return "UNKNOWN_ERROR"
	}
}

func accountSettingsErrorResponse(err error) apiAccountSettingsResponse {
	response := apiAccountSettingsResponse{
		apiGenericResponse: apiGenericResponse{Success: false, ErrorCode: accountSettingsErrorCode(err)},
	}
	if response.ErrorCode == "UNKNOWN_ERROR" {
		response.Error = err.Error()
	}
	return response
}

// loadVerifiedAccount loads an account and checks that it exists, is
// verified, and is not suspended, returning the appropriate sentinel error
// otherwise.
func (a *ergoAPI) loadVerifiedAccount(accountName string) (accountData ClientAccount, err error) {
	accountData, err = a.server.accounts.LoadAccount(accountName)
	if err == nil {
		if !accountData.Verified {
			err = errAccountUnverified
		} else if accountData.Suspended != nil {
			err = errAccountSuspended
		}
	}
	return
}

func (a *ergoAPI) accountSettingsResponse(accountName string) apiAccountSettingsResponse {
	accountData, err := a.loadVerifiedAccount(accountName)
	if err != nil {
		return accountSettingsErrorResponse(err)
	}

	settings := accountData.Settings
	return apiAccountSettingsResponse{
		apiGenericResponse: apiGenericResponse{Success: true},
		AlwaysOn:           apiPersistentStatusToString(settings.AlwaysOn),
		AutoAway:           apiPersistentStatusToString(settings.AutoAway),
		Email:              settings.Email,
		ReplayJoins:        apiReplayJoinsToString(settings.ReplayJoins),
	}
}

func (a *ergoAPI) handleNsSaget(w http.ResponseWriter, r *http.Request) {
	var request apiAccountSettingsRequest
	if err := a.decodeJSONRequest(&request, w, r); err != nil {
		return
	}

	if request.AccountName == "" {
		a.writeJSONResponse(apiAccountSettingsResponse{
			apiGenericResponse: apiGenericResponse{Success: false, ErrorCode: "INVALID_REQUEST"},
		}, w, r)
		return
	}

	a.writeJSONResponse(a.accountSettingsResponse(request.AccountName), w, r)
}

type apiNsSasetRequest struct {
	AccountName string  `json:"accountName"`
	AlwaysOn    *string `json:"alwaysOn"`
	AutoAway    *string `json:"autoAway"`
	Email       *string `json:"email"`
	ReplayJoins *string `json:"replayJoins"`
}

func (a *ergoAPI) handleNsSaset(w http.ResponseWriter, r *http.Request) {
	var request apiNsSasetRequest
	if err := a.decodeJSONRequest(&request, w, r); err != nil {
		return
	}

	if request.AccountName == "" {
		a.writeJSONResponse(apiAccountSettingsResponse{
			apiGenericResponse: apiGenericResponse{Success: false, ErrorCode: "INVALID_REQUEST"},
		}, w, r)
		return
	}

	var alwaysOn, autoAway PersistentStatus
	var replayJoins ReplayJoinsSetting
	var err error
	if request.AlwaysOn != nil {
		if alwaysOn, err = apiPersistentStatusFromString(*request.AlwaysOn); err != nil {
			a.writeJSONResponse(apiAccountSettingsResponse{
				apiGenericResponse: apiGenericResponse{Success: false, ErrorCode: "INVALID_REQUEST"},
			}, w, r)
			return
		}
	}
	if request.AutoAway != nil {
		if autoAway, err = apiPersistentStatusFromString(*request.AutoAway); err != nil {
			a.writeJSONResponse(apiAccountSettingsResponse{
				apiGenericResponse: apiGenericResponse{Success: false, ErrorCode: "INVALID_REQUEST"},
			}, w, r)
			return
		}
	}
	if request.ReplayJoins != nil {
		if replayJoins, err = apiReplayJoinsFromString(*request.ReplayJoins); err != nil {
			a.writeJSONResponse(apiAccountSettingsResponse{
				apiGenericResponse: apiGenericResponse{Success: false, ErrorCode: "INVALID_REQUEST"},
			}, w, r)
			return
		}
	}

	// reject the write up front if the account isn't in a usable state
	// (ModifyAccountSettings doesn't check suspension on its own)
	if _, err := a.loadVerifiedAccount(request.AccountName); err != nil {
		a.writeJSONResponse(accountSettingsErrorResponse(err), w, r)
		return
	}

	munger := func(in AccountSettings) (out AccountSettings, err error) {
		out = in
		if request.AlwaysOn != nil {
			out.AlwaysOn = alwaysOn
		}
		if request.AutoAway != nil {
			out.AutoAway = autoAway
		}
		if request.Email != nil {
			out.Email = *request.Email
		}
		if request.ReplayJoins != nil {
			out.ReplayJoins = replayJoins
		}
		return
	}

	if _, err := a.server.accounts.ModifyAccountSettings(request.AccountName, munger); err != nil {
		a.writeJSONResponse(accountSettingsErrorResponse(err), w, r)
		return
	}

	a.writeJSONResponse(a.accountSettingsResponse(request.AccountName), w, r)
}

type apiAccountDetailsResponse struct {
	apiGenericResponse
	AccountName  string   `json:"accountName,omitempty"`
	Email        string   `json:"email,omitempty"`
	RegisteredAt string   `json:"registeredAt,omitempty"`
	Channels     []string `json:"channels,omitempty"`
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
			if !accountData.RegisteredAt.IsZero() {
				response.RegisteredAt = accountData.RegisteredAt.Format(utils.IRCv3TimestampFormat)
			}

			// Get channels the account is in
			response.Channels = a.server.channels.ChannelsForAccount(accountData.NameCasefolded, true)
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

type apiAccountListResponse struct {
	apiGenericResponse
	Accounts   []apiAccountDetailsResponse `json:"accounts"`
	TotalCount int                         `json:"totalCount"`
}

func (a *ergoAPI) handleAccountList(w http.ResponseWriter, r *http.Request) {
	var response apiAccountListResponse

	// Get all account names
	accounts := a.server.accounts.AllNicks()
	response.TotalCount = len(accounts)

	// Load account details
	response.Accounts = make([]apiAccountDetailsResponse, 0, len(accounts))
	for _, account := range accounts {
		accountData, err := a.server.accounts.LoadAccount(account)
		if err != nil {
			// shouldn't happen
			continue
		}

		response.Accounts = append(
			response.Accounts,
			apiAccountDetailsResponse{
				apiGenericResponse: apiGenericResponse{
					Success: true,
				},
				AccountName: accountData.Name,
				Email:       accountData.Settings.Email,
			},
		)
	}

	response.Success = true
	a.writeJSONResponse(response, w, r)
}

type apiStatusResponse struct {
	apiGenericResponse
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	Commit    string `json:"commit,omitempty"`
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

func (a *ergoAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	server := a.server
	stats := server.stats.GetValues()

	response := apiStatusResponse{
		apiGenericResponse: apiGenericResponse{Success: true},
		Version:            SemVer,
		GoVersion:          runtime.Version(),
		Commit:             Commit,
		StartTime:          server.ctime.Format(utils.IRCv3TimestampFormat),
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

type apiChannelData struct {
	Name         string `json:"name"`
	HasKey       bool   `json:"hasKey"`
	InviteOnly   bool   `json:"inviteOnly"`
	Secret       bool   `json:"secret"`
	UserCount    int    `json:"userCount"`
	Topic        string `json:"topic"`
	TopicSetAt   string `json:"topicSetAt,omitempty"`
	CreatedAt    string `json:"createdAt"`
	Registered   bool   `json:"registered"`
	Owner        string `json:"owner,omitempty"`
	RegisteredAt string `json:"registeredAt,omitempty"`
}

func (channel *Channel) apiData() (result apiChannelData) {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	result.Name = channel.name
	result.HasKey = channel.key != ""
	result.InviteOnly = channel.flags.HasMode(modes.InviteOnly)
	result.Secret = channel.flags.HasMode(modes.Secret)
	result.UserCount = len(channel.members)
	result.Topic = channel.topic
	if !channel.topicSetTime.IsZero() {
		result.TopicSetAt = channel.topicSetTime.UTC().Format(utils.IRCv3TimestampFormat)
	}
	result.CreatedAt = channel.createdTime.UTC().Format(utils.IRCv3TimestampFormat)
	result.Registered = channel.registeredFounder != ""
	if result.Registered {
		result.Owner = channel.registeredFounder
		if !channel.registeredTime.IsZero() {
			result.RegisteredAt = channel.registeredTime.UTC().Format(utils.IRCv3TimestampFormat)
		}
	}
	return
}

type apiListResponse struct {
	apiGenericResponse
	Channels []apiChannelData `json:"channels"`
}

type apiWhoisRequest struct {
	Nickname string `json:"nickname"`
}

type apiWhoisChannelData struct {
	Name     string `json:"name"`
	Mode     string `json:"mode,omitempty"`
	JoinTime string `json:"join_time"`
}

type apiWhoisResponse struct {
	apiGenericResponse
	Present      bool                  `json:"present"`
	Nickname     string                `json:"nickname,omitempty"`
	Username     string                `json:"username,omitempty"`
	Hostname     string                `json:"hostname,omitempty"`
	Realname     string                `json:"realname,omitempty"`
	Account      string                `json:"account"`
	Modes        string                `json:"modes,omitempty"`
	Away         string                `json:"away,omitempty"`
	Channels     []apiWhoisChannelData `json:"channels"`
	SessionCount int                   `json:"session_count"`
}

func (a *ergoAPI) handleWhois(w http.ResponseWriter, r *http.Request) {
	var request apiWhoisRequest
	if err := a.decodeJSONRequest(&request, w, r); err != nil {
		return
	}

	response := apiWhoisResponse{
		apiGenericResponse: apiGenericResponse{Success: true},
	}

	client := a.server.clients.Get(request.Nickname)
	if client != nil {
		response.Present = true
		details := client.Details()
		response.Nickname = details.nick
		response.Username = details.username
		response.Hostname = details.hostname
		response.Realname = details.realname
		if details.account != "" {
			response.Account = details.accountName
		}
		response.Modes = client.ModeString()
		if away, awayMsg := client.Away(); away {
			response.Away = awayMsg
		}
		response.SessionCount = len(client.Sessions())

		channels := client.Channels()
		response.Channels = make([]apiWhoisChannelData, 0, len(channels))
		for _, channel := range channels {
			present, joinTime, cModes := channel.ClientStatus(client)
			if !present {
				continue
			}
			chData := apiWhoisChannelData{
				Name:     channel.Name(),
				JoinTime: joinTime.Format(utils.IRCv3TimestampFormat),
			}
			for _, m := range modes.ChannelUserModes {
				if slices.Contains(cModes, m) {
					chData.Mode = string(rune(m))
					break
				}
			}
			response.Channels = append(response.Channels, chData)
		}
	}

	a.writeJSONResponse(response, w, r)
}

func (a *ergoAPI) handleList(w http.ResponseWriter, r *http.Request) {
	channels := a.server.channels.ListableChannels()
	response := apiListResponse{
		apiGenericResponse: apiGenericResponse{Success: true},
		Channels:           make([]apiChannelData, 0, len(channels)),
	}
	for _, channel := range channels {
		response.Channels = append(response.Channels, channel.apiData())
	}
	a.writeJSONResponse(response, w, r)
}
