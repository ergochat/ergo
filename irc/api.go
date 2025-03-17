package irc

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func newAPIHandler(server *Server) http.Handler {
	api := &ergoAPI{
		server: server,
		mux:    http.NewServeMux(),
	}

	api.mux.HandleFunc("POST /v1/rehash", api.handleRehash)
	api.mux.HandleFunc("POST /v1/check_auth", api.handleCheckAuth)
	api.mux.HandleFunc("POST /v1/saregister", api.handleSaregister)

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
		http.Error(w, fmt.Sprintf("failed to deserialize json request: %v", err), http.StatusInternalServerError)
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
		a.server.logger.Error("internal", "failed to serialize API response", r.URL.String(), err.Error())
		http.Error(w, fmt.Sprintf("failed to serialize json response: %v", err), http.StatusInternalServerError)
	}
}

type apiGenericResponse struct {
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
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
