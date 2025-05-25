         __ __  ______ ___  ______ ___ 
      __/ // /_/ ____/ __ \/ ____/ __ \
     /_  // __/ __/ / /_/ / / __/ / / /
    /_  // __/ /___/ _, _/ /_/ / /_/ / 
     /_//_/ /_____/_/ |_|\____/\____/  

        Ergo IRCd API Documentation
            https://ergo.chat/

_Copyright © Daniel Oaks <daniel@danieloaks.net>, Shivaram Lingamneni <slingamn@cs.stanford.edu>_


--------------------------------------------------------------------------------------------

Ergo has an experimental HTTP API. Some general information about the API:

1. All requests to the API are via POST.
1. All requests to the API are authenticated via bearer authentication. This is a header named `Authorization` with the value `Bearer <token>`. A list of valid tokens is hardcoded in the Ergo config. Future versions of Ergo may allow additional validation schemes for tokens.
1. The request parameters are sent as JSON in the POST body.
1. Any status code other than 200 is an error response; the response body is undefined in this case (likely human-readable text for debugging).
1. A 200 status code indicates successful execution of the request. The response body will be JSON and may indicate application-level success or failure (typically via the `success` field, which takes a boolean value).

API endpoints are versioned (currently all endpoints have a `/v1/` path prefix). Backwards-incompatible updates will most likely take the form of endpoints with new names, or an increased version prefix. Any exceptions to this will be specifically documented in the changelog.

All API endpoints should be considered highly privileged. Bearer tokens should be kept secret. Access to the API should be either over a trusted link (like loopback) or secured via verified TLS. See the `api` section of `default.yaml` for examples of how to configure this.

Here's an example of how to test an API configured to run over loopback TCP in plaintext:

```bash
curl -d '{"accountName": "invalidaccountname", "passphrase": "invalidpassphrase"}' -H 'Authorization: Bearer EYBbXVilnumTtfn4A9HE8_TiKLGWEGylre7FG6gEww0' -v http://127.0.0.1:8089/v1/check_auth
```

This returns:

```json
{"success":false}
```

Endpoints
=========

`/v1/account_details`
----------------

This endpoint fetches account details and returns them as JSON. The request is a JSON object with fields:

* `accountName`: string, name of the account

The response is a JSON object with fields:

* `success`: whether the account exists or not
* `accountName`: canonical, case-unfolded version of the account name
* `email`: email address of the account provided
* `registeredAt`: string, registration date/time of the account (in ISO8601 format)
* `channels`: array of strings, list of channels the account is registered on or associated with

`/v1/check_auth`
----------------

This endpoint verifies the credentials of a NickServ account; this allows Ergo to be used as the source of truth for authentication by another system. The request is a JSON object with fields:

* `accountName`: string, name of the account
* `passphrase`: string, alleged passphrase of the account

The response is a JSON object with fields:

* `success`: whether the credentials provided were valid
* `accountName`: canonical, case-unfolded version of the account name

`/v1/rehash`
------------

This endpoint rehashes the server (i.e. reloads the configuration file, TLS certificates, and other associated data). The body is ignored. The response is a JSON object with fields:

* `success`: boolean, indicates whether the rehash was successful
* `error`: string, optional, human-readable description of the failure

`/v1/saregister`
----------------

This endpoint registers an account in NickServ, with the same semantics as `NS SAREGISTER`. The request is a JSON object with fields:

* `accountName`: string, name of the account
* `passphrase`: string, passphrase of the account

The response is a JSON object with fields:

* `success`: whether the account creation succeeded
* `errorCode`: string, optional, machine-readable description of the error. Possible values include: `ACCOUNT_EXISTS`, `INVALID_PASSPHRASE`, `UNKNOWN_ERROR`.
* `error`: string, optional, human-readable description of the failure.

`/v1/account_list`
-------------------

This endpoint fetches a list of all accounts. The request body is ignored and can be empty.

The response is a JSON object with fields:

* `success`: whether the request succeeded
* `accounts`: array of objects, each with fields:
  * `success`: boolean, whether this individual account query succeeded
  * `accountName`: string, canonical, case-unfolded version of the account name
* `totalCount`: integer, total number of accounts returned


`/v1/status`
-------------

This endpoint returns status information about the running Ergo server. The request body is ignored and can be empty.

The response is a JSON object with fields:

* `success`: whether the request succeeded
* `version`: string, Ergo server version string
* `go_version`: string, version of Go runtime used
* `start_time`: string, server start time in ISO8601 format
* `users`: object with fields:
  * `total`: total number of users connected
  * `invisible`: number of invisible users
  * `operators`: number of operators connected
  * `unknown`: number of users with unknown status
  * `max`: maximum number of users seen connected at once
* `channels`: integer, number of channels currently active
* `servers`: integer, number of servers connected in the network
