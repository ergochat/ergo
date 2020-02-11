// Copyright (c) 2020 Matt Ouille
// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

// Portions of this code copyright Grafana Labs and contributors
// and released under the Apache 2.0 license

package ldap

import (
	"fmt"
	"strings"
	"time"
)

type LDAPConfig struct {
	Enabled    bool
	Autocreate bool

	Host          string
	Port          int
	Timeout       time.Duration
	UseSSL        bool   `yaml:"use-ssl"`
	StartTLS      bool   `yaml:"start-tls"`
	SkipTLSVerify bool   `yaml:"skip-tls-verify"`
	RootCACert    string `yaml:"root-ca-cert"`
	ClientCert    string `yaml:"client-cert"`
	ClientKey     string `yaml:"client-key"`

	BindDN        string   `yaml:"bind-dn"`
	BindPassword  string   `yaml:"bind-password"`
	SearchFilter  string   `yaml:"search-filter"`
	SearchBaseDNs []string `yaml:"search-base-dns"`

	// user validation: require them to be in any one of these groups
	RequireGroups []string `yaml:"require-groups"`

	// two ways of testing group membership: either via an attribute
	// of the user's DN, typically named 'memberOf', but customizable:
	MemberOfAttribute string `yaml:"member-of-attribute"`
	// or by searching for groups that match the user's DN
	// and testing their names:
	GroupSearchFilter              string   `yaml:"group-search-filter"`
	GroupSearchFilterUserAttribute string   `yaml:"group-search-filter-user-attribute"`
	GroupSearchBaseDNs             []string `yaml:"group-search-base-dns"`
}

// shouldAdminBind checks if we should use
// admin username & password for LDAP bind
func (config *LDAPConfig) shouldAdminBind() bool {
	return config.BindPassword != ""
}

// shouldSingleBind checks if we can use "single bind" approach
func (config *LDAPConfig) shouldSingleBind() bool {
	return strings.Contains(config.BindDN, "%s")
}

// singleBindDN combines the bind with the username
// in order to get the proper path
func (config *LDAPConfig) singleBindDN(username string) string {
	return fmt.Sprintf(config.BindDN, username)
}
