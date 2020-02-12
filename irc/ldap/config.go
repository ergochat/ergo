// Copyright 2014-2018 Grafana Labs
// Released under the Apache 2.0 license

// Modification notice:
// 1. All field names were changed from toml and snake case to yaml and kebab case,
//    matching the Oragono project conventions
// 2. Four fields were added:
//    2.1 `Enabled`
//    2.2 `Autocreate`
//    2.3 `Timeout`
//    2.4 `RequireGroups`

// XXX: none of AttributeMap does anything in oragono, except MemberOf,
// which can be used to retrieve group memberships

package ldap

import (
	"time"
)

type ServerConfig struct {
	Enabled    bool
	Autocreate bool

	Host          string
	Port          int
	Timeout       time.Duration
	UseSSL        bool   `yaml:"use-ssl"`
	StartTLS      bool   `yaml:"start-tls"`
	SkipVerifySSL bool   `yaml:"ssl-skip-verify"`
	RootCACert    string `yaml:"root-ca-cert"`
	ClientCert    string `yaml:"client-cert"`
	ClientKey     string `yaml:"client-key"`

	BindDN        string   `yaml:"bind-dn"`
	BindPassword  string   `yaml:"bind-password"`
	SearchFilter  string   `yaml:"search-filter"`
	SearchBaseDNs []string `yaml:"search-base-dns"`

	// user validation: require them to be in any one of these groups
	RequireGroups []string `yaml:"require-groups"`

	// two ways of testing group membership:
	// either by searching for groups that match the user's DN
	// and testing their names:
	GroupSearchFilter              string   `yaml:"group-search-filter"`
	GroupSearchFilterUserAttribute string   `yaml:"group-search-filter-user-attribute"`
	GroupSearchBaseDNs             []string `yaml:"group-search-base-dns"`

	// or by an attribute on the user's DN, typically named 'memberOf', but customizable:
	Attr AttributeMap `yaml:"attributes"`
}

// AttributeMap is a struct representation for LDAP "attributes" setting
type AttributeMap struct {
	Username string
	Name     string
	Surname  string
	Email    string
	MemberOf string `yaml:"member-of"`
}
