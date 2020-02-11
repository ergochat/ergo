// Copyright Grafana Labs and contributors
// and released under the Apache 2.0 license

package ldap

import (
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

func isMemberOf(memberOf []string, group string) bool {
	if group == "*" {
		return true
	}

	for _, member := range memberOf {
		if strings.EqualFold(member, group) {
			return true
		}
	}
	return false
}

func getArrayAttribute(name string, entry *ldap.Entry) []string {
	if strings.ToLower(name) == "dn" {
		return []string{entry.DN}
	}

	for _, attr := range entry.Attributes {
		if attr.Name == name && len(attr.Values) > 0 {
			return attr.Values
		}
	}
	return []string{}
}

func getAttribute(name string, entry *ldap.Entry) string {
	if strings.ToLower(name) == "dn" {
		return entry.DN
	}

	for _, attr := range entry.Attributes {
		if attr.Name == name {
			if len(attr.Values) > 0 {
				return attr.Values[0]
			}
		}
	}
	return ""
}
