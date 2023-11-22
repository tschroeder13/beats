/*
Elastic Metricbeat helper for LDAP connectivity
*/
package ldaphelper

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ldapUrl stores all values needed for an ldapsearch
type ldapUrl struct {
	Scheme     string
	Hostname   string
	Port       string
	BaseDN     string
	Attributes []string
	Scope      int
	Filter     string
}

// Generate a ldapUrl from a URL string, e.g. copied from advanced options in Apache Directory Studio
func NewLdapUrl(s string) (*ldapUrl, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("URL parsing error: %w", err)
	}
	var scp int
	query := strings.Split(u.RawQuery, "?")
	attr := strings.Split(query[0], ",")
	if strings.Split(u.RawQuery, "?")[1] == "sub" {
		scp = ldap.ScopeWholeSubtree
	}
	if strings.Split(u.RawQuery, "?")[1] == "one" {
		scp = ldap.ScopeSingleLevel
	}
	if strings.Split(u.RawQuery, "?")[1] == "" {
		scp = ldap.ScopeBaseObject
	}

	return &ldapUrl{
		Scheme:     u.Scheme,
		Hostname:   u.Hostname(),
		Port:       u.Port(),
		BaseDN:     u.Path[1:],
		Attributes: attr,
		Scope:      scp,
		Filter:     query[2],
	}, nil
}

// rebuild an connection string from ldapUrl for connection purpose only
func (l ldapUrl) ToConnectionString() string {
	return l.Scheme + "://" + l.Hostname + ":" + l.Port
}

// Search an LDAP by URL (e.g. from Apache Directory Studio)
func LdapSearch(uri string, binddn string, bindpw string) (*ldap.SearchResult, error) {
	u, err := NewLdapUrl(uri)
	if err != nil {
		return nil, fmt.Errorf("Provided URI not parsable: %w", err)
	}
	s := u.ToConnectionString()
	l, err := ldap.DialURL(s)
	if err != nil {
		return nil, fmt.Errorf("Provided URI not parsable: %w", err)
	}
	defer l.Close()
	err = l.Bind(binddn, bindpw)
	if err != nil {
		log.Fatal(err)
	}
	searchRequest := ldap.NewSearchRequest(
		u.BaseDN,
		u.Scope,
		ldap.NeverDerefAliases, 0, 0, false,
		u.Filter,
		u.Attributes,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}
	return sr, err
}

// Search an LDAP by URL (e.g. from Apache Directory Studio) with SSL enabled
func LdapsSearch(uri string, tls *tls.Config, binddn string, bindpw string) (*ldap.SearchResult, error) {
	u, err := NewLdapUrl(uri)
	if err != nil {
		return nil, fmt.Errorf("Provided Uri not parsable: %w", err)
	}
	s := u.ToConnectionString()
	l, err := ldap.DialURL(s, ldap.DialWithTLSConfig(tls))
	if err != nil {
		return nil, fmt.Errorf("Provided URI not parsable: %w", err)
	}
	defer l.Close()
	err = l.Bind(binddn, bindpw)
	if err != nil {
		log.Fatal(err)
	}
	searchRequest := ldap.NewSearchRequest(
		u.BaseDN,
		u.Scope,
		ldap.NeverDerefAliases, 0, 0, false,
		u.Filter,
		u.Attributes,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}
	return sr, err
}

// Convert an entry*s Distinguished Name into a string like "some.longer.name.space"
func DnToNs(dn string) string {
	dnArr := strings.Split(dn, ",")
	for i := 0; i < len(dnArr); i++ {
		dnArr[i] = strings.Split(dnArr[i], "=")[1]
	}
	res := ""
	for i := len(dnArr) - 1; i >= 0; i-- {
		res += dnArr[i]
		if i != 0 {
			res += "."
		}
	}
	return res
}

// sort a []*ldap.Entry by entry's DN length/depth - shortest to longest
func SortSRbyDepth(entries []*ldap.Entry) []*ldap.Entry {
	sort.SliceStable(entries[:], func(i, j int) bool {
		a := DnToNs(entries[i].DN)
		b := DnToNs(entries[j].DN)
		return len(strings.Split(a, ".")) < len(strings.Split(b, "."))
	})
	return entries
}
