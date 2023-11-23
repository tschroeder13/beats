/*
Elastic Metricbeat helper for LDAP connectivity
*/
package ldapsearch

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-multierror"
	"github.com/mcuadros/go-defaults"
)

// ldapUrl stores all values needed for an ldapsearch
type ldapUrl struct {
	Scheme       string   `default:"ldaps"`
	Hostname     string   `default:"localhost"`
	Port         string   `default:"636"`
	BaseDN       string   `default:"dc=example,dc=org"`
	Attributes   []string `default:"[*]"`
	Scope        int      `default:"2"`
	Filter       string   `default:"(objectClass=*)"`
	DerefAliases int      `default:"0"`
	SizeLimit    int      `default:"0"`
	TimeLimit    int      `default:"0"`
	TypesOnly    bool     `default:"false"`
}

// Generate a ldapUrl from a URL string, e.g. copied from advanced options in Apache Directory Studio
func NewLdapUrl(s string) (*ldapUrl, error) {
	var err error
	u, e := url.Parse(s)
	url := new(ldapUrl)
	defaults.SetDefaults(url)
	if e != nil {
		err = multierror.Append(err, e)
	}
	if u != nil {

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
		if u.Fragment != "" {
			fragment := strings.Split(u.Fragment, "#")
			da, err := strconv.Atoi(fragment[0])
			if e != nil {
				err = multierror.Append(err, e)
			}
			sl, err := strconv.Atoi(fragment[1])
			if e != nil {
				err = multierror.Append(err, e)
			}
			tl, err := strconv.Atoi(fragment[2])
			if e != nil {
				err = multierror.Append(err, e)
			}
			to, err := strconv.ParseBool(fragment[3])
			if e != nil {
				err = multierror.Append(err, e)
			}
			url = &ldapUrl{
				Scheme:       u.Scheme,
				Hostname:     u.Hostname(),
				Port:         u.Port(),
				BaseDN:       u.Path[1:],
				Attributes:   attr,
				Scope:        scp,
				Filter:       query[2],
				DerefAliases: da,
				SizeLimit:    sl,
				TimeLimit:    tl,
				TypesOnly:    to,
			}
		} else {
			url = &ldapUrl{
				Scheme:     u.Scheme,
				Hostname:   u.Hostname(),
				Port:       u.Port(),
				BaseDN:     u.Path[1:],
				Attributes: attr,
				Scope:      scp,
				Filter:     query[2],
			}
		}
	}
	return url, err
}

// rebuild an connection string from ldapUrl for connection purpose only
func (l ldapUrl) ToConnectionString() string {
	return l.Scheme + "://" + l.Hostname + ":" + l.Port
}

// Search an LDAP by URL (e.g. from Apache Directory Studio)
func LdapSearch(uri string, binddn string, bindpw string) (*ldap.SearchResult, error) {
	var err error
	u, e := NewLdapUrl(uri)
	if e != nil {
		err = multierror.Append(err, e)
	}
	s := u.ToConnectionString()
	l, e := ldap.DialURL(s)
	if e != nil {
		err = multierror.Append(err, e)
	}
	defer l.Close()
	e = l.Bind(binddn, bindpw)
	if e != nil {
		err = multierror.Append(err, e)
	}
	searchRequest := ldap.NewSearchRequest(
		u.BaseDN,
		u.Scope,
		ldap.NeverDerefAliases, 0, 0, false,
		u.Filter,
		u.Attributes,
		nil,
	)

	sr, e := l.Search(searchRequest)
	if e != nil {
		err = multierror.Append(err, e)
		// return nil, fmt.Errorf("Provided URI not parsable: %w", err)
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
