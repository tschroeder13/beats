package ldaphelper

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type ldapUrl struct {
	Scheme     string
	Hostname   string
	Port       string
	BaseDN     string
	Attributes []string
	Scope      int
	Filter     string
}

// type LdapConnection struct {
// 	*ldap.Conn
// 	logger *logp.Logger
// }

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
func LdapSearch(uri string, binddn string, bindpw string) (*ldap.SearchResult, error) {
	u, err := NewLdapUrl(uri)
	if err != nil {
		return nil, fmt.Errorf("Provided URI not parsable: %w", err)
	}
	l, err := ldap.DialURL(uri)
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
func LdapsSearch(uri string, tls *tls.Config, binddn string, bindpw string) (*ldap.SearchResult, error) {
	u, err := NewLdapUrl(uri)
	if err != nil {
		return nil, fmt.Errorf("Provided URI not parsable: %w", err)
	}
	// println("PONG!" + cacertpath)
	// certPool := x509.NewCertPool()
	// pem, err := os.ReadFile(cacertpath)
	// if err != nil {
	// 	return nil, fmt.Errorf("CA file could not be opened: %w", err)
	// }
	// certPool.AppendCertsFromPEM(pem)
	// tlsConf := &tls.Config{RootCAs: certPool}
	// // ldap.Logger(log.Named("LDAP").)
	l, err := ldap.DialURL(uri, ldap.DialWithTLSConfig(tls))
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
