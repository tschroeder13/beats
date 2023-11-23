// go:build unit
package ldapsearch

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/elastic/beats/v7/libbeat/tests/compose"
	"github.com/go-ldap/ldap/v3"
	"github.com/joeshaw/multierror"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

func getConfigs() map[string]string {
	return map[string]string{
		"bind_dn": "cn=admin,dc=example,dc=org",
		"bind_pw": "adminpassword",
		"period":  "10s",
		"url":     "ldaps://localhost:1636/cn=monitor?+?sub?(objectClass=*)",
	}
}

func TestNewLdapsUrlSubScope(t *testing.T) {
	url, err := NewLdapUrl(getConfigs()["url"])
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, url.Scheme, "ldaps", "Scheme does not match")
	assert.Equal(t, url.Hostname, "localhost", "Hostname does not match")
	assert.Equal(t, url.Port, "1636", "Port does not match")
	assert.Equal(t, url.BaseDN, "cn=monitor", "BaseDN does not match")
	assert.Equal(t, url.Attributes[0], "+", "Attributes does not match")
	assert.Equal(t, url.Scope, ldap.ScopeWholeSubtree, "Scope does not match")
	assert.Equal(t, url.Filter, "(objectClass=*)", "Filter does not match")
}

func TestNewLdapsUrlBaseScope(t *testing.T) {
	s := "ldaps://localhost:1636/cn=monitor?+??(objectClass=*)"
	url, err := NewLdapUrl(s)
	assert.NilError(t, err, "Unexpected error parsing LDAP URL")
	assert.Equal(t, url.Scope, ldap.ScopeBaseObject, "Scope does not match")
}

func TestNewLdapsUrlOneScope(t *testing.T) {
	s := "ldaps://localhost:1636/cn=monitor?+?one?(objectClass=*)"
	url, err := NewLdapUrl(s)
	assert.NilError(t, err, "Unexpected error parsing LDAP URL")
	assert.Equal(t, url.Scope, ldap.ScopeSingleLevel, "Scope does not match")
}

func TestNewLDapUrlAdvanced(t *testing.T) {
	s := "ldaps://your.ldap.host:636/cn=search,o=base?some,return,attributes,list?sub?(objectClass=inetOrgPerson)#0#10#60#false"
	url, err := NewLdapUrl(s)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, url.DerefAliases, 0, "Dereference Aliases not as expected")
	assert.Equal(t, url.SizeLimit, 10, "Dereference Aliases not as expected")
	assert.Equal(t, url.TimeLimit, 60, "Dereference Aliases not as expected")
	assert.Equal(t, url.TypesOnly, false, "Dereference Aliases not as expected")

}

func TestNewLDapUrlDefaults(t *testing.T) {
	s := ":///cn=search,o=base???####"
	url, err := NewLdapUrl(s)
	assert.Check(t, err != nil, "URL not parsable %v", err)
	assert.Equal(t, url.Scheme, "ldaps", "Default Scheme not as expected")
	assert.Equal(t, url.Hostname, "localhost", "Default Scheme not as expected")
	assert.Equal(t, url.Port, "636", "Default Port not as expected")
	assert.Equal(t, url.BaseDN, "dc=example,dc=org", "Default Base DN not as expected")
	assert.Equal(t, url.Attributes[0], "*", "Default Attributes not as expected")
	assert.Equal(t, url.Scope, 2, "Default Scope not as expected")
	assert.Equal(t, url.Filter, "(objectClass=*)", "Default Filter not as expected")
	assert.Equal(t, url.DerefAliases, 0, "Default Dereference Aliases not as expected")
	assert.Equal(t, url.SizeLimit, 0, "Default Size limit not as expected")
	assert.Equal(t, url.TimeLimit, 0, "Default Time limit not as expected")
	assert.Equal(t, url.TypesOnly, false, "Default Types only not as expected")

}

func TestToConnectionString(t *testing.T) {
	url, err := NewLdapUrl(getConfigs()["url"])
	if err != nil {
		t.Fatal(err)
	}
	uri := url.ToConnectionString()

	assert.Equal(t, uri, "ldaps://localhost:1636", "LdapURL.toUri conversion not as expected!")
}

func TestLdapsSearch(t *testing.T) {
	compose.EnsureUp(t, "ldap")
	url := "ldaps://localhost:1636/ou=users,dc=example,dc=org?cn,sn,gidNumber,objectClass?sub?(objectClass=inetOrgPerson)"
	config := getConfigs()
	var errs multierror.Errors
	sr, err := LdapsSearch(
		url,
		&tls.Config{InsecureSkipVerify: true},
		config["bind_dn"],
		config["bind_pw"],
	)
	errs = append(errs, err)

	entries := sr.Entries

	assert.Check(t, cmp.Len(entries, 3), "Result Count does not match")
	for _, entry := range entries {
		assert.Check(t, cmp.Contains(entry.GetAttributeValues("objectClass"), "inetOrgPerson"), "ObjectClass 'inetOrgPerson' unavailable")
	}
	e := errs.Err().(*multierror.MultiError)
	for _, er := range e.Errors {

		if er != nil {
			t.Fatal(er)
		}
	}
}
func TestLdapSearch(t *testing.T) {
	compose.EnsureUp(t, "ldap")
	url := "ldap://localhost:1389/ou=users,dc=example,dc=org?cn,sn,gidNumber,objectClass?sub?(objectClass=inetOrgPerson)"
	config := getConfigs()
	var errs multierror.Errors
	sr, err := LdapSearch(
		url,
		config["bind_dn"],
		config["bind_pw"],
	)
	errs = append(errs, err)

	entries := sr.Entries

	assert.Check(t, cmp.Len(entries, 3), "Result Count does not match")
	for _, entry := range entries {
		assert.Check(t, cmp.Contains(entry.GetAttributeValues("objectClass"), "inetOrgPerson"), "ObjectClass 'inetOrgPerson' unavailable")
	}
	e := errs.Err().(*multierror.MultiError)
	for _, er := range e.Errors {

		if er != nil {
			t.Fatal(er)
		}
	}
}

func TestSortSR(t *testing.T) {
	compose.EnsureUp(t, "ldap")
	url := "ldap://localhost:1389/cn=monitor?+?sub?(objectClass=*)"
	config := getConfigs()
	var errs multierror.Errors
	sr, err := LdapSearch(
		url,
		config["bind_dn"],
		config["bind_pw"],
	)
	errs = append(errs, err)

	entries := sr.Entries
	SortSRbyDepth(entries)
	prev := 0
	for _, entry := range entries {
		ns := (DnToNs(entry.DN))
		assert.Assert(t, len(strings.Split(ns, ".")) >= prev, "Sorting DR by depth not working")
		prev = len(strings.Split(ns, "."))

	}
}
