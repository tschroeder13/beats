// go:build unit

package ldapsearch

import (
	"crypto/tls"
	"testing"

	"github.com/elastic/beats/v7/libbeat/tests/compose"
	"github.com/elastic/beats/v7/metricbeat/helper/ldapsearch"
)

func TestEventMapping(t *testing.T) {
	compose.EnsureUp(t, "ldap")
	config := map[string]string{
		"bind_dn": "cn=admin,dc=example,dc=org",
		"bind_pw": "adminpassword",
		"period":  "10s",
		"url":     "ldaps://localhost:1636/cn=monitor?+?sub?(objectClass=*)",
	}
	sr, err := ldapsearch.LdapsSearch(
		config["url"],
		&tls.Config{InsecureSkipVerify: true},
		config["bind_dn"],
		config["bind_pw"],
	)
	evt := eventMapping(sr.Entries, "cnMonitor")
	for _, e := range evt {
		println(e.StringToPrint())
	}
	if err != nil {
		t.Fatal(err)
	}
}
