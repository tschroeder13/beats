//go:build integration

package ldapsearch

import (
	"testing"

	"github.com/elastic/beats/v7/libbeat/tests/compose"
	mbtest "github.com/elastic/beats/v7/metricbeat/mb/testing"
	"github.com/stretchr/testify/assert"
)

func TestFetch(t *testing.T) {
	service := compose.EnsureUp(t, "ldap")

	for _, config := range getConfigs(service.Host()) {

		f := mbtest.NewReportingMetricSetV2Error(t, config)
		events, errs := mbtest.ReportingFetchV2Error(f)
		assert.Empty(t, errs)
		assert.NotEmpty(t, events)
		t.Logf("Test fetch events for %s/%s: %+v", f.Module().Name(), f.Name(), events)
		if len(errs) > 0 {
			t.Fatalf("Expected 0 errors, had %d. %v\n", len(errs), errs)
		}
	}
}

func getConfigs(host string) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"module":      "ldap",
			"metricsets":  []string{"ldapsearch"},
			"hosts":       []string{host},
			"bind_dn":     "cn=admin,dc=example,dc=org",
			"bind_pw":     "adminpassword",
			"enabled":     true,
			"period":      "10s",
			"ssl.enabled": false,
			"ldapsearch.searches": []map[string]interface{}{
				{"name": "cnMonitor",
					"url": "ldap://localhost:1389/cn=monitor?*?sub?(objectClass=*)",
				},
			},
		},
		{
			"module":                      "ldap",
			"metricsets":                  []string{"ldapsearch"},
			"enabled":                     true,
			"hosts":                       []string{"localhost"},
			"bind_dn":                     "cn=admin,dc=example,dc=org",
			"bind_pw":                     "adminpassword",
			"period":                      "10s",
			"ssl.enabled":                 true,
			"ssl.certificate_authorities": []string{"../_meta/certs/rootCA.crt"},
			"ssl.certificate":             "../_meta/certs/domain.crt",
			"ssl.key":                     "../_meta/certs/domain.key",
			"ldapsearch.searches": []map[string]interface{}{
				{"name": "cnMonitor",
					"url": "ldaps://localhost:1636/cn=monitor?*?sub?(objectClass=*)",
				},
			},
		},
		{
			"module":                      "ldap",
			"metricsets":                  []string{"ldapsearch"},
			"enabled":                     true,
			"hosts":                       []string{"localhost"},
			"bind_dn":                     "cn=admin,dc=example,dc=org",
			"bind_pw":                     "adminpassword",
			"period":                      "10s",
			"ssl.enabled":                 true,
			"ssl.certificate_authorities": []string{"../_meta/certs/rootCA.crt"},
			"ssl.certificate":             "../_meta/certs/domain.crt",
			"ssl.key":                     "../_meta/certs/domain.key",
			"ldapsearch.searches": []map[string]interface{}{
				{"name": "cnMonitor",
					"url": "ldaps://localhost:1636/ou=users,dc=example,dc=org?cn,sn,gidNumber,objectClass?sub?(objectClass=inetOrgPerson)",
				},
			},
		},
	}
}
