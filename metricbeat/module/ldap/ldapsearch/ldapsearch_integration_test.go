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
		// if len(errs) > 0 {
		// 	t.Fatalf("Expected 0 errord, had %d. %v\n", len(errs), errs)
		// }
		assert.Empty(t, errs)
		assert.NotEmpty(t, events)
		t.Logf("%s/%s events: %+v", f.Module().Name(), f.Name(), events)
	}
}

func TestData(t *testing.T) {
	service := compose.EnsureUp(t, "ldap")

	f := mbtest.NewReportingMetricSetV2Error(t, getConfigs(service.Host()))

	err := mbtest.WriteEventsReporterV2Error(f, t, "")
	if !assert.NoError(t, err) {
		t.FailNow()
	}
}

func getConfigs(host string) []map[string]interface{} {
	cnMonitorUrl := "ldap://" + host + "/cn=monitor?+??(objectClass=*)"
	return []map[string]interface{}{
		{
			"module":                "ldap",
			"metricsets":            []string{"ldapsearch"},
			"hosts":                 []string{host},
			"enabled":               true,
			"period":                "10s",
			"ssl.enabled":           true,
			"ssl.verification_mode": "none",
			"ldapsearch.searches": []map[string]interface{}{
				{"name": "cnMonitor",
					"url": cnMonitorUrl,
					// "cert_path": "some path", ## to be replaced with module's ssl.certificate_authorities
					"bind_dn": "cn=admin,dc=example,dc=org",
					"bind_pw": "adminpassword",
					"mode":    "allAttributes",
				},
			},
		},
		{
			"module":                      "ldap",
			"metricsets":                  []string{"ldapsearch"},
			"hosts":                       []string{host},
			"enabled":                     true,
			"period":                      "10s",
			"ssl.enabled":                 true,
			"ssl.certificate_authorities": []string{"../_meta/certs/rootCA.crt"},
			"ssl.certificate":             "../_meta/certs/domain.crt",
			"ssl.key":                     "../_meta/certs/domain.key",
			"ldapsearch.searches": []map[string]interface{}{
				{"name": "cnMonitor",
					"url": cnMonitorUrl,
					// "cert_path": "some path", ## to be replaced with module's ssl.certificate_authorities
					"bind_dn": "cn=admin,dc=example,dc=org",
					"bind_pw": "adminpassword",
					"mode":    "allAttributes",
				},
			},
		},
	}
}
