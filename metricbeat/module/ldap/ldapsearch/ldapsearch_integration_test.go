//go:build integration

package ldapsearch

import (
	"reflect"
	"testing"

	"github.com/elastic/beats/v7/libbeat/tests/compose"
	"github.com/elastic/beats/v7/metricbeat/mb"
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
		t.Logf("%s/%s events: %+v", f.Module().Name(), f.Name(), events)
		if len(errs) > 0 {
			t.Fatalf("Expected 0 errord, had %d. %v\n", len(errs), errs)
		}
	}
}

func TestNew(t *testing.T) {
	type args struct {
		base mb.BaseMetricSet
	}
	tests := []struct {
		name    string
		args    args
		want    mb.MetricSet
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.base)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

// func TestSubtreeMapping(t *testing.T) {
// 	service := compose.EnsureUp(t, "ldap")

// 	f := mbtest.NewReportingMetricSetV2Error(t, getConfigs(service.Host()))

// 	err := mbtest.WriteEventsReporterV2Error(f, t, "")
// 	if !assert.NoError(t, err) {
// 		t.FailNow()
// 	}
// }

func getConfigs(host string) []map[string]interface{} {
	return []map[string]interface{}{
		// {
		// 	"module":                "ldap",
		// 	"metricsets":            []string{"ldapsearch"},
		// 	"hosts":                 []string{host},
		// 	"bind_dn":               "cn=admin,dc=example,dc=org",
		// 	"bind_pw":               "adminpassword",
		// 	"enabled":               true,
		// 	"period":                "10s",
		// 	"ssl.enabled":           true,
		// 	"ssl.verification_mode": "none",
		// 	"ldapsearch.searches": []map[string]interface{}{
		// 		{"name": "cnMonitor",
		// 			"url":  cnMonitorUrl,
		// 			"mode": "all",
		// 		},
		// 	},
		// },
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
					"url":  "ldaps://localhost:1636/cn=monitor?*?sub?(objectClass=*)",
					"mode": "all",
				},
			},
		},
	}
}
