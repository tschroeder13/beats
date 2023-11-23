package ldapsearch

import (
	"fmt"

	"github.com/elastic/beats/v7/libbeat/common/cfgwarn"
	"github.com/elastic/beats/v7/metricbeat/helper/ldapsearch"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/go-ldap/ldap/v3"
)

// init registers the MetricSet with the central registry as soon as the program
// starts. The New function will be called later to instantiate an instance of
// the MetricSet for each host defined in the module's configuration. After the
// MetricSet has been created then Fetch will begin to be called periodically.
func init() {
	mb.Registry.MustAddMetricSet("ldap", "ldapsearch", New)
}

type search struct {
	// Namespace for the ldap event. It effectively names the metricset. For example using `performance` will name
	// all events `ldap.performance.*`
	Name    string `config:"name"`
	LdapUrl string `config:"url"`
	// // Path to the server's trusted root CA certificate
	// CaCertPath string `config:"cert_path"`
	// The user's DN to search with
	BindDN string `config:"bind_dn"`
	// The user's password
	BindSecret string `config:"bind_pw"`
}

// MetricSet holds any configuration or state information. It must implement
// the mb.MetricSet interface. And this is best achieved by embedding
// mb.BaseMetricSet because it implements all of the required mb.MetricSet
// interface methods except for Fetch.
type MetricSet struct {
	mb.BaseMetricSet
	BindDN string            `config:"bind_dn"`
	BindPW string            `config:"bind_pw"`
	TLS    *tlscommon.Config `config:"ssl"`
	// counter int
	Searches []search `config:"ldapsearch.searches" validate:"nonzero,required"`
}

// New creates a new instance of the MetricSet. New is responsible for unpacking
// any MetricSet specific configuration options if there are any.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	cfgwarn.Beta("The ldap ldapsearch metricset is beta.")

	b := &MetricSet{BaseMetricSet: base}
	if err := base.Module().UnpackConfig(&b); err != nil {
		return nil, err
	}

	return b, nil
}

// Fetch methods implements the data gathering and data conversion to the right
// format. It publishes the event which is then forwarded to the output. In case
// of an error set the Error field of mb.Event or simply call report.Error().
func (m *MetricSet) Fetch(reporter mb.ReporterV2) error {
	var err error
	var sr *ldap.SearchResult

	for _, s := range m.Searches {
		if !m.TLS.IsEnabled() {
			sr, err = ldapsearch.LdapSearch(s.LdapUrl,
				m.BindDN,
				m.BindPW,
			)
		}
		if m.TLS.IsEnabled() {
			var tlsConfig *tlscommon.TLSConfig
			tlsConfig, err = tlscommon.LoadTLSConfig(m.TLS)
			if err != nil {
				return fmt.Errorf("could not load provided TLS configuration: %w", err)
			}
			sr, err = ldapsearch.LdapsSearch(s.LdapUrl,
				tlsConfig.ToConfig(),
				m.BindDN,
				m.BindPW,
			)
		}
		if err != nil {
			m.Logger().Errorf("error doing search %s", s, err)
		}
		eventMapping(sr.Entries, s.Name)
		if err != nil {
			reporter.Error(err)
		}
		reporter.Event(mb.Event{
			MetricSetFields: mapstr.M{
				s.Name: sr.Entries,
			},
		})
	}

	return err
}
