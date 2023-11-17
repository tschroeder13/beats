package ldapsearch

import (
	"fmt"

	"github.com/elastic/beats/v7/libbeat/common/cfgwarn"
	"github.com/elastic/beats/v7/metricbeat/helper/ldaphelper"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
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
	Namespace string `config:"name"`
	LdapUrl   string `config:"url"`
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
	TLS *tlscommon.Config `config:"ssl"`
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
func (m *MetricSet) Fetch(report mb.ReporterV2) error {

	for _, s := range m.Searches {
		err := m.searchLdap(s, report)
		if err != nil {
			m.Logger().Errorf("error doing search %s", s, err)
		}
	}
	return nil
}

func (m *MetricSet) searchLdap(s search, reporter mb.ReporterV2) error {
	if !m.TLS.IsEnabled() {
		sr, err := ldaphelper.LdapSearch(s.LdapUrl,
			s.BindDN,
			s.BindSecret,
		)
		sr.PrettyPrint(2)
		if err != nil {
			reporter.Error(err)
		}
		reporter.Event(mb.Event{
			MetricSetFields: mapstr.M{
				"ldapsearch.result": sr.Entries,
			},
		})

	}
	if m.TLS.IsEnabled() {
		println("PING!")
		tlsConfig, err := tlscommon.LoadTLSConfig(m.TLS)
		if err != nil {
			return fmt.Errorf("could not load provided TLS configuration: %w", err)
		}
		sr, err := ldaphelper.LdapsSearch(s.LdapUrl,
			tlsConfig.ToConfig(),
			s.BindDN,
			s.BindSecret,
		)
		sr.PrettyPrint(2)
		if err != nil {
			reporter.Error(err)
		}
		reporter.Event(mb.Event{
			MetricSetFields: mapstr.M{
				"ldapsearch.result": sr.Entries,
			},
		})
	}

	return nil
}
