package ldapsearch

import (
	"github.com/elastic/beats/v7/metricbeat/helper/ldaphelper"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/go-ldap/ldap/v3"
)

func eventMapping(entries []*ldap.Entry, name string) []mapstr.M {
	ldaphelper.SortSRbyDepth(entries)

	events := []mapstr.M{}
	for idx, entry := range entries {
		event := mapstr.M{}
		ns := ldaphelper.DnToNs(entry.DN)
		for _, attr := range entry.Attributes {
			event.Put(attr.Name, attr.Values[0])
		}
		if entry.GetAttributeValue("entryDN") == "" {
			event.Put("entryDN", entry.DN)

		}
		event.Put("Namespace", ns)
		event.Put("Search Name", name)
		event.Put("Total", len(entries))
		event.Put("Count", idx)
		events = append(events, event)
	}
	return events
}
