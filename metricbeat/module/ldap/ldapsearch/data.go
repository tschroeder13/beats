package ldapsearch

import (
	"github.com/elastic/beats/v7/metricbeat/helper/ldapsearch"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/go-ldap/ldap/v3"
)

func eventMapping(entries []*ldap.Entry, name string) []mapstr.M {
	ldapsearch.SortSRbyDepth(entries)

	events := []mapstr.M{}
	for idx, entry := range entries {
		event := mapstr.M{}
		ns := ldapsearch.DnToNs(entry.DN)
		for _, attr := range entry.Attributes {
			event.Put(attr.Name, attr.Values[0])
		}
		if entry.GetAttributeValue("entryDN") == "" {
			event.Put("entryDN", entry.DN)

		}
		event.Put("namespace", ns)
		event.Put("search Name", name)
		event.Put("total", len(entries))
		event.Put("count", idx)
		events = append(events, event)
	}
	return events
}
