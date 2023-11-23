import metricbeat
import os
import pytest
import sys
import unittest

LDAP_FIELDS = metricbeat.COMMON_FIELDS + ["ldap"]


@metricbeat.parameterized_with_supported_versions
class Test(metricbeat.BaseTest):

    COMPOSE_SERVICES = ['ldap']

    @unittest.skipUnless(metricbeat.INTEGRATION_TESTS, "integration test")
    @pytest.mark.tag('integration')
    def test_status(self):
        """
        LDAP module outputs an event.
        """
        additional_content = """
  "ldapsearch.searches":
    - "name": "cnMonitor",
      "url": "ldaps://localhost:1636/ou=users,dc=example,dc=org?cn,sn,gidNumber,objectClass?sub?(objectClass=inetOrgPerson)",
"""

        self.render_config_template(modules=[{
            "name": "ldap",
            "metricsets": ["ldapsearch"],
            "hosts": ["localhost"],
            "period": "10s",
            "enabled": True,
			"bind_dn": "cn=admin,dc=example,dc=org",
			"bind_pw": "adminpassword",
			"ssl.enabled": True,
			"ssl.certificate_authorities": ["../_meta/certs/rootCA.crt"],
			"ssl.certificate":             "../_meta/certs/domain.crt",
			"ssl.key":                     "../_meta/certs/domain.key",
            "additional_content": additional_content,
        }])
        proc = self.start_beat()
        self.wait_until(lambda: self.output_lines() > 0)
        proc.check_kill_and_wait()
        self.assert_no_logged_warnings()

        output = self.read_output_json()
        self.assertTrue(len(output) >= 1)
        evt = output[0]

        println(evt)

