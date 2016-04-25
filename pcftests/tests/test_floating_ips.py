# Copyright 2013 IBM Corporation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import subprocess

from oslo_log import log as logging
from tempest.common.utils import data_utils
from tempest import config
from tempest.lib.common.utils import misc as misc_utils
import tempest.test

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class FloatingIpsTest(base.BasePCFTest):
    """Tests capability to allocate Floating IPs.."""
    credentials = ['primary', 'admin']

    @classmethod
    def setup_credentials(cls):
        super(FloatingIpsTest, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(FloatingIpsTest, cls).setup_clients()
        cls.client = cls.floatingip_client

    @classmethod
    def resource_setup(cls):
        """Setup resources"""
        super(FloatingIpsTest, cls).resource_setup()

    @classmethod
    def resource_cleanup(cls):
        """Cleanup at the end of the tests."""
        super(FloatingIpsTest, cls).resource_cleanup()

    def ping_ip_address(self, ip_address, should_succeed=True,
                        ping_timeout=None):
        timeout = ping_timeout or CONF.validation.ping_timeout
        cmd = ['ping', '-c1', '-w1', ip_address]

        def ping():
            proc = subprocess.Popen(cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            proc.communicate()
            return (proc.returncode == 0) == should_succeed

        caller = misc_utils.find_test_caller()
        LOG.debug('%(caller)s begins to ping %(ip)s in %(timeout)s sec and the'
                  'expected result is %(should_succeed)s' %
                  {'caller': caller, 'ip': ip_address, 'timeout': timeout,
                   'should_succeed': 'reachable' if should_succeed
                   else 'unreachable'})
        result = tempest.test.call_until_true(ping, timeout, 1)
        LOG.debug('%(caller)s finishes ping %(ip)s in %(timeout)s sec and the '
                  'ping result is %(result)s' % {
                      'caller': caller, 'ip': ip_address, 'timeout': timeout,
                      'result': 'expected' if result else 'unexpected'
                  })
        return result

    def test_allocate_floatingip(self):
        # Test the capability to allocate Floating IPs

        # Add rules to the security group
        rulesets = [
            dict(
                protocol='icmp',
            )
        ]
        server_name = data_utils.rand_name(self.__class__.__name__)
        server, floating = self.start_creation(rulesets, name=server_name)
        # Check instance_id in the floating_ip body
        body = (self.client.show_floating_ip(floating['id'])
                ['floating_ip'])
        self.assertEqual(server['id'], body['instance_id'])

        # Ping floating ip
        msg = "Timed out waiting for %s to become reachable" % floating['ip']
        self.assertTrue(self.ping_ip_address(floating['ip'],
                                             should_succeed=True), msg)
