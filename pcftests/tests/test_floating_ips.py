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
from tempest import config
import tempest.test
from tempest_lib.common.utils import misc as misc_utils

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class FloatingIpsTest(base.BaseServerTest):
    """Tests capability to allocate Floating IPs.."""

    @classmethod
    def setup_credentials(cls):
        # Floating IP actions might need a full network configuration
        cls.set_network_resources(network=True, subnet=True,
                                  router=True, dhcp=True)
        super(FloatingIpsTest, cls).setup_credentials()
        cls.tenant_id = cls.os.credentials.tenant_id

    @classmethod
    def setup_clients(cls):
        super(FloatingIpsTest, cls).setup_clients()
        cls.client = cls.os.compute_floating_ips_client

    @classmethod
    def resource_setup(cls):
        """Setup resources"""
        super(FloatingIpsTest, cls).resource_setup()
        cls.floating_ip_id = None

        cls.server = cls.create_server(
            wait_until='ACTIVE')
        cls.server_id = cls.server['id']
        # Floating IP creation
        body = cls.client.create_floating_ip()['floating_ip']
        cls.floating_ip_id = body['id']
        cls.floating_ip = body['ip']

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

    def test_allocate_floating_ip(self):
        # Capability to allocate Floating IPs.
        # Allocation of a new floating IP to a project
        body = self.client.create_floating_ip()['floating_ip']
        floating_ip_id_allocated = body['id']
        self.addCleanup(self.client.delete_floating_ip,
                        floating_ip_id_allocated)
        floating_ip_details = self.client.show_floating_ip(
            floating_ip_id_allocated)['floating_ip']
        # Checking if the details of allocated IP is in list of floating IP
        body = self.client.list_floating_ips()['floating_ips']
        self.assertIn(floating_ip_details, body)

    def test_associate_disassociate_floating_ip(self):
        # Positive test:Associate and disassociate the provided floating IP
        # to a specific server should be successful

        # Association of floating IP to fixed IP address
        self.client.associate_floating_ip_to_server(
            self.floating_ip,
            self.server_id)

        # Check instance_id in the floating_ip body
        body = (self.client.show_floating_ip(self.floating_ip_id)
                ['floating_ip'])
        self.assertEqual(self.server_id, body['instance_id'])

        # Ping floating ip
        ip_address = self.floating_ip
        msg = "Timed out waiting for %s to become reachable" % ip_address
        self.assertTrue(self.ping_ip_address(ip_address,
                                             should_succeed=True), msg)

        # Disassociation of floating IP that was associated in this method
        self.client.disassociate_floating_ip_from_server(
            self.floating_ip,
            self.server_id)
