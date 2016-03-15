# Copyright 2012 OpenStack Foundation
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


from oslo_log import log as logging

from tempest.common.utils import data_utils
from tempest import config
from tempest import exceptions
from tempest import test

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class TestMetadata(base.BasePCFTest):

    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(TestMetadata, cls).setup_clients()
        cls.client = cls.floatingip_client

    def verify_metadata(self):
        # Verify metadata service
        md_url = 'http://169.254.169.254/latest/meta-data/public-ipv4'
        private_key = self.keypair['private_key']
        ssh_client = self.get_remote_client(self.floating['ip'],
                                            private_key=private_key,
                                            password='cubswin:)')

        def exec_cmd_and_verify_output():
            cmd = 'curl ' + md_url
            result = ssh_client.exec_command(cmd)
            if result:
                msg = ('Failed while verifying metadata on server. '
                       'Result of command "%s" is NOT "%s".'
                       % (cmd, self.floating['ip']))
                self.assertEqual(self.floating['ip'], result, msg)
                return 'Verification is successful!'

        if not test.call_until_true(exec_cmd_and_verify_output,
                                    CONF.compute.build_timeout,
                                    CONF.compute.build_interval):
            raise exceptions.TimeoutException('Timed out while waiting to '
                                              'verify metadata on server. '
                                              '%s is empty.' % md_url)

    def test_metadata(self):
        # Add rules to the security group
        rulesets = [
            dict(
                # ssh
                protocol='tcp',
                port_range_min=22,
                port_range_max=22,
            ),
            dict(
                # ping
                protocol='icmp',
            )
        ]
        server_name = data_utils.rand_name(self.__class__.__name__)
        server, self.floating = self.start_creation(rulesets, name=server_name)
        self.verify_metadata()
