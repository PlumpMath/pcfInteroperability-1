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


from oslo_log import log as logging
from tempest.common.utils import data_utils
from tempest import config

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class VmsIpsTest(base.BasePCFTest):
    """
    Tests capability of the VMs inside a Project
    to talk to each other via the floating IP.
    """
    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(VmsIpsTest, cls).setup_clients()

    @classmethod
    def setup_credentials(cls):
        # Floating IP actions might need a full network configuration
        super(VmsIpsTest, cls).setup_credentials()

    def test_connectivity_between_vms(self):
        """Test capability of the VMs inside a Project
        to talk to each other via the floating IP.
        """
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
        server, floating = self.start_creation(rulesets, name=server_name)
        new_name = data_utils.rand_name(self.__class__.__name__)
        new_server, new_floating = self.start_creation(rulesets,
                                                       name=new_name)

        ip_address = new_floating['ip']
        private_key = self.keypair['private_key']
        ssh_client = self.get_remote_client(floating['ip'],
                                            private_key=private_key,
                                            password='cubswin:)')

        msg = "Timed out waiting for %s to become reachable" % ip_address
        try:
            self.assertTrue(self.check_remote_connectivity
                            (ssh_client, ip_address), msg)
        except Exception:
            LOG.exception("Unable to access {dest} via ssh to "
                          "floating-ip {src}".format(dest=ip_address,
                                                     src=floating['ip']))
            raise
