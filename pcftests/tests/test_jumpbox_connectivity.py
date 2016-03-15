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
from tempest import config
from tempest import exceptions
from tempest import test

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class JumpboxConnectivityTest(base.BasePCFTest):

    @classmethod
    def skip_checks(cls):
        super(JumpboxConnectivityTest, cls).skip_checks()
        if (not CONF.pcf.jumpbox_server or
                not CONF.pcf.jumpbox_private_key_path or
                not CONF.pcf.jumpbox_ssh_password or
                not CONF.pcf.jumpbox_ssh_user):
            msg = ("Impossible to connect to jumpbox. "
                   "Jumpbox credentials aren't provided. "
                   "Check config file.")
            raise cls.skipException(msg)

    def setUp(self):
        super(JumpboxConnectivityTest, self).setUp()
        server = CONF.pcf.jumpbox_server
        private_key = (open(CONF.pcf.jumpbox_private_key_path)).read()
        ssh_login = CONF.pcf.jumpbox_ssh_user
        ssh_password = CONF.pcf.jumpbox_ssh_password
        self.ssh_client = self.get_remote_client(server, private_key,
                                                 ssh_password, ssh_login)

    def test_connectivity_to_endpoints(self):

        keystone_url = CONF.identity.uri
        cmd = 'curl ' + keystone_url

        def exec_cmd_and_verify_output():
            result = self.ssh_client.exec_command(cmd)
            if result:
                msg = ('Failed while verifying connectivity. '
                       'Result of command "%s" is "%s".' % (cmd, result))
                self.assertIn(keystone_url, result, msg)
                return 'Verification is successful!'

        if not test.call_until_true(exec_cmd_and_verify_output,
                                    CONF.compute.build_timeout,
                                    CONF.compute.build_interval):
            msg = ("Timed out while waiting to verify connectivity. "
                   "%s isn't responding." % keystone_url)
            raise exceptions.TimeoutException(msg)

    def test_connectivity_to_internet(self):

        ip_address = '8.8.8.8'

        msg = "Timed out waiting for %s to become reachable" % ip_address
        try:
            self.assertTrue(self.check_remote_connectivity
                            (self.ssh_client, ip_address), msg)
        except Exception:
            LOG.exception("Unable to access {dest} via ssh to "
                          "floating-ip {src}".format(dest=ip_address,
                                                     src=self.floating['ip']))
            raise
