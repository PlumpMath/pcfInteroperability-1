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


import netaddr
import six

from oslo_log import log as logging
from tempest.common.utils.linux import remote_client
from tempest import config
from tempest import exceptions
from tempest import test
from tempest_lib.common.utils import misc as misc_utils
from tempest_lib import exceptions as lib_exc

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class JumpboxIpsTest(base.BasePCFTest):

    def _ssh_to_server(self, server, private_key):
        ssh_login = CONF.pcf.jumpbox_ssh_user
        self.ssh_client = self.get_remote_client(server,
                                                 username=ssh_login,
                                                 private_key=private_key)
        return self.ssh_client

    def get_remote_client(self, server_or_ip, username=None, private_key=None,
                          log_console_of_servers=None):
        """Get a SSH client to a remote server

        @param server_or_ip a server object as returned by Tempest compute
            client or an IP address to connect to
        @param username name of the Linux account on the remote server
        @param private_key the SSH private key to use
        @param log_console_of_servers a list of server objects. Each server
            in the list will have its console printed in the logs in case the
            SSH connection failed to be established
        @return a RemoteClient object
        """
        if isinstance(server_or_ip, six.string_types):
            ip = server_or_ip
        else:
            addrs = server_or_ip['addresses'][CONF.compute.network_for_ssh]
            try:
                ip = (addr['addr'] for addr in addrs if
                      netaddr.valid_ipv4(addr['addr'])).next()
            except StopIteration:
                raise lib_exc.NotFound("No IPv4 addresses to use for SSH to "
                                       "remote server.")

        if username is None:
            username = CONF.scenario.ssh_user
        # Set this with 'keypair' or others to log in with keypair or
        # username/password.
        if CONF.validation.auth_method == 'keypair':
            password = "123"
            if private_key is None:
                private_key = self.keypair['private_key']
        else:
            password = CONF.compute.image_ssh_password
            private_key = None
        linux_client = remote_client.RemoteClient(ip, username,
                                                  pkey=private_key,
                                                  password=password)
        try:
            linux_client.validate_authentication()
        except Exception as e:
            message = ('Initializing SSH connection to %(ip)s failed. '
                       'Error: %(error)s' % {'ip': ip, 'error': e})
            caller = misc_utils.find_test_caller()
            if caller:
                message = '(%s) %s' % (caller, message)
            LOG.exception(message)
            # If we don't explicitly set for which servers we want to
            # log the console output then all the servers will be logged.
            # See the definition of _log_console_output()
            self._log_console_output(log_console_of_servers)
            raise

        return linux_client

    def test_connectivity_to_endpoints(self):

        server = CONF.pcf.jumpbox_server
        private_key = (open(CONF.pcf.jumpbox_private_key_path)).read()

        self._ssh_to_server(server, private_key)

        keystone_url = CONF.identity.uri
        cmd = 'curl ' + keystone_url

        def exec_cmd_and_verify_output():
            result = self.ssh_client.exec_command(cmd)
            if result:
                msg = ('Failed while verifying connectivity to keystone. '
                       'Result of command "%s" is "%s".' % (cmd, result))
                self.assertIn(keystone_url, result, msg)
                return 'Verification is successful!'

        if not test.call_until_true(exec_cmd_and_verify_output,
                                    CONF.compute.build_timeout,
                                    CONF.compute.build_interval):
            msg = ('Timed out while waiting to verify connectivity '
                   'to keystone. %s is empty.' % keystone_url)
            raise exceptions.TimeoutException(msg)

    def test_connectivity_to_internet(self):

        server = CONF.pcf.jumpbox_server
        private_key = (open(CONF.pcf.jumpbox_private_key_path)).read()

        self._ssh_to_server(server, private_key)
        ip_address = '8.8.8.8'
        cmd = 'ping ' + '-c1 ' + '-w1 ' + ip_address

        def exec_cmd_and_verify_output():

            result = self.ssh_client.exec_command(cmd)
            print(result)
            if result:
                msg = ('Failed while pinging. Result '
                       'of command "%s" is NOT "%s".' % (cmd, result))
                self.assertIn("1 received", result, msg)
                return 'Verification is successful!'
