# Copyright 2013 OpenStack Foundation
# Copyright 2013 IBM Corp
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
#    under the License.from oslo_log import log as logging

from oslo_log import log as logging
from tempest.common import compute
from tempest.common import waiters
from tempest import config
import tempest.test
from tempest_lib import exceptions as lib_exc

CONF = config.CONF
LOG = logging.getLogger(__name__)


class BaseServerTest(tempest.test.BaseTestCase):
    """Base test case class for all PCF tests."""

    disk_config = 'AUTO'
    credentials = ['primary', 'admin']

    @classmethod
    def setup_credentials(cls):
        """Setup credentials."""
        cls.set_network_resources()
        super(BaseServerTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        """Setup resources."""
        super(BaseServerTest, cls).resource_setup()
        cls.servers = []

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(BaseServerTest, cls).setup_clients()
        cls.servers_client = cls.manager.servers_client

    @classmethod
    def resource_cleanup(cls):
        """Cleanup at the end of the tests."""
        cls.clear_servers()

    @classmethod
    def create_server(cls, validatable=False, volume_backed=False,
                      **kwargs):
        """Wrapper utility that returns a test server.

        This wrapper utility calls the common create test server and
        returns a test server. The purpose of this wrapper is to minimize
        the impact on the code of the tests already using this
        function.

        :param validatable: Whether the server will be pingable or sshable.
        :param volume_backed: Whether the instance is volume backed or not.
        """
        body, servers = compute.create_test_server(
            cls.os,
            validatable,
            validation_resources=cls.validation_resources,
            volume_backed=volume_backed,
            **kwargs)

        cls.servers.extend(servers)

        return body

    @classmethod
    def clear_servers(cls):
        """Clear servers at the end of tests."""
        LOG.debug('Clearing servers: %s', ','.join(
            server['id'] for server in cls.servers))
        for server in cls.servers:
            try:
                cls.servers_client.delete_server(server['id'])
            except lib_exc.NotFound:
                # Something else already cleaned up the server, nothing to be
                # worried about
                pass
            except Exception:
                LOG.exception('Deleting server %s failed' % server['id'])

        for server in cls.servers:
            try:
                waiters.wait_for_server_termination(cls.servers_client,
                                                    server['id'])
            except Exception:
                LOG.exception('Waiting for deletion of server %s failed'
                              % server['id'])
