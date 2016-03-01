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


class BasePCFTest(tempest.test.BaseTestCase):
    """Base test case class for all PCF tests."""

    credentials = ['primary']

    @classmethod
    def setup_credentials(cls):
        """Setup credentials."""
        cls.set_network_resources()
        super(BasePCFTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        """Setup resources."""
        super(BasePCFTest, cls).resource_setup()
        cls.servers = []

    def setUp(self):
        super(BasePCFTest, self).setUp()
        self.keypairs = {}
        self.cleanup_waits = []
        self.addCleanup(self._wait_for_cleanups)

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(BasePCFTest, cls).setup_clients()
        cls.servers_client = cls.manager.servers_client
        cls.keypairs_client = cls.os.keypairs_client
        cls.compute_security_groups_client = (
            cls.os.compute_security_groups_client)
        cls.security_group_rules_client = (
            cls.os.security_group_rules_client)
        cls.compute_floating_ips_client = (
            cls.os.compute_floating_ips_client)

    @classmethod
    def resource_cleanup(cls):
        """Cleanup at the end of the tests."""
        cls.clear_servers()

    def delete_wrapper(self, delete_thing, *args, **kwargs):
        """Ignores NotFound exceptions for delete operations.

        @param delete_thing: delete method of a resource. method will be
            executed as delete_thing(*args, **kwargs)

        """
        try:
            # Tempest clients return dicts, so there is no common delete
            # method available. Using a callable instead
            delete_thing(*args, **kwargs)
        except lib_exc.NotFound:
            # If the resource is already missing, mission accomplished.
            pass

    def addCleanup_with_wait(self, waiter_callable, thing_id, thing_id_param,
                             cleanup_callable, cleanup_args=None,
                             cleanup_kwargs=None, waiter_client=None):
        """Adds wait for async resource deletion at the end of cleanups

        @param waiter_callable: callable to wait for the resource to delete
            with the following waiter_client if specified.
        @param thing_id: the id of the resource to be cleaned-up
        @param thing_id_param: the name of the id param in the waiter
        @param cleanup_callable: method to load pass to self.addCleanup with
            the following *cleanup_args, **cleanup_kwargs.
            usually a delete method.
        """
        if cleanup_args is None:
            cleanup_args = []
        if cleanup_kwargs is None:
            cleanup_kwargs = {}
        self.addCleanup(cleanup_callable, *cleanup_args, **cleanup_kwargs)
        wait_dict = {
            'waiter_callable': waiter_callable,
            thing_id_param: thing_id
        }
        if waiter_client:
            wait_dict['client'] = waiter_client
        self.cleanup_waits.append(wait_dict)

    def _wait_for_cleanups(self):
        # To handle async delete actions, a list of waits is added
        # which will be iterated over as the last step of clearing the
        # cleanup queue. That way all the delete calls are made up front
        # and the tests won't succeed unless the deletes are eventually
        # successful. This is the same basic approach used in the api tests to
        # limit cleanup execution time except here it is multi-resource,
        # because of the nature of the scenario tests.
        for wait in self.cleanup_waits:
            waiter_callable = wait.pop('waiter_callable')
            waiter_callable(**wait)

    def _log_console_output(self, servers=None):
        if not CONF.compute_feature_enabled.console_output:
            LOG.debug('Console output not supported, cannot log')
            return
        if not servers:
            servers = self.servers_client.list_servers()
            servers = servers['servers']
        for server in servers:
            console_output = self.servers_client.get_console_output(
                server['id'])['output']
            LOG.debug('Console output for %s\nbody=\n%s',
                      server['id'], console_output)

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
        tenant_network = cls.get_tenant_network()

        body, servers = compute.create_test_server(
            cls.os,
            validatable,
            validation_resources=cls.validation_resources,
            tenant_network=tenant_network,
            volume_backed=volume_backed,
            **kwargs)

        cls.servers.extend(servers)

        return body

    @classmethod
    def clear_servers(cls):
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

    def _create_loginable_secgroup_rule(self, secgroup_id=None):
        """Create loginable security group rule

        These rules are intended to permit inbound ssh and icmp
        traffic from all sources, so no group_id is provided.
        Setting a group_id would only permit traffic from ports
        belonging to the same security group.
        """

        client = self.compute_security_groups_client
        client_rules = self.security_group_rules_client
        if secgroup_id is None:
            sgs = client.list_security_groups()['security_groups']
            for sg in sgs:
                if sg['name'] == 'default':
                    secgroup_id = sg['id']

        # These rules are intended to permit inbound ssh and icmp
        # traffic from all sources, so no group_id is provided.
        # Setting a group_id would only permit traffic from ports
        # belonging to the same security group.
        rulesets = [
            {
                # ssh
                'ip_protocol': 'tcp',
                'from_port': 22,
                'to_port': 22,
                'cidr': '0.0.0.0/0',
            },
            {
                # ping
                'ip_protocol': 'icmp',
                'from_port': -1,
                'to_port': -1,
                'cidr': '0.0.0.0/0',
            }
        ]
        rules = list()
        for ruleset in rulesets:
            sg_rule = client_rules.create_security_group_rule(
                parent_group_id=secgroup_id, **ruleset)['security_group_rule']
            self.addCleanup(self.delete_wrapper,
                            client_rules.delete_security_group_rule,
                            sg_rule['id'])
            rules.append(sg_rule)
        return rules
