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


import collections
import netaddr
import six
import time

from oslo_log import log as logging
from tempest.common import compute
from tempest.common.utils import data_utils
from tempest.common.utils.linux import remote_client
from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import misc as misc_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import network_resources
import tempest.test


CONF = config.CONF
LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


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
        cls.tenant_id = cls.manager.identity_client.tenant_id
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
        cls.floatingip_client = (
            cls.os.compute_floating_ips_client)
        cls.glance_client = cls.os.image_client_v2
        cls.keypairs_client = cls.os.keypairs_client
        cls.networks_client = cls.os.networks_client
        cls.routers_client = cls.os.routers_client
        cls.servers_client = cls.os.servers_client
        cls.sg_client = cls.os.compute_security_groups_client
        cls.sg_rules_client = cls.os.security_group_rules_client
        cls.subnets_client = cls.os.subnets_client
        cls.volumes_ext_client = cls.os.volumes_extensions_client
        cls.volume_client = cls.os.volumes_v2_client
        if CONF.volume_feature_enabled.api_v1:
            cls.volume_client = cls.os.volumes_client

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

    def wait_for(self, condition):
        """Repeatedly calls condition() until a timeout."""
        start_time = int(time.time())
        while True:
            try:
                condition()
            except Exception:
                pass
            else:
                return
            if int(time.time()) - start_time >= self.build_timeout:
                condition()
                return
            time.sleep(self.build_interval)

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

    def create_keypair(self):

        name = data_utils.rand_name(self.__class__.__name__)
        # We don't need to create a keypair by pubkey in scenario
        body = self.keypairs_client.create_keypair(name=name)
        self.addCleanup(self.keypairs_client.delete_keypair, name)
        return body['keypair']

    def create_security_group(self):
        """Create a security group without rules."""
        sg_name = data_utils.rand_name('secgroup')
        sg_desc = sg_name + " description"
        sg_dict = dict(name=sg_name,
                       description=sg_desc,
                       tenant_id=self.tenant_id)
        result = self.sg_client.create_security_group(**sg_dict)
        secgroup = network_resources.DeletableSecurityGroup(
            client=self.sg_client,
            **result['security_group']
        )
        self.addCleanup(self.delete_wrapper, secgroup.delete)
        return secgroup

    def create_secgroup_rule(self, secgroup_id, rulesets):
        """Create security group rule"""

        client = self.sg_rules_client
        rules = []
        for ruleset in rulesets:
            ruleset['tenant_id'] = self.tenant_id
            ruleset['security_group_id'] = secgroup_id
            for r_direction in ['ingress', 'egress']:
                ruleset['direction'] = r_direction
                try:
                    sg_rule = client.create_security_group_rule(**ruleset)
                    sg_rule = network_resources.DeletableSecurityGroupRule(
                        client=client,
                        **sg_rule['security_group_rule'])
                    self.addCleanup(self.delete_wrapper, sg_rule.delete)
                except lib_exc.Conflict as ex:
                    # if rule already exist - skip rule and continue
                    msg = 'Security group rule already exists'
                    if msg not in ex._error_string:
                        raise ex
                else:
                    self.assertEqual(r_direction, sg_rule.direction)
                    rules.append(sg_rule)
        return rules

    def create_networks(self):
        """Create a network with a subnet connected to a router."""

        # Create network
        name = data_utils.rand_name('network')
        result = self.networks_client.create_network(name=name,
                                                     tenant_id=self.tenant_id)
        network = network_resources.DeletableNetwork(
            networks_client=self.networks_client,
            routers_client=self.routers_client,
            **result['network'])
        self.addCleanup(self.delete_wrapper, network.delete)

        # Get or create router
        router_id = CONF.network.public_router_id
        network_id = CONF.network.public_network_id
        if router_id:
            result = self.routers_client.show_router(router_id)
            router = network_resources.AttributeDict(**result['router'])
        elif network_id:
            name = data_utils.rand_name('router')
            result = self.routers_client.create_router(
                name=name,
                admin_state_up=True,
                tenant_id=self.tenant_id)
            router = network_resources.DeletableRouter(
                routers_client=self.routers_client,
                **result['router'])
            self.addCleanup(self.delete_wrapper, router.delete)
            router.set_gateway(network_id)
        else:
            raise Exception("Neither of 'public_router_id' or "
                            "'public_network_id' has been defined.")

        # Create subnet
        def cidr_in_use(cidr, tenant_id):
            """Check cidr existence
            :returns: True if subnet with cidr already exist in tenant
                  False else
            """
            subnets_list = self.os_adm.subnets_client.list_subnets(
                tenant_id=tenant_id, cidr=cidr)
            return len(subnets_list['subnets']) != 0

        tenant_cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)
        num_bits = CONF.network.project_network_mask_bits

        result = None
        # Repeatedly attempt subnet creation with sequential cidr
        # blocks until an unallocated block is found.
        for subnet_cidr in tenant_cidr.subnet(num_bits):
            str_cidr = str(subnet_cidr)
            if cidr_in_use(str_cidr, tenant_id=network.tenant_id):
                continue
            subnet = dict(
                name=data_utils.rand_name('subnet'),
                network_id=network.id,
                tenant_id=network.tenant_id,
                cidr=str_cidr,
                ip_version=4
            )
            try:
                result = self.subnets_client.create_subnet(**subnet)
                break
            except lib_exc.Conflict as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        self.assertIsNotNone(result, 'Unable to allocate tenant network')
        subnet = network_resources.DeletableSubnet(
            subnets_client=self.subnets_client,
            routers_client=self.routers_client,
            **result['subnet'])
        self.addCleanup(self.delete_wrapper, subnet.delete)

        # Add subnet to router
        subnet.add_to_router(router.id)

        return network, subnet, router

    def get_remote_client(self, server_ip, private_key, password,
                          ssh_login=None,
                          log_console_of_servers=None):
        # Get a SSH client to a remote server
        if ssh_login is None:
            ssh_login = CONF.validation.image_ssh_user
        if isinstance(server_ip, six.string_types):
            ip = server_ip
        else:
            addrs = server_ip['addresses'][CONF.compute.network_for_ssh]
            try:
                ip = (addr['addr'] for addr in addrs if
                      netaddr.valid_ipv4(addr['addr'])).next()
            except StopIteration:
                raise lib_exc.NotFound("No IPv4 addresses to use for SSH to "
                                       "remote server.")

        linux_client = remote_client.RemoteClient(ip, ssh_login,
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

    def check_remote_connectivity(self, source, dest):
        """check ping server via source ssh connection

        :param source: RemoteClient: an ssh connection from which to ping
        :param dest: and IP to ping against
        :param should_succeed: boolean should ping succeed or not
        :param nic: specific network interface to ping from
        :returns: boolean -- should_succeed == ping
        :returns: ping is false if ping failed
        """
        should_succeed = True

        def ping_remote():
            try:
                source.ping_host(dest, nic=None)
            except lib_exc.SSHExecCommandFailed:
                LOG.warning('Failed to ping IP: %s via a ssh connection '
                            'from: %s.' % (dest, source.ssh_client.host))
                return not should_succeed
            return should_succeed

        return tempest.test.call_until_true(ping_remote,
                                            CONF.validation.ping_timeout, 1)

    def start_creation(self, rulesets, name=None):

        self.keypair = self.create_keypair()
        self.secgroup = self.create_security_group()
        self.create_secgroup_rule(self.secgroup['id'], rulesets)
        self.network, self.subnet, self.router = self.create_networks()

        if name is None:
            name = data_utils.rand_name('server')
        network = {'uuid': self.network.id}
        security_groups = [{'name': self.secgroup['name']}]
        self.md = {'meta1': 'data1', 'meta2': 'data2', 'metaN': 'dataN'}
        server = self.create_server(name=name,
                                    networks=[network],
                                    security_groups=security_groups,
                                    key_name=self.keypair['name'],
                                    metadata=self.md,
                                    wait_until='ACTIVE')
        self.addCleanup(waiters.wait_for_server_termination,
                        self.servers_client,
                        server['id'])

        self.addCleanup_with_wait(
            waiter_callable=waiters.wait_for_server_termination,
            thing_id=server['id'], thing_id_param='server_id',
            cleanup_callable=self.delete_wrapper,
            cleanup_args=[self.servers_client.delete_server, server['id']],
            waiter_client=self.servers_client)

        server_id = server['id']

        # Floating IP creation
        floating = self.floatingip_client.create_floating_ip()['floating_ip']
        floating_ip_id = floating['id']
        self.addCleanup(self.floatingip_client.delete_floating_ip,
                        floating_ip_id)
        floating_ip = floating['ip']
        self.floating_ip_tuple = Floating_IP_tuple(
            floating_ip, server)
        # Association of floating IP to fixed IP address
        self.floatingip_client.associate_floating_ip_to_server(
            floating_ip,
            server_id)

        return server, floating

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
