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


import collections
import netaddr

from oslo_log import log as logging
from tempest.common import compute
from tempest.common.utils import data_utils
from tempest.common import waiters
from tempest import config
from tempest.services.network import resources as net_resources
from tempest_lib import exceptions as lib_exc

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class FloatingIpsTest(base.BasePCFTest):
    """Tests capability to allocate Floating IPs.."""

    credentials = ['primary', 'admin']

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
        cls.network_client = cls.os.network_client
        cls.networks_client = cls.os.networks_client
        cls.subnets_client = cls.os.subnets_client

    @classmethod
    def resource_setup(cls):
        """Setup resources"""
        super(FloatingIpsTest, cls).resource_setup()
        cls.floating_ip_id = None

    def create_server(self, name=None, image=None, flavor=None,
                      validatable=False, wait_until=None,
                      wait_on_delete=True, clients=None, **kwargs):
        """Wrapper utility that returns a test server.

        This wrapper utility calls the common create test server and
        returns a test server. The purpose of this wrapper is to minimize
        the impact on the code of the tests already using this
        function.
        """

        # Needed for the cross_tenant_traffic test:
        if clients is None:
            clients = self.manager

        vnic_type = CONF.network.port_vnic_type

        # If vnic_type is configured create port for
        # every network
        if vnic_type:
            ports = []
            networks = []
            create_port_body = {'binding:vnic_type': vnic_type,
                                'namestart': 'port-smoke'}
            if kwargs:
                # Convert security group names to security group ids
                # to pass to create_port
                if 'security_groups' in kwargs:
                    security_groups =\
                        clients.network_client.list_security_groups(
                        ).get('security_groups')
                    sec_dict = dict([(s['name'], s['id'])
                                    for s in security_groups])

                    sec_groups_names = [s['name'] for s in kwargs.pop(
                        'security_groups')]
                    security_groups_ids = [sec_dict[s]
                                           for s in sec_groups_names]

                    if security_groups_ids:
                        create_port_body[
                            'security_groups'] = security_groups_ids
                networks = kwargs.pop('networks')

            # If there are no networks passed to us we look up
            # for the tenant's private networks and create a port
            # if there is only one private network. The same behaviour
            # as we would expect when passing the call to the clients
            # with no networks
            if not networks:
                networks = clients.networks_client.list_networks(
                    filters={'router:external': False})
                self.assertEqual(1, len(networks),
                                 "There is more than one"
                                 " network for the tenant")
            for net in networks:
                net_id = net['uuid']
                port = self._create_port(network_id=net_id,
                                         client=clients.ports_client,
                                         **create_port_body)
                ports.append({'port': port.id})
            if ports:
                kwargs['networks'] = ports
            self.ports = ports

        tenant_network = self.get_tenant_network()

        body, servers = compute.create_test_server(
            clients,
            tenant_network=tenant_network,
            wait_until=wait_until,
            **kwargs)

        # TODO(jlanoux) Move wait_on_delete in compute.py
        if wait_on_delete:
            self.addCleanup(waiters.wait_for_server_termination,
                            clients.servers_client,
                            body['id'])

        self.addCleanup_with_wait(
            waiter_callable=waiters.wait_for_server_termination,
            thing_id=body['id'], thing_id_param='server_id',
            cleanup_callable=self.delete_wrapper,
            cleanup_args=[clients.servers_client.delete_server, body['id']],
            waiter_client=clients.servers_client)
        server = clients.servers_client.show_server(body['id'])['server']
        return server

    def _list_subnets(self, *args, **kwargs):
        """List subnets using admin creds """
        subnets_list = self.os_adm.subnets_client.list_subnets(
            *args, **kwargs)
        return subnets_list['subnets']

    def _create_server(self, name, network, port_id=None):
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        security_groups = [{'name': self.security_group['name']}]
        network = {'uuid': network.id}
        if port_id is not None:
            network['port'] = port_id

        server = self.create_server(
            name=name,
            networks=[network],
            key_name=keypair['name'],
            security_groups=security_groups,
            wait_until='ACTIVE')
        self.servers.append(server)
        return server

    def create_networks(self, client=None, networks_client=None,
                        subnets_client=None, tenant_id=None,
                        dns_nameservers=None):
        """Create a network with a subnet connected to a router.

        The baremetal driver is a special case since all nodes are
        on the same shared network.

        :param client: network client to create resources with.
        :param tenant_id: id of tenant to create resources in.
        :param dns_nameservers: list of dns servers to send to subnet.
        :returns: network, subnet, router
        """

        network = self._create_network(
            client=client, networks_client=networks_client,
            tenant_id=tenant_id)
        router = self._get_router(client=client, tenant_id=tenant_id)

        subnet_kwargs = dict(network=network, client=client,
                             subnets_client=subnets_client)
        # use explicit check because empty list is a valid option
        if dns_nameservers is not None:
            subnet_kwargs['dns_nameservers'] = dns_nameservers
        subnet = self._create_subnet(**subnet_kwargs)
        subnet.add_to_router(router.id)

        return network, subnet, router

    def _get_router(self, client=None, tenant_id=None):
        """Retrieve a router for the given tenant id.

        If a public router has been configured, it will be returned.

        If a public router has not been configured, but a public
        network has, a tenant router will be created and returned that
        routes traffic to the public network.
        """
        if not client:
            client = self.network_client
        if not tenant_id:
            tenant_id = client.tenant_id
        router_id = CONF.network.public_router_id
        network_id = CONF.network.public_network_id
        if router_id:
            body = client.show_router(router_id)
            return net_resources.AttributeDict(**body['router'])
        elif network_id:
            router = self._create_router(client, tenant_id)
            router.set_gateway(network_id)
            return router
        else:
            raise Exception("Neither of 'public_router_id' or "
                            "'public_network_id' has been defined.")

    def _create_subnet(self, network, client=None, subnets_client=None,
                       namestart='subnet-smoke', **kwargs):
        """Create a subnet for the given network

        within the cidr block configured for tenant networks.
        """
        if not client:
            client = self.network_client
        if not subnets_client:
            subnets_client = self.subnets_client

        def cidr_in_use(cidr, tenant_id):
            """Check cidr existence

            :returns: True if subnet with cidr already exist in tenant
                  False else
            """
            cidr_in_use = self._list_subnets(tenant_id=tenant_id, cidr=cidr)
            return len(cidr_in_use) != 0

        ip_version = kwargs.pop('ip_version', 4)

        if ip_version == 6:
            tenant_cidr = netaddr.IPNetwork(
                CONF.network.tenant_network_v6_cidr)
            num_bits = CONF.network.tenant_network_v6_mask_bits
        else:
            tenant_cidr = netaddr.IPNetwork(CONF.network.tenant_network_cidr)
            num_bits = CONF.network.tenant_network_mask_bits

        result = None
        str_cidr = None
        # Repeatedly attempt subnet creation with sequential cidr
        # blocks until an unallocated block is found.
        for subnet_cidr in tenant_cidr.subnet(num_bits):
            str_cidr = str(subnet_cidr)
            if cidr_in_use(str_cidr, tenant_id=network.tenant_id):
                continue

            subnet = dict(
                name=data_utils.rand_name(namestart),
                network_id=network.id,
                tenant_id=network.tenant_id,
                cidr=str_cidr,
                ip_version=ip_version,
                **kwargs
            )
            try:
                result = subnets_client.create_subnet(**subnet)
                break
            except lib_exc.Conflict as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        self.assertIsNotNone(result, 'Unable to allocate tenant network')
        subnet = net_resources.DeletableSubnet(
            network_client=client, subnets_client=subnets_client,
            **result['subnet'])
        self.addCleanup(self.delete_wrapper, subnet.delete)
        return subnet

    def _create_network(self, client=None, networks_client=None,
                        tenant_id=None, namestart='network-smoke-'):
        if not client:
            client = self.network_client
        if not networks_client:
            networks_client = self.networks_client
        if not tenant_id:
            tenant_id = client.tenant_id
        name = data_utils.rand_name(namestart)
        result = networks_client.create_network(name=name, tenant_id=tenant_id)
        network = net_resources.DeletableNetwork(
            networks_client=networks_client, **result['network'])
        self.addCleanup(self.delete_wrapper, network.delete)
        return network

    def _create_router(self, client=None, tenant_id=None,
                       namestart='router-smoke'):
        if not client:
            client = self.network_client
        if not tenant_id:
            tenant_id = client.tenant_id
        name = data_utils.rand_name(namestart)
        result = client.create_router(name=name,
                                      admin_state_up=True,
                                      tenant_id=tenant_id)
        router = net_resources.DeletableRouter(client=client,
                                               **result['router'])
        self.addCleanup(self.delete_wrapper, router.delete)
        return router

    def create_empty_security_group(self, client=None, tenant_id=None,
                                    namestart='secgroup-tempest'):
        """Create a security group without rules.

        Default rules will be created:
         - IPv4 egress to any
         - IPv6 egress to any

        :param tenant_id: secgroup will be created in this tenant
        :returns: DeletableSecurityGroup -- containing the secgroup created
        """
        client = self.network_client
        if not tenant_id:
            tenant_id = client.tenant_id
        sg_name = data_utils.rand_name(namestart)
        sg_desc = sg_name + " description"
        sg_dict = dict(name=sg_name,
                       description=sg_desc)
        sg_dict['tenant_id'] = tenant_id
        result = client.create_security_group(**sg_dict)
        secgroup = net_resources.DeletableSecurityGroup(
            client=client,
            **result['security_group']
        )
        self.addCleanup(self.delete_wrapper, secgroup.delete)
        return secgroup

    def _create_security_group_rule(self, secgroup=None, client=None,
                                    tenant_id=None, **kwargs):
        """Create a rule from a dictionary of rule parameters.

        Create a rule in a secgroup. if secgroup not defined will search for
        default secgroup in tenant_id.

        :param secgroup: type DeletableSecurityGroup.
        :param tenant_id: if secgroup not passed -- the tenant in which to
            search for default secgroup
        :param kwargs: a dictionary containing rule parameters:
            for example, to allow incoming ssh:
            rule = {
                    direction: 'ingress'
                    protocol:'tcp',
                    port_range_min: 22,
                    port_range_max: 22
                    }
        """
        if client is None:
            client = self.network_client
        if not tenant_id:
            tenant_id = client.tenant_id
        if secgroup is None:
            secgroup = self._default_security_group(client=client,
                                                    tenant_id=tenant_id)

        ruleset = dict(security_group_id=secgroup.id,
                       tenant_id=secgroup.tenant_id)
        ruleset.update(kwargs)

        sg_rule = client.create_security_group_rule(**ruleset)
        sg_rule = net_resources.DeletableSecurityGroupRule(
            client=client,
            **sg_rule['security_group_rule']
        )
        self.addCleanup(self.delete_wrapper, sg_rule.delete)

        return sg_rule

    def _create_loginable_secgroup_rule(self, client=None, secgroup=None):
        """Create loginable security group rule

        These rules are intended to permit inbound ssh and icmp
        traffic from all sources, so no group_id is provided.
        Setting a group_id would only permit traffic from ports
        belonging to the same security group.
        """

        if client is None:
            client = self.network_client
        rules = []
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
            ),
            dict(
                # ipv6-icmp for ping6
                protocol='icmp',
                ethertype='IPv6',
            )
        ]
        for ruleset in rulesets:
            for r_direction in ['ingress', 'egress']:
                ruleset['direction'] = r_direction
                try:
                    sg_rule = self._create_security_group_rule(
                        client=client, secgroup=secgroup, **ruleset)
                except lib_exc.Conflict as ex:
                    # if rule already exist - skip rule and continue
                    msg = 'Security group rule already exists'
                    if msg not in ex._error_string:
                        raise ex
                else:
                    self.assertEqual(r_direction, sg_rule.direction)
                    rules.append(sg_rule)

        return rules

    def create_keypair(self, client=None):
        if not client:
            client = self.keypairs_client
        name = data_utils.rand_name(self.__class__.__name__)
        # We don't need to create a keypair by pubkey in scenario
        body = client.create_keypair(name=name)
        self.addCleanup(client.delete_keypair, name)
        return body['keypair']

    def create_security_group(self, client=None, tenant_id=None,
                              namestart='secgroup'):
        if client is None:
            client = self.network_client
        if tenant_id is None:
            tenant_id = client.tenant_id
        secgroup = self.create_empty_security_group(namestart=namestart,
                                                    client=client,
                                                    tenant_id=tenant_id)

        # Add rules to the security group
        self._create_loginable_secgroup_rule(client=client,
                                             secgroup=secgroup)
        return secgroup

    def test_allocate_floating_ip(self):
        # Capability to allocate Floating IPs.
        # Allocation of a new floating IP to a project
        floating_ip = self.client.create_floating_ip()['floating_ip']
        floating_ip_id_allocated = floating_ip['id']
        self.addCleanup(self.client.delete_floating_ip,
                        floating_ip_id_allocated)
        floating_ip_details = self.client.show_floating_ip(
            floating_ip_id_allocated)['floating_ip']
        # Checking if the details of allocated IP is in list of floating IP
        floating_ip = self.client.list_floating_ips()['floating_ips']
        self.assertIn(floating_ip_details, floating_ip)

    def test_associate_disassociate_floating_ip(self):
        # Associate and disassociate the provided floating IP
        # to a specific server should be successful

        self.security_group = (
            self.create_security_group(tenant_id=self.tenant_id))

        self.network, self.subnet, self.router = self.create_networks()

        name = data_utils.rand_name('server')
        server = self._create_server(name, self.network)
        print(server)
        server_id = server.get('id')

        # Floating IP creation
        floating_ip_body = self.client.create_floating_ip()['floating_ip']
        self.floating_ip_id = floating_ip_body['id']
        floating_ip = floating_ip_body['ip']
        print(floating_ip)

        # Association of floating IP to fixed IP address
        self.client.associate_floating_ip_to_server(
            floating_ip,
            server_id)
        print (server)

        # Check instance_id in the floating_ip body
        body = (self.client.show_floating_ip(self.floating_ip_id)
                ['floating_ip'])
        self.assertEqual(server_id, body['instance_id'])

        # Disassociation of floating IP that was associated in this method
        self.client.disassociate_floating_ip_from_server(
            floating_ip,
            server_id)
