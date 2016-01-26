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
#    under the License.

from oslo_log import log as logging
from tempest.common.utils import data_utils
from tempest import config
from tempest_lib import exceptions as lib_exc

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class BasicOperationsFlavorsTest(base.BaseServerTest):
    """Here we test the basic operations of images."""

#    disk_config = 'AUTO'
#    credentials = ['primary', 'admin']

    @classmethod
    def setup_credentials(cls):
        """Setup credentials."""
        super(BasicOperationsFlavorsTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        """Setup resources."""
        super(BasicOperationsFlavorsTest, cls).resource_setup()
        cls.created_flavors = []

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(BasicOperationsFlavorsTest, cls).setup_clients()
        cls.flavor_client = cls.os_adm.flavors_client

    @classmethod
    def resource_cleanup(cls):
        """Cleanup at the end of the tests."""
        cls.clear_flavors()

    @classmethod
    def create_flavor(cls, **kwargs):
        """Wrapper that returns a test image."""
        flavor_name = data_utils.rand_name('flavor')
        flavor_id = data_utils.rand_int_id(start=1000)

        if 'name' in kwargs:
            flavor_name = kwargs.pop('name')

        ram = kwargs.pop('ram')
        vcpus = kwargs.pop('vcpus')
        disk = kwargs.pop('disk')

        flavor = (cls.flavor_client.create_flavor
                  (name=flavor_name,
                   ram=ram,
                   vcpus=vcpus,
                   disk=disk,
                   id=flavor_id))['flavor']

        # Image objects returned by the v1 client have the image
        # data inside a dict that is keyed against 'image'.
        if 'flavor' in flavor:
            flavor = flavor['flavor']
        cls.created_flavors.append(flavor['id'])

        return flavor['id']

    @classmethod
    def clear_flavors(cls):
        """Clear flavors at the end of tests."""
        LOG.debug('Clearing flavors: %s', ','.join(cls.created_flavors))
        for flavor_id in cls.created_flavors:
            try:
                cls.flavor_client.delete_flavor(flavor_id)
            except lib_exc.NotFound:
                # The image may have already been deleted which is OK.
                pass
            except Exception:
                LOG.exception(
                    'Exception raised deleting flavor %s' % flavor_id)

    def test_flavor_create(self):
        """Here we test these functionalities.

        Ability to create or modify Flavors.
        """
        flavor_name = data_utils.rand_name('flavor')

        ram = 64
        vcpus = 1
        disk = 0

        # Create a flavor without extra specs
        flavor_id = self.create_flavor(
            name=flavor_name,
            ram=ram,
            vcpus=vcpus,
            disk=disk)

        server_name = data_utils.rand_name('server')
        self.create_server(
            name=server_name,
            image_id=CONF.compute.image_ref,
            flavor=flavor_id,
            wait_until='ACTIVE')
