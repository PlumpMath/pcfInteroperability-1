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

# import urllib2
import time

from oslo_log import log as logging
from six import moves
from tempest.common import compute
from tempest.common.utils import data_utils
from tempest.common import waiters
from tempest import config
import tempest.test
from tempest_lib import exceptions as lib_exc

CONF = config.CONF
LOG = logging.getLogger(__name__)


class BasicOperationsImagesTest(tempest.test.BaseTestCase):
    """Here we test the basic operations of images."""

    disk_config = 'AUTO'
    credentials = ['primary', 'admin']

    @classmethod
    def setup_credentials(cls):
        """Setup credentials."""
        cls.set_network_resources()
        super(BasicOperationsImagesTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        """Setup resources."""
        super(BasicOperationsImagesTest, cls).resource_setup()
        cls.build_interval = CONF.compute.build_interval
        cls.build_timeout = CONF.compute.build_timeout
        cls.created_images = []
        cls.created_flavors = []
        cls.servers = []

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(BasicOperationsImagesTest, cls).setup_clients()
        cls.glance_client = cls.os.image_client_v2
        cls.flavor_client = cls.os_adm.flavors_client
        cls.servers_client = cls.manager.servers_client

    @classmethod
    def resource_cleanup(cls):
        """Cleanup at the end of the tests."""
        cls.clear_servers()
        cls.clear_flavors()
        cls.clear_images()

    def _get_output(self):
        output = self.servers_client.get_console_output(
            self.server_id, length=10)['output']
        self.assertTrue(output, "Console output was empty.")
        lines = len(output.split('\n'))
        self.assertEqual(lines, 10)

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

    @classmethod
    def create_image(cls, **kwargs):
        """Wrapper that returns a test image."""
        name = data_utils.rand_name(cls.__name__ + "-instance")

        if 'name' in kwargs:
            name = kwargs.pop('name')

        container_format = kwargs.pop('container_format')
        disk_format = kwargs.pop('disk_format')

        image = cls.glance_client.create_image(name, container_format,
                                               disk_format, **kwargs)
        # Image objects returned by the v1 client have the image
        # data inside a dict that is keyed against 'image'.
        if 'image' in image:
            image = image['image']
        cls.created_images.append(image['id'])
        return image

    @classmethod
    def clear_images(cls):
        """Clear images at the end of tests."""
        LOG.debug('Clearing images: %s', ','.join(cls.created_images))
        for image_id in cls.created_images:
            try:
                cls.glance_client.delete_image(image_id)
            except lib_exc.NotFound:
                # The image may have already been deleted which is OK.
                pass
            except Exception:
                LOG.exception('Exception raised deleting image %s' % image_id)

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

    def test_image_create(self):
        """Here we test these functionalities.

        Ability to upload custom images to Glance.
        """
        # image_link =
        #   'http://download.cirros-cloud.net/0.3.1/cirros-0.3.1-x86_64-disk.img'
        image_link = '/opt/stack/tempest/cirros-0.3.1-x86_64-disk.img'

        image_name = data_utils.rand_name('image')
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 visibility='private')
        self.assertIn('id', body)
        image_id = body.get('id')

        # response = urllib2.urlopen(image_link, timeout=30)
        response = open(image_link)
        file_content = response.read()
        image_file = moves.cStringIO(file_content)
        self.glance_client.store_image_file(image_id, image_file)

        # Now try to get image details
        body = self.glance_client.show_image(image_id)
        self.assertEqual(image_id, body['id'])
        self.assertIn('size', body)
        self.assertEqual(body['status'], 'active')

        server_name = data_utils.rand_name('server')
        server = self.create_server(
            name=server_name,
            image_id=image_id,
            flavor=CONF.compute.flavor_ref,
            wait_until='ACTIVE')

        self.assertIn('id', server)
        self.server_id = server.get('id')

        # wait for console log
        self.wait_for(self._get_output)

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
