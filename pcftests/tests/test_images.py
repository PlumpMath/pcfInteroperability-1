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
from tempest.common.utils import data_utils
from tempest import config
from tempest_lib import exceptions as lib_exc

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class BasicOperationsImagesTest(base.BaseServerTest):
    """Here we test the basic operations of images."""

#    disk_config = 'AUTO'
#    credentials = ['primary']

    @classmethod
    def setup_credentials(cls):
        """Setup credentials."""
        super(BasicOperationsImagesTest, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        """Setup resources."""
        super(BasicOperationsImagesTest, cls).resource_setup()
        cls.build_interval = CONF.compute.build_interval
        cls.build_timeout = CONF.compute.build_timeout
        cls.created_images = []

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(BasicOperationsImagesTest, cls).setup_clients()
        cls.glance_client = cls.os.image_client_v2

    @classmethod
    def resource_cleanup(cls):
        """Cleanup at the end of the tests."""
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
