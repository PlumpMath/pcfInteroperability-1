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


from six import moves
import urllib2

from oslo_log import log as logging
from tempest.common.utils import data_utils
from tempest import config
from tempest_lib import exceptions as lib_exc

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ImagesTest(base.BasePCFTest):
    """Here we test the basic operations of images."""

    @classmethod
    def resource_setup(cls):
        """Setup resources."""
        super(ImagesTest, cls).resource_setup()
        cls.build_interval = CONF.compute.build_interval
        cls.build_timeout = CONF.compute.build_timeout
        cls.created_images = []

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(ImagesTest, cls).setup_clients()

    @classmethod
    def resource_cleanup(cls):
        """Cleanup at the end of the tests."""
        cls.clear_images()
        super(ImagesTest, cls).resource_cleanup()

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

    def test_image_create_run_from_volume(self):
        """Here we test these functionalities.

        Ability to upload custom images to Glance.
        Ability of Cinder to support raw format.
        """

        # Download and store image
        image_link = ('http://download.cirros-cloud.net/'
                      '0.3.1/cirros-0.3.1-x86_64-disk.img')
        # image_link = '/opt/stack/tempest/cirros-0.3.1-x86_64-disk.img'
        image_name = data_utils.rand_name('image')
        # Image objects returned by the v1 client have the image
        # data inside a dict that is keyed against 'image'.
        image = self.glance_client.create_image(name=image_name,
                                                container_format='bare',
                                                disk_format='raw',
                                                visibility='private')
        if 'image' in image:
            image = image['image']
        self.created_images.append(image['id'])
        self.assertIn('id', image)
        image_id = image.get('id')

        response = urllib2.urlopen(image_link, timeout=30)
        # response = open(image_link)
        file_content = response.read()
        image_file = moves.cStringIO(file_content)
        self.glance_client.store_image_file(image_id, image_file)

        # Trying to get image details
        body = self.glance_client.show_image(image_id)
        self.assertEqual(image_id, body['id'])
        self.assertIn('size', body)
        self.assertEqual(body['status'], 'active')

        # Creating volume from image
        volume_name = data_utils.rand_name(self.__class__.__name__)
        volume = self.volume_client.create_volume(
            display_name=volume_name,
            imageRef=image_id)
        self.volume_client.wait_for_volume_status(volume['volume']['id'],
                                                  'available')
        bd_map_v2 = [{
            'uuid': volume['volume']['id'],
            'source_type': 'volume',
            'destination_type': 'volume',
            'boot_index': 0,
            'delete_on_termination': True}]

        # Creating instance from volume
        server_name = data_utils.rand_name(self.__class__.__name__)
        server = self.create_server(
            name=server_name,
            flavor=CONF.compute.flavor_ref,
            block_device_mapping_v2=bd_map_v2,
            wait_until='ACTIVE')
        self.assertIn('id', server)

        # wait for console log
        self.wait_for(self._log_console_output)

    def test_instance_boot_from_image(self):
        """Here we test ability to	boot directly from image."""

        # Creating instance from volume
        server_name = data_utils.rand_name(self.__class__.__name__)
        server = self.create_server(
            name=server_name,
            flavor=CONF.compute.flavor_ref,
            image_id=CONF.compute.image_ref,
            wait_until='ACTIVE')
        self.assertIn('id', server)

        # wait for console log
        self.wait_for(self._log_console_output)
