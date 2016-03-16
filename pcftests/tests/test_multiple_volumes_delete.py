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


import time

from oslo_log import log as logging
from tempest.common.utils import data_utils
from tempest import config
from tempest_lib import exceptions as lib_exc

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class VolumesTest(base.BasePCFTest):
    """Here we test the Cinder functionality"""

    @classmethod
    def resource_setup(cls):
        """Setup resources."""
        super(VolumesTest, cls).resource_setup()
        cls.created_volumes = []

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(VolumesTest, cls).setup_clients()

    @classmethod
    def resource_cleanup(cls):
        """Cleanup at the end of the tests."""
        cls.clear_volumes()
        super(VolumesTest, cls).resource_cleanup()

    @classmethod
    def clear_volumes(cls):
        """Clear volumes at the end of tests."""
        LOG.debug('Clearing volumes: %s', ','.join(cls.created_volumes))
        for volume_id in cls.created_volumes:
            try:
                cls.volumes_ext_client.delete_volume(volume_id)
            except lib_exc.NotFound:
                # The volume may have already been deleted which is OK.
                pass
            except Exception:
                LOG.exception(
                    'Exception raised deleting volume %s' % volume_id)

    def test_multiple_volumes_delete(self):
        """
        Here we test the ability of Cinder to be capable
        of deleting multiple 20GB volumes within 300 seconds.
        """
        volume_number = CONF.pcf.volumes_number
        volume_size = 20
        volumes = self.created_volumes

        for i in range(volume_number):
            volume_name = data_utils.rand_name(self.__class__.__name__)
            volume = self.volume_client.create_volume(
                display_name=volume_name,
                size=volume_size)
            volume_id = volume['volume']['id']
            volumes.append(volume_id)
            self.volume_client.wait_for_volume_status(volume_id,
                                                      'available')

        start_time = time.time()
        for volume_id in volumes:
            self.volumes_ext_client.delete_volume(volume_id)
        for volume_id in volumes:
            self.volumes_ext_client.wait_for_resource_deletion(volume_id)
        check_time = time.time() - start_time
        self.assertTrue(check_time <= 300,
                        "The deletion of %s %s GB volumes took %s seconds"
                        % (volume_number, volume_size, check_time))
