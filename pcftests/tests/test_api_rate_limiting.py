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
from tempest.lib import exceptions as lib_exc

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ApiRateTest(base.BasePCFTest):

    credentials = ['primary', 'admin']

    @classmethod
    def setup_credentials(cls):
        """Setup credentials."""
        super(ApiRateTest, cls).setup_credentials()
        cls.tenant_id = cls.os.credentials.tenant_id

    @classmethod
    def resource_setup(cls):
        """Setup resources."""
        super(ApiRateTest, cls).resource_setup()
        cls.created_volumes = []
        cls.created_flavors = []

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(ApiRateTest, cls).setup_clients()

    @classmethod
    def resource_cleanup(cls):
        """Cleanup at the end of the tests."""
        cls.clear_volumes()
        super(ApiRateTest, cls).resource_cleanup()

    @classmethod
    def clear_volumes(cls):
        """Clear volumes at the end of tests."""
        LOG.debug('Clearing volumes: %s', ','.join(cls.created_volumes))
        for volume_id in cls.created_volumes:
            try:
                cls.volumes_ext_client.delete_volume(volume_id)
                cls.volumes_ext_client.wait_for_resource_deletion(volume_id)
            except lib_exc.NotFound:
                # The volume may have already been deleted which is OK.
                pass
            except Exception:
                LOG.exception(
                    'Exception raised deleting volume %s' % volume_id)

    def test_api_rate_limiting(self):
        vms = CONF.pcf.vms_volumes_number

        made_vms = 0
        try:
            for i in range(vms):
                server_name = data_utils.rand_name(self.__class__.__name__)
                self.create_server(
                    name=server_name,
                    image_id=CONF.compute.image_ref,
                    flavor=CONF.compute.flavor_ref)
                made_vms += 1
        except Exception:
            pass
        self.assertEqual(vms, made_vms,
                         message='Only %s servers was created' % made_vms)

        volume_size = 20
        try:
            for i in range(vms):
                volume_name = data_utils.rand_name(self.__class__.__name__)
                volume = self.volume_client.create_volume(
                    display_name=volume_name,
                    size=volume_size)
                volume_id = volume['volume']['id']
                self.created_volumes.append(volume_id)
        except Exception:
            pass
        for volume_id in self.created_volumes:
            self.volume_client.wait_for_volume_status(volume_id, 'available')
        self.assertEqual(vms, len(self.created_volumes),
                         message='Only %s volumes was created'
                                 % len(self.created_volumes))
        for volume_id in self.created_volumes:
            self.volumes_ext_client.delete_volume(volume_id)
        for server in self.servers:
            self.servers_client.delete_server(server['id'])
