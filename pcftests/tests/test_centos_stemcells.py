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
from tempest import config

from pcftests.tests import base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class CentosFlavorsTest(base.BasePCFTest):

    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        cls.flavor_client = cls.os_adm.flavors_client
        cls.quotas_client = cls.os_adm.volume_quotas_v2_client

    def test_flavors_for_centos(self):

        if not CONF.pcf.centos_stemcells_required:
            self.skipTest("CentOS stemcells requirment isn't configured.")

        centos_flavor = False
        flavors = self.flavor_client.list_flavors()['flavors']
        for flavor in flavors:
            flavor_ref = flavor['id']
            flavor = self.flavor_client.show_flavor(flavor_ref)['flavor']
            disk = flavor['disk']
            if disk > 30:
                centos_flavor = True
                break
        msg = 'There are no flavors with at least 30 GB of ephemeral disk'
        self.assertTrue(centos_flavor, msg)
