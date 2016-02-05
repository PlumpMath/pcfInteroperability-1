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

from pcftests.tests import base


class QuotasTest(base.BaseServerTest):
    """Tests Quotas."""

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(QuotasTest, cls).setup_clients()
        cls.client = cls.os.quotas_client

    @classmethod
    def resource_setup(cls):
        """Setup resources"""
        super(QuotasTest, cls).resource_setup()
        cls.tenant_id = cls.client.tenant_id

    def test_quotas(self):
        """Verify that quotas are available for the user/tenant."""
        cores = 32
        instances = 22
        ram = 64000

        quotas = self.client.show_quota_set(self.tenant_id)['quota_set']
        self.assertGreater(quotas['cores'], cores)
        self.assertGreater(quotas['instances'], instances)
        self.assertGreater(quotas['ram'], ram)
