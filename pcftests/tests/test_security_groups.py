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

from tempest.common.utils import data_utils

from pcftests.tests import base


class SecurityGroupsTest(base.BaseServerTest):
    """Tests capability to allocate Floating IPs.."""

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(SecurityGroupsTest, cls).setup_clients()
        cls.client = cls.os.compute_security_groups_client

    @classmethod
    def resource_setup(cls):
        """Setup resources"""
        super(SecurityGroupsTest, cls).resource_setup()
        cls.security_groups = []

    @classmethod
    def resource_cleanup(cls):
        """Cleanup at the end of the tests."""
        cls.clear_security_groups()

    @classmethod
    def create_security_group(cls, name=None, description=None):
        if name is None:
            name = data_utils.rand_name(cls.__name__ + "-securitygroup")
        if description is None:
            description = data_utils.rand_name('description')
        body = cls.client.create_security_group(
            name=name, description=description)['security_group']
        cls.security_groups.append(body)

        return body

    @classmethod
    def clear_security_groups(cls):
        # Delete all security groups
        for sg in cls.security_groups:
            cls.client.delete_security_group(sg['id'])
            cls.client.wait_for_resource_deletion(sg['id'])

    def test_create_security_groups(self):
        # Should return the list of Security Groups
        # Create 3 Security Groups
        security_group_list = []
        for i in range(3):
            body = self.create_security_group()
            security_group_list.append(body)
        # Fetch all Security Groups and verify the list
        # has all created Security Groups
        fetched_list = self.client.list_security_groups()['security_groups']
        # Now check if all the created Security Groups are in fetched list
        missing_sgs = \
            [sg for sg in security_group_list if sg not in fetched_list]
        self.assertFalse(missing_sgs,
                         "Failed to find Security Group %s in fetched "
                         "list" % ', '.join(m_group['name']
                                            for m_group in missing_sgs))

    def test_update_security_groups(self):
        # Update security group name and description
        # Create a security group
        sg = self.create_security_group()
        self.assertIn('id', sg)
        sg_id = sg['id']
        # Update the name and description
        sg_new_name = data_utils.rand_name('sg-new')
        sg_new_desc = data_utils.rand_name('description-new')
        self.client.update_security_group(sg_id,
                                          name=sg_new_name,
                                          description=sg_new_desc)
        # get the security group
        fetched_group = (self.client.show_security_group(sg_id)
                         ['security_group'])
        self.assertEqual(sg_new_name, fetched_group['name'])
        self.assertEqual(sg_new_desc, fetched_group['description'])
