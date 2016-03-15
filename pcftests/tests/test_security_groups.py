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


class SecurityGroupsTest(base.BasePCFTest):
    """Tests capability to allocate Floating IPs.."""

    @classmethod
    def setup_clients(cls):
        """Setup clients."""
        super(SecurityGroupsTest, cls).setup_clients()

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
    def clear_security_groups(cls):
        # Delete all security groups
        for sg in cls.security_groups:
            cls.sg_client.delete_security_group(sg['id'])
            cls.sg_client.wait_for_resource_deletion(sg['id'])

    def test_create_security_groups(self):
        """Here we test	capability to create and modify Security Groups"""

        # Creating Security Group
        name = data_utils.rand_name(self.__class__.__name__)
        description = data_utils.rand_name(self.__class__.__name__)
        sg = self.sg_client.create_security_group(
            name=name, description=description)['security_group']
        self.security_groups.append(sg)
        self.assertIn('id', sg)
        sg_id = sg['id']

        # Fetch all Security Groups and verify the list
        # has the created Security Group
        fetched_list = self.sg_client.list_security_groups()['security_groups']
        # Now check if the created Security Group is in fetched list
        missing_sgs = [sgr for sgr in self.security_groups
                       if sgr not in fetched_list]
        self.assertFalse(missing_sgs,
                         "Failed to find Security Group %s in fetched "
                         "list" % ', '.join(m_group['name']
                                            for m_group in missing_sgs))

        # Update security group name and description
        # Update the name and description
        sg_new_name = data_utils.rand_name('sg-new')
        sg_new_desc = data_utils.rand_name('description-new')
        self.sg_client.update_security_group(sg_id,
                                             name=sg_new_name,
                                             description=sg_new_desc)
        fetched_group = (self.sg_client.show_security_group(sg_id)
                         ['security_group'])
        self.assertEqual(sg_new_name, fetched_group['name'])
        self.assertEqual(sg_new_desc, fetched_group['description'])

        # Creating a Security Group to add rules to it
        # Adding rules to the created Security Group
        ruleset = dict(
            protocol='tcp',
            port_range_min=22,
            port_range_max=22,
            direction='ingress',
            tenant_id=self.tenant_id,
            security_group_id=sg_id)

        rule = self.sg_rules_client.create_security_group_rule(
            **ruleset)['security_group_rule']
        rule_id = rule['id']
        # Delete the Security Group rule at the end of this method
        self.addCleanup(
            self.sg_rules_client.delete_security_group_rule,
            rule_id)

        # Get rules of the created Security Group
        rules = self.sg_client.show_security_group(
            sg_id)['security_group']['rules']
        self.assertTrue(any([i for i in rules if i['id'] == rule_id]))
