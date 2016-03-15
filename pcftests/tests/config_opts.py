# Copyright 2012 OpenStack Foundation
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

from oslo_config import cfg


pcf_group = cfg.OptGroup(name='pcf',
                         title='PCF options')
PCFGroup = [
    cfg.BoolOpt('centos_stemcells_required',
                default=False,
                help="if CentOS stemcells are required"),
    cfg.IntOpt('vms_volumes_number',
               default=6,
               help="Number of VMs and volumes for testing deploing and "
                    "deleting up a consistent number "
                    "of VMs and volumes at once"),
    cfg.IntOpt('volumes_number',
               default=6,
               help="Number of VMs and volumes for testing 	capability of "
                    "deleting multiple 20GB volumes within 300 seconds"),
    cfg.StrOpt('jumpbox_server',
               default=None,
               help="IP address of jumpbox"),
    cfg.StrOpt('jumpbox_private_key_path',
               default=None,
               help="Private key path"),
    cfg.StrOpt('jumpbox_ssh_user',
               default=None,
               help="SSH user to jumpbox"),
    cfg.StrOpt('jumpbox_ssh_password',
               default=None,
               help="SSH password to jumpbox")
]
