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
import netaddr
from oslo_log import log as logging
from oslo_utils import excutils

from neutron._i18n import _LE, _LW
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
#from neutron.common import constants
from neutron.agent.l3 import fip_rule_priority_allocator as frpa
from neutron.agent.l3 import link_local_allocator as lla
from neutron.agent.linux import iptables_manager
from neutron.common import utils as common_utils
from neutron.ipam import utils as ipam_utils


LOG = logging.getLogger(__name__)
SNAT_NS_PREFIX = 'snat-'

EXT_DEV_PREFIX = namespaces.EXTERNAL_DEV_PREFIX
SNAT_2_ROUTER_DEV_PREFIX = 'snat2r-'
ROUTER_2_SNAT_DEV_PREFIX = namespaces.ROUTER_2_SNAT_DEV_PREFIX
# Route Table index for FIPs
SNAT_RT_TBL = 18
SNAT_LL_SUBNET = '169.254.128.128/31'
ROUTER_2_SNAT_IP_ADDR = '169.254.128.128'
SNAT_2_ROUTER_IP_ADDR = '169.254.128.129'
SNAT_PREFIXLEN = 31
# Rule priority 
SNAT_PR_START = 167772100

class LocalSnatNamespace(namespaces.Namespace):

    def __init__(self, router_id, agent_conf, driver, use_ipv6):
        self.router_id = router_id
        self.name = self.get_snat_ns_name(router_id)
        super(LocalSnatNamespace, self).__init__(
            self.name, agent_conf, driver, use_ipv6)
        
        #self.agent_gateway_port = None
        self._rule_priority = frpa.FipPriority(str(SNAT_PR_START))
        
        #self._iptables_manager = iptables_manager.IptablesManager(
        #    namespace=self.name,
        #    use_ipv6=self.use_ipv6)
        # SNAT namespace need a single vpair for all VM's on host
        # This is unlike FIPs subnets generated for every VM
        subnet = netaddr.IPNetwork(SNAT_LL_SUBNET)
        self.vpair = lla.LinkLocalAddressPair(subnet)
     
     
    
    def get_r2snat_interface(self, router_id):
        mac = None
        ip_wrapper = ip_lib.IPWrapper(namespace=self.name)
        for d in ip_wrapper.get_devices(exclude_loopback=True):
            if d.name.startswith(ROUTER_2_SNAT_DEV_PREFIX):
                mac = d.link.address
                break
        res = {"id": self.get_rtr_ext_device_name(router_id),
               "mac_address": mac,
               "fixed_ips": [{'subnet_id': '0000-0000',
                              'ip_address': ROUTER_2_SNAT_IP_ADDR}],
               }
        return res

    def get_snat2r_interface(self, router_id):
        mac = None
        ip_wrapper = ip_lib.IPWrapper(namespace=self.name)
        for d in ip_wrapper.get_devices(exclude_loopback=True):
            if d.name.startswith(SNAT_2_ROUTER_DEV_PREFIX):
                mac = d.link.address
                break
        res = {"id": self.get_int_device_name(router_id),
               "mac_address": mac,
               "fixed_ips": [{'subnet_id': '0000-0000',
                              'ip_address': SNAT_2_ROUTER_IP_ADDR}],
               }
        return res


    @classmethod
    def get_snat_ns_name(cls, router_id):
        return namespaces.build_ns_name(SNAT_NS_PREFIX, router_id)
    
    def get_ext_device_name(self, port_id):
        return (EXT_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_int_device_name(self, router_id):
        return (SNAT_2_ROUTER_DEV_PREFIX + router_id)[:self.driver.DEV_NAME_LEN]

    def get_rtr_ext_device_name(self, router_id):
        return (ROUTER_2_SNAT_DEV_PREFIX + router_id)[:self.driver.DEV_NAME_LEN]



    def delete(self):
        
        LOG.warning("delete")
        self.destroyed = True
        ip_wrapper = ip_lib.IPWrapper(namespace=self.name)
        for d in ip_wrapper.get_devices(exclude_loopback=True):
            if d.name.startswith(SNAT_2_ROUTER_DEV_PREFIX):
                # update local ARP table
                #self._update_snat_arp_entry(d, 'delete')
                # internal link between IRs and FIP NS
                ip_wrapper.del_veth(d.name)
 
        #self.agent_gateway_port = None

        # TODO(mrsmith): add LOG warn if fip count != 0
        LOG.warning('DVR: destroy LocalSnat namespace: %s', self.name)
        super(LocalSnatNamespace, self).delete()
    


    def _add_cidr_to_device(self, device, ip_cidr):
        if not device.addr.list(to=ip_cidr):
            device.addr.add(ip_cidr, add_broadcast=False)

    def create_rtr_2_snat_link(self, ri):
        """Create interface between router and Local Snat namespace."""
        LOG.warning("Create SNAT link interfaces for router %s", ri.router_id)
        rtr_2_snat_name = self.get_rtr_ext_device_name(ri.router_id)
        snat_2_rtr_name = self.get_int_device_name(ri.router_id)
        snat_ns_name = self.name

        # add link local IP to interface
        #if ri.rtr_fip_subnet is None:
        #    ri.rtr_fip_subnet = self.local_subnets.allocate(ri.router_id)
        rtr_2_snat, snat_2_rtr = self.vpair.get_pair()
        rtr_2_snat_dev = ip_lib.IPDevice(rtr_2_snat_name, namespace=ri.ns_name)
        snat_2_rtr_dev = ip_lib.IPDevice(snat_2_rtr_name, namespace=snat_ns_name)

        if not rtr_2_snat_dev.exists():
            ip_wrapper = ip_lib.IPWrapper(namespace=ri.ns_name)
            rtr_2_snat_dev, snat_2_rtr_dev = ip_wrapper.add_veth(rtr_2_snat_name,
                                                               snat_2_rtr_name,
                                                               snat_ns_name)
            mtu = (self.agent_conf.network_device_mtu or
                   ri.get_ex_gw_port().get('mtu'))
            if mtu:
                rtr_2_snat_dev.link.set_mtu(mtu)
                snat_2_rtr_dev.link.set_mtu(mtu)
            rtr_2_snat_dev.link.set_up()
            snat_2_rtr_dev.link.set_up()

        self._add_cidr_to_device(rtr_2_snat_dev, str(rtr_2_snat))
        self._add_cidr_to_device(snat_2_rtr_dev, str(snat_2_rtr))
           
        # add default route for the link local interface
        rtr_2_snat_dev.route.add_gateway(str(snat_2_rtr.ip), table=SNAT_RT_TBL)
        
        #update local arp table
        #self._update_snat_arp_entry(snat_2_rtr_dev, 'add')

    
    def _update_snat_arp_entry(self, snat_2_rtr_dev, operation):
        try:            
            
            if snat_2_rtr_dev.exists():
                mac = snat_2_rtr_dev.address()
                ip = '169.254.128.129'
                if operation == 'add':
                    snat_2_rtr_dev.neigh.add(ip, mac)
                elif operation == 'delete':
                    snat_2_rtr_dev.neigh.delete(ip, mac)
                return True
            else:
                if operation == 'add':
                    LOG.warning(_LW("Device %s does not exist so ARP entry "
                                    "cannot be updated, will cache "
                                    "information to be applied later "
                                    "when the device exists"),
                                snat_2_rtr_dev)
                return False
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("DVR: Failed updating LOCAL SNAT arp entry"))
                