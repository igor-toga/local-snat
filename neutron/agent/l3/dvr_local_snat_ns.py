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
#SNAT_INT_DEV_PREFIX = constants.SNAT_INT_DEV_PREFIX

EXT_DEV_PREFIX = namespaces.EXTERNAL_DEV_PREFIX
SNAT_2_ROUTER_DEV_PREFIX = 'snat2r-'
ROUTER_2_SNAT_DEV_PREFIX = namespaces.ROUTER_2_SNAT_DEV_PREFIX
# Route Table index for FIPs
SNAT_RT_TBL = 18
SNAT_LL_SUBNET = '169.254.128.0/31'
# Rule priority 
SNAT_PR_START = 167772100

class LocalSnatNamespace(namespaces.Namespace):

    def __init__(self, router_id, agent_conf, driver, use_ipv6):
        self.router_id = router_id
        self.name = self.get_snat_ns_name(router_id)
        super(LocalSnatNamespace, self).__init__(
            self.name, agent_conf, driver, use_ipv6)
        
        self.agent_gateway_port = None
        self._rule_priority = frpa.FipPriority(str(SNAT_PR_START))
        
        self._iptables_manager = iptables_manager.IptablesManager(
            namespace=self.name,
            use_ipv6=self.use_ipv6)
        # SNAT namespace need a single vpair for all VM's on host
        # This is unlike FIPs subnets generated for every VM
        subnet = netaddr.IPNetwork(SNAT_LL_SUBNET)
        self.vpair = lla.LinkLocalAddressPair(subnet)
        


    @classmethod
    def get_snat_ns_name(cls, router_id):
        return namespaces.build_ns_name(SNAT_NS_PREFIX, router_id)
    
    def get_ext_device_name(self, port_id):
        return (EXT_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_int_device_name(self, router_id):
        return (SNAT_2_ROUTER_DEV_PREFIX + router_id)[:self.driver.DEV_NAME_LEN]

    def get_rtr_ext_device_name(self, router_id):
        return (ROUTER_2_SNAT_DEV_PREFIX + router_id)[:self.driver.DEV_NAME_LEN]



        
    def _gateway_added(self, ex_gw_port, interface_name):
        """Add Local Snat IP gateway port."""
        LOG.warning("add gateway interface(%s)", interface_name)
        ns_name = self.name
        self.driver.plug(ex_gw_port['network_id'],
                         ex_gw_port['id'],
                         interface_name,
                         ex_gw_port['mac_address'],
                         bridge=self.agent_conf.external_network_bridge,
                         namespace=ns_name,
                         prefix=EXT_DEV_PREFIX,
                         mtu=ex_gw_port.get('mtu'))

        # Remove stale fg devices
        ip_wrapper = ip_lib.IPWrapper(namespace=ns_name)
        devices = ip_wrapper.get_devices()
        for device in devices:
            name = device.name
            if name.startswith(EXT_DEV_PREFIX) and name != interface_name:
                ext_net_bridge = self.agent_conf.external_network_bridge
                self.driver.unplug(name,
                                   bridge=ext_net_bridge,
                                   namespace=ns_name,
                                   prefix=EXT_DEV_PREFIX)

        ip_cidrs = common_utils.fixed_ip_cidrs(ex_gw_port['fixed_ips'])
        self.driver.init_l3(interface_name, ip_cidrs, namespace=ns_name,
                            clean_connections=True)

        self.update_gateway_port(ex_gw_port)

        cmd = ['sysctl', '-w', 'net.ipv4.conf.%s.proxy_arp=1' % interface_name]
        ip_wrapper.netns.execute(cmd, check_exit_code=False)



    def delete(self):
        self.destroyed = True
        ip_wrapper = ip_lib.IPWrapper(namespace=self.name)
        for d in ip_wrapper.get_devices(exclude_loopback=True):
            if d.name.startswith(SNAT_2_ROUTER_DEV_PREFIX):
                # internal link between IRs and FIP NS
                ip_wrapper.del_veth(d.name)
            #===================================================================
            # elif d.name.startswith(EXT_DEV_PREFIX):
            #     # single port from FIP NS to br-ext
            #     # TODO(carl) Where does the port get deleted?
            #     LOG.debug('DVR: unplug: %s', d.name)
            #     ext_net_bridge = self.agent_conf.external_network_bridge
            #     self.driver.unplug(d.name,
            #                        bridge=ext_net_bridge,
            #                        namespace=self.name,
            #                        prefix=EXT_DEV_PREFIX)
            #===================================================================
        self.agent_gateway_port = None

        # TODO(mrsmith): add LOG warn if fip count != 0
        LOG.warning('DVR: destroy LocalSnat namespace: %s', self.name)
        super(LocalSnatNamespace, self).delete()

    def create_gateway_port(self, agent_gateway_port):
        """Create Local Snat gateway port.

           Request port creation from Plugin then creates
           Local Snat namespace and adds gateway port.
        """
        LOG.warning("create_gateway_port")
        self.create()

        iface_name = self.get_ext_device_name(agent_gateway_port['id'])
        self._gateway_added(agent_gateway_port, iface_name)
        
    
    def _check_for_gateway_ip_change(self, new_agent_gateway_port):

        def get_gateway_ips(gateway_port):
            gw_ips = {}
            if gateway_port:
                for subnet in gateway_port.get('subnets', []):
                    gateway_ip = subnet.get('gateway_ip', None)
                    if gateway_ip:
                        ip_version = ip_lib.get_ip_version(gateway_ip)
                        gw_ips[ip_version] = gateway_ip
            return gw_ips

        new_gw_ips = get_gateway_ips(new_agent_gateway_port)
        old_gw_ips = get_gateway_ips(self.agent_gateway_port)

        return new_gw_ips != old_gw_ips

    def update_gateway_port(self, agent_gateway_port):
        
        LOG.warning("update_gateway_port")
        gateway_ip_not_changed = self.agent_gateway_port and (
            not self._check_for_gateway_ip_change(agent_gateway_port))
        self.agent_gateway_port = agent_gateway_port
        if gateway_ip_not_changed:
            return

        ns_name = self.name
        interface_name = self.get_ext_device_name(agent_gateway_port['id'])
        for fixed_ip in agent_gateway_port['fixed_ips']:
            ip_lib.send_ip_addr_adv_notif(ns_name,
                                          interface_name,
                                          fixed_ip['ip_address'],
                                          self.agent_conf)

        ipd = ip_lib.IPDevice(interface_name, namespace=ns_name)
        for subnet in agent_gateway_port.get('subnets',[]):
            gw_ip = subnet.get('gateway_ip')
            if gw_ip:
                is_gateway_not_in_subnet = not ipam_utils.check_subnet_ip(
                                                subnet.get('cidr'), gw_ip)
                if is_gateway_not_in_subnet:
                    ipd.route.add_route(gw_ip, scope='link')
                ipd.route.add_gateway(gw_ip)

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
        #setup the NAT rules and chains
        ri._handle_router_snat_rules(self.agent_gateway_port, rtr_2_snat_name)
