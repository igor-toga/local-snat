# Copyright (c) 2016 OpenStack Foundation
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

import netaddr
from neutron.agent.l3 import router_info as router
from neutron.agent.l3 import dvr_edge_router_base as dvr_edge_base
from neutron.agent.l3 import dvr_local_snat_ns
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import ip_lib
from neutron.common import constants as l3_constants
from neutron.common import utils as common_utils

LOG = logging.getLogger(__name__)


class DvrLocalEdgeRouter(dvr_edge_base.DvrEdgeRouterBase):

    def __init__(self, agent, host, *args, **kwargs):
        LOG.warning('DvrLocalEdgeRouter constructor')
        #bypass direct base class
        super(dvr_edge_base.DvrEdgeRouterBase, self).__init__(agent, host, *args, **kwargs)
        
        self.snat_namespace = dvr_local_snat_ns.LocalSnatNamespace(
            self.router_id, self.agent_conf, self.driver, self.use_ipv6)
        self.snat_iptables_manager = None 

                    
    def get_snat_interfaces(self):
        """
        If there is a local gateway port we return self generated port information
        Otherwise delegate information passed by neutron server
        """
        #LOG.warning("-------> get_snat_interfaces for router_id %(router)s namespace exists: %(ns)s", 
        #            {'router':self.router_id, 'ns':self.snat_namespace.exists()} )
        if self.snat_namespace.exists():
            return [self.snat_namespace.get_snat2r_interface(self.router_id)]
        else:
            super(dvr_edge_base.DvrEdgeRouterBase, self).get_snat_interfaces()
        

    def internal_network_added(self, port):
        # legacy implementation is good for us 
        # Implementation achieve correct snat port due to overridden   
        #  - get_snat_port_for_internal_port()
        #  - get_snat_interfaces()
        LOG.warning("-------> internal_network_added, STARTED")
        super(dvr_edge_base.DvrEdgeRouterBase, self).internal_network_added(port)
        LOG.warning("-------> internal_network_added, FINISHED")
        
    
    def _dvr_internal_network_removed(self, port):
        LOG.debug("-------> overriden _dvr_internal_network_removed STARTED")
        if not self.ex_gw_port:
            return

        sn_port = self.get_snat_port_for_internal_port(port, self.snat_ports)
        if not sn_port:
            return

        # DVR handling code for SNAT
        interface_name = self.get_next_hop_device_name(sn_port['id'], port['id'])
        self._snat_redirect_remove(sn_port, port, interface_name)
        # Clean up the cached arp entries related to the port subnet
        for subnet in port['subnets']:
            self._delete_arp_cache_for_internal_port(subnet)
        
        LOG.debug("-------> overriden _dvr_internal_network_removed FINISHED")

        
        
    def internal_network_removed(self, port):
        # legacy implementation is good for us 
        # Implementation achieve correct snat port due to overridden   
        #  - get_snat_port_for_internal_port()
        #  - get_snat_interfaces()
        LOG.debug("-------> internal_network_removed")
        super(dvr_edge_base.DvrEdgeRouterBase, self).internal_network_removed(port)
      
    
    def get_snat_port_for_internal_port(self, int_port, snat_ports=None):
        
        #LOG.debug("-------> get_snat_port_for_internal_port, router_id: %s", self.router_id)
        if self.snat_namespace.exists():
            return self.snat_namespace.get_snat2r_interface(self.router_id)
        else:
            super(dvr_edge_base.DvrEdgeRouterBase, self).get_snat_port_for_internal_port(int_port, snat_ports)

        
    def local_gateway_added(self, ex_gw_port, interface_name):
        
        LOG.warning("-------> local_gateway_added STARTED")
        ip_wrapr = ip_lib.IPWrapper(namespace=self.ns_name)
        ip_wrapr.netns.execute(['sysctl', '-w',
                               'net.ipv4.conf.all.send_redirects=0'])
        
        
        for p in self.internal_ports:
            # remove source policy rule for legacy snat
            remote_gateway = self.get_snat_port_for_internal_port(p)
            if remote_gateway:
                id_name = self.get_next_hop_device_name(remote_gateway['id'], p['id'])
                self._snat_redirect_remove(remote_gateway, p, id_name)
                LOG.warning("-------> local_gateway_added::_snat_redirect_remove interface: %s", id_name)
        
        self._create_dvr_gateway(ex_gw_port, interface_name)
        
        for p in self.internal_ports:
            # add source policy rule for local snat    
            local_gateway = self.snat_namespace.get_snat2r_interface(self.router_id)
            if local_gateway:
                id_name = self.get_next_hop_device_name(local_gateway['id'], p['id'])
                self._snat_redirect_add(local_gateway, p, id_name)
                LOG.warning("-------> local_gateway_added::_snat_redirect_add interface: %s", id_name)
        
                self._snat_back_redirect_add(p)

        
        # NOTE: When a router is created without a gateway the routes get
        # added to the router namespace, but if we wanted to populate
        # the same routes to the snat namespace after the gateway port
        # is added, we need to call routes_updated here.
        self.routes_updated([], self.router['routes'])
        LOG.warning("-------> local_gateway_added FINISHED")
    
    def local_gateway_removed(self, ex_gw_port, interface_name):
        
        LOG.warning("-------> local_gateway_removed STARTED")
        for p in self.internal_ports:
            # NOTE: When removing the gateway port, pass in the snat_port
            # cache along with the current ports.
            LOG.debug("-------> local_gateway_removed for port %s", p)
            local_gateway = self.snat_namespace.get_snat2r_interface(self.router_id)
            internal_interface = self.get_next_hop_device_name(local_gateway['id'], p['id'])
            self._snat_redirect_remove(local_gateway, p, internal_interface)
            LOG.warning("-------> local_gateway_removed::_snat_redirect_remove interface: %s", internal_interface)
        
        self.driver.unplug(interface_name,
                       bridge=self.agent_conf.external_network_bridge,
                       namespace=self.snat_namespace.name,
                       prefix=router.EXTERNAL_DEV_PREFIX)  
        
        self.snat_namespace.delete() 
        
        # restore default gateway rules
        for p in self.internal_ports:            
            remote_gateway = self.get_snat_port_for_internal_port(p, self.snat_ports)
            if not remote_gateway:
                continue
            internal_interface = self.get_next_hop_device_name(remote_gateway['id'], p['id'])
            self._snat_redirect_add(remote_gateway, p, internal_interface)
            LOG.warning("-------> local_gateway_removed::_snat_redirect_remove interface: %s", internal_interface)
            

                 
        LOG.warning("-------> local_gateway_removed FINISHED")

    def external_gateway_updated(self, ex_gw_port, interface_name):
        
        
        is_snat_host = self._is_this_snat_host()
        is_ns_exists = self.snat_namespace.exists()
        LOG.warning("external_gateway_updated, is_sat_host: %s namespace exists: %s",is_snat_host, is_ns_exists)
        # centralized gateway changed , call legacy implementation
        if not is_snat_host and not is_ns_exists:
            super(dvr_edge_base.DvrEdgeRouterBase, self).external_gateway_updated(ex_gw_port, interface_name)
        else:
            # added local gateway
            if is_snat_host and not is_ns_exists:
                self.local_gateway_added(ex_gw_port, interface_name)
                
            # remove local gateway
            elif not is_snat_host and is_ns_exists:
                self.local_gateway_removed(ex_gw_port, interface_name)
                
            else:
                LOG.warning("external_gateway_updated: Bad request")
        
        
    def external_gateway_added(self, ex_gw_port, interface_name):
        LOG.warning("-------> OVERRIDEN external_gateway_added STARTED")
        if self._is_this_snat_host():
            self.local_gateway_added(ex_gw_port, interface_name)
        else:
            super(dvr_edge_base.DvrEdgeRouterBase, self).external_gateway_added(ex_gw_port, interface_name)
            
    def external_gateway_removed(self, ex_gw_port, interface_name):
        LOG.warning("-------> OVERRIDEN external_gateway_removed STARTED")
        if self._is_this_snat_host():
            self.local_gateway_removed(ex_gw_port, interface_name)
        else:
            super(dvr_edge_base.DvrEdgeRouterBase, self).external_gateway_removed(ex_gw_port, interface_name)
    

    # (ishafran) Overridden no need to create internal subnet SNAT ports
    def _create_dvr_gateway(self, ex_gw_port, gw_interface_name):
        """Create SNAT namespace."""
        
        LOG.warning("_create_dvr_gateway")
        snat_ns = self._create_snat_namespace(ex_gw_port)
        
        self._external_gateway_added(ex_gw_port, gw_interface_name,
                                     snat_ns.name, preserve_ips=[])
        self.snat_iptables_manager = iptables_manager.IptablesManager(
            namespace=snat_ns.name,
            use_ipv6=self.use_ipv6)
        # kicks the FW Agent to add rules for the snat namespace
        self.agent.process_router_add(self)

    def _create_snat_namespace(self, ex_gw_port):
                
        LOG.debug("_create_local_snat_namespace")
        self.snat_namespace.create()
        self.snat_namespace.create_rtr_2_snat_link(self)
        return self.snat_namespace


    def get_next_hop_device_name(self, sn_port_id, port_id):
        if sn_port_id.startswith(dvr_local_snat_ns.SNAT_2_ROUTER_DEV_PREFIX):
            interface_name = self.snat_namespace.get_rtr_ext_device_name(self.router_id)
        else:
            interface_name = self.get_internal_device_name(port_id)
        
        return interface_name
    
    
    def _snat_redirect_add_from_port(self, port):
        ex_gw_port = self.get_ex_gw_port()
        if not ex_gw_port:
            return

        sn_port = self.get_snat_port_for_internal_port(port)
        if not sn_port:
            return
            

        interface_name = self.get_next_hop_device_name(sn_port['id'], port['id'])
            
        LOG.warning("-------> DvrLocalEdgeRouter(OVERRIDDEN)::_snat_redirect_add_from_port interface: %s", interface_name)
        self._snat_redirect_add(sn_port, port, interface_name)
    
    
    def _snat_back_redirect_add(self, p):
        interface_name = self.snat_namespace.get_int_device_name(self.router_id)
        ns_ipd = ip_lib.IPDevice(interface_name, 
                                 namespace=self.snat_namespace.get_snat_ns_name(self.router_id))

        gateway = self.snat_namespace.get_r2snat_interface(self.router_id)
        LOG.warning("-------> _snat_back_redirect_add %s", interface_name)
        
        for port_fixed_ip in p['fixed_ips']:
            port_ip_addr = port_fixed_ip['ip_address']
            # patch instead of ip _to_cidr
            port_network = netaddr.IPNetwork(port_ip_addr)
            port_network._set_prefixlen(port_fixed_ip['prefixlen'])
            port_cidr = port_network.cidr
            #port_cidr = common_utils.ip_to_cidr(port_ip_addr, port_fixed_ip['prefixlen'])
            
            for gw_fixed_ip in gateway['fixed_ips']:
                gw_ip_addr = gw_fixed_ip['ip_address']
                
                ns_ipd.route.add_route(port_cidr, gw_ip_addr)
                LOG.warning("-------> _snat_back_redirect_add ---------> PERFORMED %s", interface_name)
    
    
    # This method is called by process_scope_addresses
    # since our snat part is already generated in localSnat namespace return its device name as is
    def _get_snat_int_device_name(self, port_id):
        if self.snat_namespace.exists():
            return port_id
        else:
            long_name = l3_constants.SNAT_INT_DEV_PREFIX + port_id
            return long_name[:self.driver.DEV_NAME_LEN]
    
    
    def _add_snat_port_devicename_scopemark(self, devicename_scopemark):
        
        p = self.snat_namespace.get_r2snat_interface(self.router_id)
        device_name = p['id']
        ip_cidrs = common_utils.fixed_ip_cidrs(p['fixed_ips'])
        port_as_marks = self.get_port_address_scope_mark(p)
        for ip_version in {ip_lib.get_ip_version(cidr)
                           for cidr in ip_cidrs}:
            devicename_scopemark[ip_version][device_name] = (
                port_as_marks[ip_version])

        return devicename_scopemark
            
    def _get_address_scope_mark(self):
        # Prepare address scope iptables rule for internal ports
        internal_ports = self.router.get(l3_constants.INTERFACE_KEY, [])
        ports_scopemark = self._get_port_devicename_scopemark(
            internal_ports, self.get_internal_device_name)
        
        ports_scopemark = self._add_snat_port_devicename_scopemark(ports_scopemark)
        
        # DVR local router will use rfp port as external port
        ext_port = self.get_ex_gw_port()
        if not ext_port:
            return ports_scopemark

        ext_device_name = self.get_external_device_interface_name(ext_port)
        if not ext_device_name:
            return ports_scopemark

        ext_scope = self._get_external_address_scope()
        ext_scope_mark = self.get_address_scope_mark_mask(ext_scope)
        ports_scopemark[l3_constants.IP_VERSION_4][ext_device_name] = (
            ext_scope_mark)
        return ports_scopemark