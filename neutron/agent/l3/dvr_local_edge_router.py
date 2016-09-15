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

from neutron.agent.l3 import dvr_local_router
from neutron.agent.l3 import dvr_edge_router
from neutron.agent.l3 import dvr_local_snat_ns
from neutron.agent.linux import iptables_manager

LOG = logging.getLogger(__name__)


class DvrLocalEdgeRouter(dvr_edge_router.DvrEdgeRouter):

    def __init__(self, agent, host, *args, **kwargs):
        LOG.warning('DvrLocalEdgeRouter constructor')
        #bypass direct base class
        super(DvrEdgeRouter, self).__init__(agent, host, *args, **kwargs)
        
        self.snat_namespace = dvr_local_snat_ns.LocalSnatNamespace(
            self.router_id, self.agent_conf, self.driver, self.use_ipv6)
        self.snat_iptables_manager = None 

    #def _get_snat_int_device_name(self):
    #    return self.snat_namespace.get_int_device_name(self.router_id)


    def internal_network_added(self, port):
        LOG.debug("-----------> Called internal network added")
        dvr_local_router.DvrLocalRouter.internal_network_added(self, port)
        
    def internal_network_removed(self, port):
        LOG.debug("-----------> Called internal network removed")
        dvr_local_router.DvrLocalRouter.internal_network_removed(self, port)
      
      
        
    def external_gateway_added(self, ex_gw_port, interface_name):
        # This method is called in the following cases:
        #    1. new legacy gateway port is defined ( lays on different host ) , 
        #                lead to invocation of DvrLocalRouter method
        #    2. update of legacy gateway port is occurred. ( lays on different host ), 
        #                lead to invocation of DvrLocalRouter method
        #    3. 'add_gateway_port' caused this update. Have to add customized Snat namespace
        LOG.warning("external_gateway_added")
        if self._is_this_snat_host():
            dvr_edge_router.DvrEdgeRouter.external_gateway_added(self, ex_gw_port, interface_name)
        else:
            dvr_local_router.DvrLocalRouter.external_gateway_added(self, ex_gw_port, interface_name)

    def external_gateway_updated(self, ex_gw_port, interface_name):
        
        LOG.warning("external_gateway_updated")
        if not self._is_this_snat_host() and not self.snat_namespace:
            dvr_local_router.DvrLocalRouter.external_gateway_updated(self, ex_gw_port, interface_name)
        else:
            dvr_edge_router.DvrEdgeRouter.external_gateway_updated(self, ex_gw_port, interface_name)
            
        

    def external_gateway_removed(self, ex_gw_port, interface_name):
        #  This method is called in the following cases:
        #    1. 'remove_gateway_port' caused this removal and therefore is_snat_host will be: True
        #    2. legacy gateway_clear was called but this host had an alternative gateway connection ( snat namespace)
        
        LOG.warning("external_gateway_removed")
        if self._is_this_snat_host() or self.snat_namespace:
            dvr_edge_router.DvrEdgeRouter.external_gateway_removed(self, ex_gw_port, interface_name)
        else:
            dvr_local_router.DvrLocalRouter.external_gateway_removed(self, ex_gw_port, interface_name)
        

    

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
        self.snat_namespace.create_gateway_port(ex_gw_port)
        
        # wire additional ports between router and snat namespaces
        self.snat_namespace.create_rtr_2_snat_link(self)

        return self.snat_namespace


