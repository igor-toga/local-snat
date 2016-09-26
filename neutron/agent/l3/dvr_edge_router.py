# Copyright (c) 2015 OpenStack Foundation
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

from neutron.agent.l3 import dvr_edge_router_base as dvr_edge_base
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import router_info as router
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager

LOG = logging.getLogger(__name__)


class DvrEdgeRouter(dvr_edge_base.DvrEdgeRouterBase):

    def __init__(self, agent, host, *args, **kwargs):
        super(DvrEdgeRouter, self).__init__(agent, host, *args, **kwargs)
        self.snat_namespace = dvr_snat_ns.SnatNamespace(
            self.router_id, self.agent_conf, self.driver, self.use_ipv6)
        self.snat_iptables_manager = None

    def external_gateway_added(self, ex_gw_port, interface_name):
        super(DvrEdgeRouter, self).external_gateway_added(
            ex_gw_port, interface_name)
        if self._is_this_snat_host():
            self._create_dvr_gateway(ex_gw_port, interface_name)
            # NOTE: When a router is created without a gateway the routes get
            # added to the router namespace, but if we wanted to populate
            # the same routes to the snat namespace after the gateway port
            # is added, we need to call routes_updated here.
            self.routes_updated([], self.router['routes'])
        elif self.snat_namespace.exists():
            # This is the case where the snat was moved manually or
            # rescheduled to a different agent when the agent was dead.
            LOG.debug("SNAT was moved or rescheduled to a different host "
                      "and does not match with the current host. This is "
                      "a stale namespace %s and will be cleared from the "
                      "current dvr_snat host.", self.snat_namespace.name)
            self.external_gateway_removed(ex_gw_port, interface_name)

    def external_gateway_updated(self, ex_gw_port, interface_name):
        if not self._is_this_snat_host():
            # no centralized SNAT gateway for this node/agent
            LOG.debug("not hosting snat for router: %s", self.router['id'])
            if self.snat_namespace.exists():
                LOG.debug("SNAT was rescheduled to host %s. Clearing snat "
                          "namespace.", self.router.get('gw_port_host'))
                return self.external_gateway_removed(
                    ex_gw_port, interface_name)
            return

        if not self.snat_namespace.exists():
            # SNAT might be rescheduled to this agent; need to process like
            # newly created gateway
            return self.external_gateway_added(ex_gw_port, interface_name)
        else:
            self._external_gateway_added(ex_gw_port,
                                        interface_name,
                                        self.snat_namespace.name,
                                        preserve_ips=[])

    def _external_gateway_removed(self, ex_gw_port, interface_name):
        super(DvrEdgeRouter, self).external_gateway_removed(ex_gw_port,
                                                            interface_name)
        if not self._is_this_snat_host() and not self.snat_namespace.exists():
            # no centralized SNAT gateway for this node/agent
            LOG.debug("not hosting snat for router: %s", self.router['id'])
            return

        self.driver.unplug(interface_name,
                           bridge=self.agent_conf.external_network_bridge,
                           namespace=self.snat_namespace.name,
                           prefix=router.EXTERNAL_DEV_PREFIX)

    def external_gateway_removed(self, ex_gw_port, interface_name):
        self._external_gateway_removed(ex_gw_port, interface_name)
        if self.snat_namespace.exists():
            self.snat_namespace.delete()

    def internal_network_added(self, port):
        super(DvrEdgeRouter, self).internal_network_added(port)

        # TODO(gsagie) some of this checks are already implemented
        # in the base class, think how to avoid re-doing them
        if not self._is_this_snat_host():
            return

        sn_port = self.get_snat_port_for_internal_port(port)
        if not sn_port:
            return

        ns_name = dvr_snat_ns.SnatNamespace.get_snat_ns_name(self.router['id'])
        interface_name = self._get_snat_int_device_name(sn_port['id'])
        self._internal_network_added(
            ns_name,
            sn_port['network_id'],
            sn_port['id'],
            sn_port['fixed_ips'],
            sn_port['mac_address'],
            interface_name,
            dvr_snat_ns.SNAT_INT_DEV_PREFIX,
            mtu=sn_port.get('mtu'))

    def _dvr_internal_network_removed(self, port):
        super(DvrEdgeRouter, self)._dvr_internal_network_removed(port)

        if not self.ex_gw_port:
            return

        sn_port = self.get_snat_port_for_internal_port(port, self.snat_ports)
        if not sn_port:
            return

        if not self._is_this_snat_host():
            return

        snat_interface = self._get_snat_int_device_name(sn_port['id'])
        ns_name = self.snat_namespace.name
        prefix = dvr_snat_ns.SNAT_INT_DEV_PREFIX
        if ip_lib.device_exists(snat_interface, namespace=ns_name):
            self.driver.unplug(snat_interface, namespace=ns_name,
                               prefix=prefix)

    def _plug_snat_port(self, port):
        interface_name = self._get_snat_int_device_name(port['id'])
        self._internal_network_added(
            self.snat_namespace.name, port['network_id'],
            port['id'], port['fixed_ips'],
            port['mac_address'], interface_name,
            dvr_snat_ns.SNAT_INT_DEV_PREFIX,
            mtu=port.get('mtu'))

    def _create_dvr_gateway(self, ex_gw_port, gw_interface_name):
        """Create SNAT namespace."""
        snat_ns = self._create_snat_namespace()
        # connect snat_ports to br_int from SNAT namespace
        for port in self.get_snat_interfaces():
            # create interface_name
            self._plug_snat_port(port)
        self._external_gateway_added(ex_gw_port, gw_interface_name,
                                     snat_ns.name, preserve_ips=[])
        self.snat_iptables_manager = iptables_manager.IptablesManager(
            namespace=snat_ns.name,
            use_ipv6=self.use_ipv6)
        # kicks the FW Agent to add rules for the snat namespace
        self.agent.process_router_add(self)

    def _create_snat_namespace(self):
        # TODO(mlavalle): in the near future, this method should contain the
        # code in the L3 agent that creates a gateway for a dvr. The first step
        # is to move the creation of the snat namespace here
        self.snat_namespace.create()
        return self.snat_namespace

    def _get_snat_int_device_name(self, port_id):
        long_name = dvr_snat_ns.SNAT_INT_DEV_PREFIX + port_id
        return long_name[:self.driver.DEV_NAME_LEN]
