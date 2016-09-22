from oslo_log import log as logging

from neutron._i18n import _LE
from neutron.agent.l3 import dvr_local_router
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import router_info as router
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.common import constants as l3_constants

LOG = logging.getLogger(__name__)


class DvrEdgeRouterBase(dvr_local_router.DvrLocalRouter):

    def __init__(self, agent, host, *args, **kwargs):
        super(DvrEdgeRouterBase, self).__init__(agent, host, *args, **kwargs)
        self.snat_namespace = None
        self.snat_iptables_manager = None

    
    
    def delete(self, agent):
        super(DvrEdgeRouterBase, self).delete(agent)
        if self.snat_namespace.exists():
            self.snat_namespace.delete()
            

    def _is_this_snat_host(self):
        host = self.router.get('gw_port_host')
        LOG.warning("_is_this_snat_host: attribute gw_port_host: %s, self host: %s", host, self.host)
        if not host:
            LOG.debug("gw_port_host missing from router: %s",
                      self.router['id'])
        return host == self.host

    def _handle_router_snat_rules(self, ex_gw_port, interface_name):
        super(DvrEdgeRouterBase, self)._handle_router_snat_rules(
            ex_gw_port, interface_name)

        if not self._is_this_snat_host():
            return
        if not self.get_ex_gw_port():
            return

        if not self.snat_iptables_manager:
            LOG.debug("DVR router: no snat rules to be handled")
            return

        with self.snat_iptables_manager.defer_apply():
            self._empty_snat_chains(self.snat_iptables_manager)

            # NOTE: DVR adds the jump to float snat via super class,
            # but that is in the router namespace and not snat.

            self._add_snat_rules(ex_gw_port, self.snat_iptables_manager,
                                 interface_name)

    
    
    
    def update_routing_table(self, operation, route):
        if self.get_ex_gw_port() and self._is_this_snat_host():
            ns_name = self.snat_namespace.name
            # NOTE: For now let us apply the static routes both in SNAT
            # namespace and Router Namespace, to reduce the complexity.
            if self.snat_namespace.exists():
                super(DvrEdgeRouterBase, self)._update_routing_table(
                    operation, route, namespace=ns_name)
            else:
                LOG.error(_LE("The SNAT namespace %s does not exist for "
                              "the router."), ns_name)
        super(DvrEdgeRouterBase, self).update_routing_table(operation, route)
        
    def process_address_scope(self):
        super(DvrEdgeRouterBase, self).process_address_scope()

        if not self._is_this_snat_host():
            return
        if not self.snat_iptables_manager:
            LOG.debug("DVR router: no snat rules to be handled")
            return

        # Prepare address scope iptables rule for dvr snat interfaces
        internal_ports = self.get_snat_interfaces()
        ports_scopemark = self._get_port_devicename_scopemark(
            internal_ports, self._get_snat_int_device_name)
        # Prepare address scope iptables rule for external port
        external_port = self.get_ex_gw_port()
        if external_port:
            external_port_scopemark = self._get_port_devicename_scopemark(
                [external_port], self.get_external_device_name)
            for ip_version in (l3_constants.IP_VERSION_4,
                               l3_constants.IP_VERSION_6):
                ports_scopemark[ip_version].update(
                    external_port_scopemark[ip_version])

        with self.snat_iptables_manager.defer_apply():
            self._add_address_scope_mark(
                self.snat_iptables_manager, ports_scopemark)
