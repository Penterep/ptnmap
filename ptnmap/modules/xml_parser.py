import ipaddress
import re

import defusedxml.ElementTree as ET

class XmlParser:

    def __init__(self, xml_output: str, ptjsonlib, use_json):
        try:
            self.ptjsonlib = ptjsonlib
            self.root = ET.fromstring(xml_output)
        except Exception as e:
            self.ptjsonlib.end_error(f"Error parsing XML file - {e}", use_json)

    def parse_results(self, args):
        """Main method"""
        scan_ports = args.scan_port_connect or args.scan_port_syn or args.scan_port_udp

        if args.scan_live:
            self.get_live_hosts()
        if args.scan_service and not scan_ports:
            self.get_services()
        if args.scan_os:
            self.get_os()
        if scan_ports:
            self.get_ports(self.is_multi_target(getattr(args, "target", None)))


    def get_os(self):
        """Get result from OS detection scan"""
        result_string = ""

        for index, osmatch in enumerate(self.root.find("host").find("os").findall("osmatch")):
            osmatch_name = osmatch.get("name")
            osmatch_accuracy = osmatch.get("accuracy")
            result_string += f"{osmatch_name} ({osmatch_accuracy}%)"

            if int(osmatch_accuracy) > 90 and not self.ptjsonlib.json_object["results"]["properties"].get("vendor") and osmatch.find("osclass").get("vendor") is not None:
                self.ptjsonlib.add_properties({"os": osmatch.find("osclass").get("vendor")})
            if index+1 != len(self.root.find("host").find("os").findall("osmatch")):
                result_string += ", "

        self.ptjsonlib.add_properties({"description": "Nmap: " + result_string})

    def get_live_hosts(self):
        """Get result from live host scan"""
        for host in self.root.findall("host"):
            self.add_device_nodes(host)


    def get_services(self):
        """Parse service scan xml output"""
        for host in self.root.findall("host"):
            for port in host.find("ports").findall("port"):
                banner = ""
                port_id = port.get("portid")
                state = port.find("state").get("state")
                if state == "closed":
                    continue
                service = port.find("service")
                if service is not None:
                    service = port.find("service").get("name")
                    product = port.find("service").get("product")
                    version = port.find("service").get("version")
                    extrainfo = port.find("service").get("extrainfo")
                    if product:
                        banner += f'{product}'
                    if version:
                        banner += f'{version}'
                    if extrainfo:
                        banner += f' ({extrainfo})'
                name = service.upper() if service else port_id
                props = {"port": port_id, "name": name, "state": state, "serviceType": self.get_service_type(service)}
                if banner: props["version"] = banner
                self.ptjsonlib.add_node(self.ptjsonlib.create_node_object("service", properties=props))

    def get_ports(self, multi_target=False):
        for host in self.root.findall("host"):
            service_parent = None
            service_parent_type = None
            if multi_target:
                device_node = self.add_device_nodes(host)
                service_parent = device_node.get("key")
                service_parent_type = "device"

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port in ports_elem.findall("port"):
                raw_state = port.find("state").get("state")
                if raw_state == "closed":
                    continue
                port_id = port.get("portid")
                protocol = port.get("protocol")
                state = "portState" + raw_state.capitalize()
                reason = port.find("state").get("reason")
                service_elem = port.find("service")
                name = port_id
                service = None
                if service_elem is not None:
                    name = service_elem.get("name")
                    service = self.get_service_type(name)
                    if name:
                        name = name.upper()
                props = {"name": name, "port": port_id, "protocol": protocol, "portState": state, "serviceType": service}
                version = self.get_service_version(service_elem)
                if version:
                    props["version"] = version
                self.ptjsonlib.add_node(self.ptjsonlib.create_node_object("service", parent_type=service_parent_type, parent=service_parent, properties=props))

    @staticmethod
    def is_multi_target(target):
        if not target:
            return False

        target = target.strip()
        try:
            return ipaddress.ip_network(target, strict=False).num_addresses > 1
        except ValueError:
            pass

        return any(separator in target for separator in [",", " ", "*"]) or re.search(r"(?:^|\.)\d+-\d+(?:\.|$)", target) is not None

    def add_device_nodes(self, host):
        device_props = {}
        adapter_props = {"name": "Net interface"}
        ip_props = {"ip_address_type": "ipAddressTypeIPv4"}

        for address in host.findall("address"):
            addr = address.get("addr")
            vendor = address.get("vendor")
            if address.get("addrtype") == "ipv4":
                device_props["name"] = addr
                ip_props["name"] = addr
                ip_props["ip_address"] = addr
            if address.get("addrtype") == "mac":
                adapter_props["macAddress"] = addr
            if vendor:
                adapter_props["vendor"] = vendor

        device_node = self.ptjsonlib.create_node_object("device", properties=device_props)
        device_node["autoAddChildren"] = False
        self.ptjsonlib.add_node(device_node)

        adapter_node = self.ptjsonlib.create_node_object(
            "net_adapter", parent=device_node.get("key"), properties=adapter_props
        )
        adapter_node["autoAddChildren"] = False
        self.ptjsonlib.add_node(adapter_node)

        ip_node = self.ptjsonlib.create_node_object(
            "ip_address", parent=adapter_node.get("key"), properties=ip_props
        )
        ip_node["autoAddChildren"] = False
        self.ptjsonlib.add_node(ip_node)
        return device_node

    @staticmethod
    def get_service_version(service_elem):
        if service_elem is None:
            return None

        banner = ""
        product = service_elem.get("product")
        version = service_elem.get("version")
        extrainfo = service_elem.get("extrainfo")
        if product:
            banner += product
        if version:
            banner += version
        if extrainfo:
            banner += f" ({extrainfo})"
        return banner or None

    @staticmethod
    def get_service_type(service):
        if not service:
            return None

        if service == "http":
            return "serviceTypeHttps"

        return "serviceType" + service.capitalize()

    def get_elapsed_time(self):
        return self.root.find("runstats").find("finished").get("elapsed")

    def get_input_args(self):
        """Retrieve nmap input args"""
        return self.root.get("args")

    def get_summary(self):
        """Retrieve nmap summary"""
        return self.root.find("runstats").find("finished").get("summary")
