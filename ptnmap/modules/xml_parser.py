import ipaddress
import json
import re
from pathlib import Path

import defusedxml.ElementTree as ET

class XmlParser:

    def __init__(self, xml_output: str, ptjsonlib, use_json):
        try:
            self.ptjsonlib = ptjsonlib
            self.root = ET.fromstring(xml_output)
            self.service_mapping = None
        except Exception as e:
            self.ptjsonlib.end_error(f"Error parsing XML file - {e}", use_json)

    def parse_results(self, args):
        """Main method"""
        scan_ports = args.scan_port_connect or args.scan_port_syn or args.scan_port_udp
        current_service = (
            args.scan_service
            and not self.is_multi_target(getattr(args, "target", None))
            and bool(getattr(args, "target", None))
            and self.is_single_port(getattr(args, "port", None))
        )

        if args.scan_live:
            self.get_live_hosts()
        if current_service:
            self.get_service_properties()
        elif args.scan_service and not scan_ports:
            self.get_services()
        if args.scan_os:
            self.get_os()
        if scan_ports and not current_service:
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


    def get_service_properties(self):
        """Update the current service without creating a new node."""
        hosts = self.root.findall("host")
        if len(hosts) != 1:
            return

        ports = hosts[0].findall("ports/port")
        if len(ports) != 1:
            return

        port = ports[0]
        state = port.find("state")
        if state is None or state.get("state") == "closed":
            return

        service = port.find("service")
        service_name = service.get("name") if service is not None else None
        service_type = self.get_service_type(service_name)
        if service_type:
            self.ptjsonlib.add_properties({"serviceType": service_type})
        elif service_name:
            self.ptjsonlib.add_properties({"name": self.get_service_name(service_name, port.get("portid"))})

    def get_services(self):
        """Parse service scan xml output"""
        for host in self.root.findall("host"):
            for port in host.find("ports").findall("port"):
                port_id = port.get("portid")
                state = port.find("state").get("state")
                if state == "closed":
                    continue
                service_elem = port.find("service")
                service = service_elem.get("name") if service_elem is not None else None
                props = {"port": port_id, "name": self.get_service_name(service, port_id), "state": state}
                service_type = self.get_service_type(service)
                if service_type:
                    props["serviceType"] = service_type
                banner = self.get_service_version(service_elem)
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
                state = "portState" + "".join(part.capitalize() for part in raw_state.split("|"))
                reason = port.find("state").get("reason")
                service_elem = port.find("service")
                service_name = service_elem.get("name") if service_elem is not None else None
                props = {"name": self.get_service_name(service_name, port_id), "port": port_id, "protocol": protocol, "portState": state}
                service_type = self.get_service_type(service_name)
                if service_type:
                    props["serviceType"] = service_type
                version = self.get_service_version(service_elem)
                if version:
                    props["version"] = version
                self.ptjsonlib.add_node(self.ptjsonlib.create_node_object("service", parent_type=service_parent_type, parent=service_parent, properties=props))

    @staticmethod
    def is_single_port(port):
        return port is not None and re.fullmatch(r"(?:[TUSP]:)?[0-9]+", port.strip()) is not None

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
                adapter_props["name"] = addr
                adapter_props["macAddress"] = addr
                if vendor:
                    adapter_props["vendor"] = vendor

        device_node = self.ptjsonlib.create_node_object("device", properties=device_props)
        device_node["autoAddChildren"] = False
        self.ptjsonlib.add_node(device_node)

        adapter_node = self.ptjsonlib.create_node_object(
            "net_interface", parent=device_node.get("key"), properties=adapter_props
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

    def get_service_definition(self, service):
        if not service:
            return {}

        if self.service_mapping is None:
            with Path(__file__).with_name("service_mapping.json").open(encoding="utf-8") as mapping_file:
                self.service_mapping = json.load(mapping_file)
        return self.service_mapping.get(service, {})

    def get_service_type(self, service):
        return self.get_service_definition(service).get("serviceType")

    def get_service_name(self, service, port):
        if not service:
            return port
        name = self.get_service_definition(service).get("name", service.upper())
        return f"{port} ({name})"

    def get_elapsed_time(self):
        return self.root.find("runstats").find("finished").get("elapsed")

    def get_input_args(self):
        """Retrieve nmap input args"""
        return self.root.get("args")

    def get_summary(self):
        """Retrieve nmap summary"""
        return self.root.find("runstats").find("finished").get("summary")
