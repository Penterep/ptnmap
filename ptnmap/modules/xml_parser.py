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
        if args.scan_live:
            self.get_live_hosts()
        if args.scan_service:
            self.get_services()
        if args.scan_os:
            self.get_os()
        if args.scan_port_connect or args.scan_port_syn:
            self.get_ports()


    def get_os(self):
        """Get result from OS detection scan"""
        result_string = ""

        for index, osmatch in enumerate(self.root.find("host").find("os").findall("osmatch")):
            osmatch_name = osmatch.get("name")
            osmatch_accuracy = osmatch.get("accuracy")
            result_string += f"{osmatch_name} ({osmatch_accuracy}%)"

            if int(osmatch_accuracy) > 90 and not self.ptjsonlib.json_object["results"]["properties"].get("vendor") and osmatch.find("osclass").get("vendor") is not None:
                self.ptjsonlib.add_property("os", osmatch.find("osclass").get("vendor"))
            if index+1 != len(self.root.find("host").find("os").findall("osmatch")):
                result_string += ", "

        self.ptjsonlib.add_property("description", "Nmap: "+ result_string)


    def get_live_hosts(self):
        """Get result from live host scan"""
        for host in self.root.findall("host"):
            props = dict()

            for address in host.findall("address"):
                addr_type = address.get("addrtype")
                state = host.find("status").get("state")
                reason = host.find("status").get("reason")
                addr = address.get("addr")
                vendor = address.get("vendor")
                if address.get("addrtype") == "ipv4":
                    props["name"] = addr
                    props["ipAddress"] = addr
                if address.get("addrtype") == "mac":
                    props["macAddress"] = addr
                if address.get("vendor"):
                    props["vendor"] = vendor
            self.ptjsonlib.add_node(self.ptjsonlib.create_node_object("device", properties=props))


    def get_services(self):
        """Parse service scan xml output"""
        for host in self.root.findall("host"):
            for port in host.find("ports").findall("port"):
                banner = ""
                port_id = port.get("portid")
                state = port.find("state").get("state")
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
                props = {"port": port_id, "name": port_id, "state": state, "serviceType": f"serviceType{service.capitalize()}"}
                if banner: props["version"] = banner
                self.ptjsonlib.add_node(self.ptjsonlib.create_node_object("service", properties=props))

    def get_ports(self):
        for host in self.root.findall("host"):
            ports = []
            for port in host.find("ports").findall("port"):
                port_id = port.get("portid")
                state = "portState" + port.find("state").get("state").capitalize()
                reason = port.find("state").get("reason")
                service = port.find("service")
                if service is not None:
                    name = port.find("service").get("name")
                    service = "serviceType" + name.capitalize()
                props = {"name": name, "port": port_id, "portState": state, "serviceType": service}
                self.ptjsonlib.add_node(self.ptjsonlib.create_node_object("service", properties=props))
        return ports

    def get_elapsed_time(self):
        return self.root.find("runstats").find("finished").get("elapsed")

    def get_input_args(self):
        """Retrieve nmap input args"""
        return self.root.get("args")

    def get_summary(self):
        """Retrieve nmap summary"""
        return self.root.find("runstats").find("finished").get("summary")