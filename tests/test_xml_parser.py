import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ptnmap.modules.xml_parser import XmlParser


class FakePtJsonLib:
    def __init__(self):
        self.nodes = []
        self.next_id = 1
        self.json_object = {"results": {"properties": {}}}

    def create_node_object(self, node_type, parent_type=None, parent=None, properties=None, **kwargs):
        node = {
            "type": node_type,
            "key": f"node-{self.next_id}",
            "parent": parent,
            "parentType": parent_type,
            "properties": properties or {},
            "vulnerabilities": [],
        }
        self.next_id += 1
        return node

    def add_node(self, node):
        self.nodes.append(node)

    def add_properties(self, properties):
        self.json_object["results"]["properties"].update(properties)

    def end_error(self, message, use_json):
        raise AssertionError(message)


def port_scan_args():
    return SimpleNamespace(
        target="192.168.1.0/24",
        scan_live=False,
        scan_service=False,
        scan_os=False,
        scan_port_connect=False,
        scan_port_syn=True,
        scan_port_udp=False,
    )


def service_scan_args():
    args = port_scan_args()
    args.scan_service = True
    args.scan_port_connect = False
    args.scan_port_syn = False
    args.scan_port_udp = False
    return args


def live_scan_args():
    args = port_scan_args()
    args.scan_live = True
    args.scan_port_syn = False
    return args


class XmlParserPortScanTest(unittest.TestCase):
    def parse_nodes(self, xml, args=None):
        ptjsonlib = FakePtJsonLib()
        XmlParser(xml, ptjsonlib, False).parse_results(args or port_scan_args())
        return ptjsonlib.nodes

    def test_port_scan_adds_devices_and_child_services_for_multiple_hosts(self):
        xml = """<nmaprun>
<host>
  <status state="up"/>
  <address addr="192.168.1.10" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="9.6"/>
    </port>
    <port protocol="tcp" portid="23">
      <state state="closed" reason="reset"/>
    </port>
  </ports>
</host>
<host>
  <status state="up"/>
  <address addr="192.168.1.11" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http"/>
    </port>
  </ports>
</host>
<runstats><finished elapsed="1" summary="ok"/></runstats>
</nmaprun>"""

        nodes = self.parse_nodes(xml)

        self.assertEqual([node["type"] for node in nodes], [
            "device", "net_interface", "ip_address", "service",
            "device", "net_interface", "ip_address", "service",
        ])
        self.assertEqual(nodes[0]["properties"], {"name": "192.168.1.10"})
        self.assertEqual(nodes[2]["properties"]["name"], "192.168.1.10")
        self.assertEqual(nodes[3]["parentType"], "device")
        self.assertEqual(nodes[3]["parent"], nodes[0]["key"])
        self.assertEqual(nodes[3]["properties"]["name"], "22 (SSH)")
        self.assertEqual(nodes[3]["properties"]["port"], "22")
        self.assertEqual(nodes[3]["properties"]["serviceType"], "serviceTypeSSH")
        self.assertEqual(nodes[3]["properties"]["version"], "OpenSSH9.6")
        self.assertEqual(nodes[4]["properties"], {"name": "192.168.1.11"})
        self.assertEqual(nodes[7]["parentType"], "device")
        self.assertEqual(nodes[7]["parent"], nodes[4]["key"])
        self.assertEqual(nodes[7]["properties"]["name"], "80 (HTTP)")
        self.assertEqual(nodes[7]["properties"]["port"], "80")
        self.assertEqual(nodes[7]["properties"]["serviceType"], "serviceTypeHttps")

    def test_port_scan_keeps_device_when_host_has_no_ports(self):
        xml = """<nmaprun>
<host>
  <status state="up"/>
  <address addr="192.168.1.12" addrtype="ipv4"/>
</host>
<runstats><finished elapsed="1" summary="ok"/></runstats>
</nmaprun>"""

        nodes = self.parse_nodes(xml)

        self.assertEqual(len(nodes), 3)
        self.assertEqual(nodes[0]["type"], "device")
        self.assertEqual(nodes[0]["properties"], {"name": "192.168.1.12"})
        self.assertEqual(nodes[1]["type"], "net_interface")
        self.assertEqual(nodes[1]["properties"], {"name": "Net interface"})

    def test_live_scan_adds_adapter_and_ip_address_children(self):
        xml = """<nmaprun>
<host>
  <status state="up"/>
  <address addr="192.168.1.1" addrtype="ipv4"/>
  <address addr="FC:22:F4:E3:83:F4" addrtype="mac" vendor="Zyxel Communications"/>
</host>
<runstats><finished elapsed="1" summary="ok"/></runstats>
</nmaprun>"""

        nodes = self.parse_nodes(xml, live_scan_args())

        self.assertEqual([node["type"] for node in nodes], ["device", "net_interface", "ip_address"])
        self.assertFalse(nodes[0]["autoAddChildren"])
        self.assertEqual(nodes[0]["properties"], {"name": "192.168.1.1"})
        self.assertEqual(nodes[1]["parent"], nodes[0]["key"])
        self.assertIsNone(nodes[1]["parentType"])
        self.assertFalse(nodes[1]["autoAddChildren"])
        self.assertEqual(nodes[1]["properties"], {
            "name": "FC:22:F4:E3:83:F4",
            "macAddress": "FC:22:F4:E3:83:F4",
            "vendor": "Zyxel Communications",
        })
        self.assertEqual(nodes[2]["parent"], nodes[1]["key"])
        self.assertIsNone(nodes[2]["parentType"])
        self.assertFalse(nodes[2]["autoAddChildren"])
        self.assertEqual(nodes[2]["properties"], {
            "name": "192.168.1.1",
            "ip_address": "192.168.1.1",
            "ip_address_type": "ipAddressTypeIPv4",
        })

    def test_single_target_port_scan_returns_only_top_level_services(self):
        xml = """<nmaprun>
<host>
  <status state="up"/>
  <address addr="192.168.1.118" addrtype="ipv4"/>
  <address addr="EE:DC:B5:BB:44:07" addrtype="mac"/>
  <ports>
    <port protocol="tcp" portid="53">
      <state state="open" reason="syn-ack"/>
      <service name="domain"/>
    </port>
  </ports>
</host>
<runstats><finished elapsed="1" summary="ok"/></runstats>
</nmaprun>"""
        args = port_scan_args()
        args.target = "192.168.1.118"

        nodes = self.parse_nodes(xml, args)

        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["type"], "service")
        self.assertIsNone(nodes[0]["parent"])
        self.assertIsNone(nodes[0]["parentType"])
        self.assertEqual(nodes[0]["properties"], {
            "name": "53 (DHCP)",
            "port": "53",
            "protocol": "tcp",
            "portState": "portStateOpen",
            "serviceType": "serviceTypeDhcp",
        })

    def test_service_scan_maps_http_to_https_service_type(self):
        xml = """<nmaprun>
<host>
  <status state="up"/>
  <address addr="192.168.1.118" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http"/>
    </port>
  </ports>
</host>
<runstats><finished elapsed="1" summary="ok"/></runstats>
</nmaprun>"""

        nodes = self.parse_nodes(xml, service_scan_args())

        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["type"], "service")
        self.assertEqual(nodes[0]["properties"]["name"], "80 (HTTP)")
        self.assertEqual(nodes[0]["properties"]["serviceType"], "serviceTypeHttps")

    def test_udp_service_name_is_uppercase(self):
        xml = """<nmaprun>
<host>
  <status state="up"/>
  <address addr="192.168.1.118" addrtype="ipv4"/>
  <ports>
    <port protocol="udp" portid="427">
      <state state="open|filtered" reason="no-response"/>
      <service name="svrloc"/>
    </port>
  </ports>
</host>
<runstats><finished elapsed="1" summary="ok"/></runstats>
</nmaprun>"""
        args = port_scan_args()
        args.target = "192.168.1.118"
        args.scan_port_syn = False
        args.scan_port_udp = True

        nodes = self.parse_nodes(xml, args)

        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["properties"], {
            "name": "427 (SVRLOC)",
            "port": "427",
            "protocol": "udp",
            "portState": "portStateOpenFiltered",
        })


class XmlParserCurrentServiceTest(unittest.TestCase):
    XML = """<nmaprun><host><ports>
<port protocol="tcp" portid="25">
  <state state="open"/>
  <service name="smtp" product="Postfix" version="3.9"/>
</port>
</ports></host></nmaprun>"""

    def parse(self, args, xml=None):
        result = FakePtJsonLib()
        XmlParser(xml or self.XML, result, True).parse_results(args)
        return result

    def args(self):
        args = service_scan_args()
        args.target = "192.168.1.118"
        args.port = "25"
        return args

    def test_single_target_and_port_update_only_current_service_type(self):
        for target in ("192.168.1.118", "mail.example.com", "192.168.1.118/32", "::1"):
            with self.subTest(target=target):
                args = self.args()
                args.target = target
                result = self.parse(args)
                self.assertEqual(result.nodes, [])
                self.assertEqual(result.json_object["results"]["properties"], {
                    "serviceType": "serviceTypeSmtp",
                })

    def test_combined_service_and_port_scans_do_not_create_nodes(self):
        for scan in ("scan_port_connect", "scan_port_syn", "scan_port_udp"):
            with self.subTest(scan=scan):
                args = self.args()
                setattr(args, scan, True)
                result = self.parse(args)
                self.assertEqual(result.nodes, [])
                self.assertEqual(result.json_object["results"]["properties"], {
                    "serviceType": "serviceTypeSmtp",
                })

    def test_multi_port_and_default_scans_keep_service_nodes(self):
        for port in (None, "25,587", "1-1000", "T:25,U:25"):
            with self.subTest(port=port):
                args = self.args()
                args.port = port
                result = self.parse(args)
                self.assertEqual(len(result.nodes), 1)
                self.assertEqual(result.nodes[0]["properties"]["serviceType"], "serviceTypeSmtp")
                self.assertEqual(result.json_object["results"]["properties"], {})

    def test_multi_target_scans_keep_service_nodes(self):
        for target in ("192.168.1.0/24", "192.168.1.1-10", "192.168.1.*"):
            with self.subTest(target=target):
                args = self.args()
                args.target = target
                result = self.parse(args)
                self.assertEqual(len(result.nodes), 1)
                self.assertEqual(result.json_object["results"]["properties"], {})

    def test_port_scan_without_service_detection_keeps_service_node(self):
        args = self.args()
        args.scan_service = False
        args.scan_port_connect = True
        result = self.parse(args)
        self.assertEqual(len(result.nodes), 1)
        self.assertEqual(result.json_object["results"]["properties"], {})

    def test_absent_or_closed_service_does_not_add_properties(self):
        for xml in (
            "<nmaprun/>",
            "<nmaprun><host/></nmaprun>",
            self.XML.replace('state="open"', 'state="closed"'),
            self.XML.replace('<service name="smtp" product="Postfix" version="3.9"/>', ""),
        ):
            with self.subTest(xml=xml):
                result = self.parse(self.args(), xml)
                self.assertEqual(result.nodes, [])
                self.assertEqual(result.json_object["results"]["properties"], {})

    def test_protocol_qualified_single_port_updates_current_service(self):
        args = self.args()
        args.port = "T:25"
        result = self.parse(args)
        self.assertEqual(result.nodes, [])
        self.assertEqual(result.json_object["results"]["properties"], {
            "serviceType": "serviceTypeSmtp",
        })

    def test_unknown_service_returns_name_without_service_type_or_nodes(self):
        result = self.parse(self.args(), self.XML.replace('name="smtp"', 'name="custom-service"'))
        self.assertEqual(result.nodes, [])
        self.assertEqual(result.json_object["results"]["properties"], {
            "name": "25 (CUSTOM-SERVICE)",
        })


class XmlParserServiceMappingTest(unittest.TestCase):
    SERVICES = {
        "http": ("HTTP", "serviceTypeHttps"),
        "https": ("HTTPS", "serviceTypeHttps"),
        "smtp": ("SMTP", "serviceTypeSmtp"),
        "submissions": ("SMTP", "serviceTypeSmtp"),
        "imap": ("IMAP", "serviceTypeImap"),
        "pop3": ("POP3", "serviceTypePop3"),
        "dns": ("DNS", "serviceTypeDns"),
        "ftp": ("FTP", "serviceTypeFTP"),
        "ssh": ("SSH", "serviceTypeSSH"),
        "msrpc": ("MSRPC", "serviceTypeMsrpc"),
        "microsoft-ds": ("SMB", "serviceTypeSmb"),
        "netbios-ssn": ("NETBIOS", "serviceTypeNetbios"),
        "ms-wbt-server": ("RDP", "serviceTypeRdp"),
        "domain": ("DHCP", "serviceTypeDhcp"),
        "upnp": ("UPnP", "serviceTypeUpnp"),
        "snmp": ("SNMP", "serviceTypeSnmp"),
    }

    def parse(self, service, args):
        service_xml = f'<service name="{service}" product="Product" version="1.2" extrainfo="extra"/>' if service else ""
        xml = f'''<nmaprun><host><ports><port protocol="tcp" portid="80">
<state state="open"/>{service_xml}</port></ports></host></nmaprun>'''
        result = FakePtJsonLib()
        XmlParser(xml, result, True).parse_results(args)
        return result

    def test_all_mappings_in_service_and_port_nodes(self):
        for service, (name, service_type) in self.SERVICES.items():
            for scan_args in (service_scan_args, port_scan_args):
                with self.subTest(service=service, scan=scan_args.__name__):
                    args = scan_args()
                    args.target = "192.168.1.118"
                    result = self.parse(service, args)
                    self.assertEqual(len(result.nodes), 1)
                    properties = result.nodes[0]["properties"]
                    self.assertEqual(properties["name"], f"80 ({name})")
                    self.assertEqual(properties["serviceType"], service_type)
                    self.assertEqual(properties["version"], "Product1.2 (extra)")

    def test_all_mappings_in_current_node_properties(self):
        for service, (_, service_type) in self.SERVICES.items():
            with self.subTest(service=service):
                args = service_scan_args()
                args.target = "192.168.1.118"
                args.port = "80"
                result = self.parse(service, args)
                self.assertEqual(result.nodes, [])
                self.assertEqual(result.json_object["results"]["properties"], {
                    "serviceType": service_type,
                })

    def test_unmapped_and_absent_services_omit_service_type(self):
        for service in ("custom-service", None):
            for scan_args in (service_scan_args, port_scan_args):
                with self.subTest(service=service, scan=scan_args.__name__):
                    args = scan_args()
                    args.target = "192.168.1.118"
                    result = self.parse(service, args)
                    properties = result.nodes[0]["properties"]
                    self.assertEqual(properties["name"], "80 (CUSTOM-SERVICE)" if service else "80")
                    self.assertNotIn("serviceType", properties)

    def test_mapping_can_be_extended_by_editing_json(self):
        with tempfile.TemporaryDirectory() as directory:
            mapping_path = Path(directory) / "service_mapping.json"
            mapping_path.write_text(json.dumps({
                "custom-service": {"name": "Custom", "serviceType": "serviceTypeCustom"},
            }), encoding="utf-8")
            with patch("ptnmap.modules.xml_parser.Path", return_value=Path(directory) / "xml_parser.py"):
                args = service_scan_args()
                args.target = "192.168.1.118"
                result = self.parse("custom-service", args)
        self.assertEqual(result.nodes[0]["properties"]["name"], "80 (Custom)")
        self.assertEqual(result.nodes[0]["properties"]["serviceType"], "serviceTypeCustom")


if __name__ == "__main__":
    unittest.main()
