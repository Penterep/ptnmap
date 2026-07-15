import unittest
from types import SimpleNamespace

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
            "device", "net_adapter", "ip_address", "service",
            "device", "net_adapter", "ip_address", "service",
        ])
        self.assertEqual(nodes[0]["properties"], {"name": "192.168.1.10"})
        self.assertEqual(nodes[2]["properties"]["name"], "192.168.1.10")
        self.assertEqual(nodes[3]["parentType"], "device")
        self.assertEqual(nodes[3]["parent"], nodes[0]["key"])
        self.assertEqual(nodes[3]["properties"]["port"], "22")
        self.assertEqual(nodes[3]["properties"]["serviceType"], "serviceTypeSsh")
        self.assertEqual(nodes[3]["properties"]["version"], "OpenSSH9.6")
        self.assertEqual(nodes[4]["properties"], {"name": "192.168.1.11"})
        self.assertEqual(nodes[7]["parentType"], "device")
        self.assertEqual(nodes[7]["parent"], nodes[4]["key"])
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

        self.assertEqual([node["type"] for node in nodes], ["device", "net_adapter", "ip_address"])
        self.assertEqual(nodes[0]["properties"], {"name": "192.168.1.1"})
        self.assertEqual(nodes[1]["parent"], nodes[0]["key"])
        self.assertIsNone(nodes[1]["parentType"])
        self.assertEqual(nodes[1]["properties"], {
            "name": "Net interface",
            "macAddress": "FC:22:F4:E3:83:F4",
            "vendor": "Zyxel Communications",
        })
        self.assertEqual(nodes[2]["parent"], nodes[1]["key"])
        self.assertIsNone(nodes[2]["parentType"])
        self.assertEqual(nodes[2]["properties"], {
            "name": "192.168.1.1",
            "ip_address_type": "ipAddressTypeIPv4",
            "vendor": "Zyxel Communications",
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
            "name": "domain",
            "port": "53",
            "protocol": "tcp",
            "portState": "portStateOpen",
            "serviceType": "serviceTypeDomain",
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
        self.assertEqual(nodes[0]["properties"]["serviceType"], "serviceTypeHttps")


if __name__ == "__main__":
    unittest.main()
