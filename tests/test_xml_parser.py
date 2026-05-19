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

        self.assertEqual([node["type"] for node in nodes], ["device", "service", "device", "service"])
        self.assertEqual(nodes[0]["properties"]["ipAddress"], "192.168.1.10")
        self.assertEqual(nodes[1]["parentType"], "device")
        self.assertEqual(nodes[1]["parent"], nodes[0]["key"])
        self.assertEqual(nodes[1]["properties"]["port"], "22")
        self.assertEqual(nodes[1]["properties"]["serviceType"], "serviceTypeSsh")
        self.assertEqual(nodes[1]["properties"]["version"], "OpenSSH9.6")
        self.assertEqual(nodes[2]["properties"]["ipAddress"], "192.168.1.11")
        self.assertEqual(nodes[3]["parentType"], "device")
        self.assertEqual(nodes[3]["parent"], nodes[2]["key"])
        self.assertEqual(nodes[3]["properties"]["port"], "80")

    def test_port_scan_keeps_device_when_host_has_no_ports(self):
        xml = """<nmaprun>
<host>
  <status state="up"/>
  <address addr="192.168.1.12" addrtype="ipv4"/>
</host>
<runstats><finished elapsed="1" summary="ok"/></runstats>
</nmaprun>"""

        nodes = self.parse_nodes(xml)

        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["type"], "device")
        self.assertEqual(nodes[0]["properties"]["ipAddress"], "192.168.1.12")

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
        self.assertEqual(nodes[0]["parentType"], "device")
        self.assertEqual(nodes[0]["properties"], {
            "name": "domain",
            "port": "53",
            "protocol": "tcp",
            "portState": "portStateOpen",
            "serviceType": "serviceTypeDomain",
        })


if __name__ == "__main__":
    unittest.main()
