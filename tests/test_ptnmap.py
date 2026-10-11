import contextlib
import io
import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ptnmap.ptnmap import PtNmap


class PtNmapServiceOutputTest(unittest.TestCase):
    def test_single_service_scan_returns_expected_json(self):
        args = SimpleNamespace(
            target="192.168.1.118", port="25", json=True,
            scan_service=True, scan_live=False, scan_os=False,
            scan_port_connect=False, scan_port_syn=False, scan_port_udp=False,
            ping_echo=False, ping_syn=False,
        )

        def scan(command, **kwargs):
            self.assertEqual(command[1:-2], ["-sV", "-p", "25", args.target])
            with open(command[-1], "w") as output:
                output.write('''<nmaprun><host><ports>
<port protocol="tcp" portid="25">
  <state state="open"/>
  <service name="smtp" product="Postfix" version="3.9"/>
</port>
</ports></host></nmaprun>''')
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        output = io.StringIO()
        with patch("ptnmap.ptnmap.subprocess.run", side_effect=scan):
            with contextlib.redirect_stdout(output):
                PtNmap(args).run(args, nmap_path="/usr/bin/nmap")

        self.assertEqual(json.loads(output.getvalue()), {
            "satid": "", "guid": "", "status": "finished", "message": "",
            "results": {
                "nodes": [],
                "properties": {"serviceType": "serviceTypeSmtp"},
                "vulnerabilities": [],
            },
        })


if __name__ == "__main__":
    unittest.main()
