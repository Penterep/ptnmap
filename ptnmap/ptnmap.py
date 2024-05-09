#!/usr/bin/python3
"""
    Copyright (c) 2024 Penterep Security s.r.o.

    ptnmap is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptnmap is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptnmap.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import re
import subprocess
import site
import tempfile
import sys
sys.path.append(__file__.rsplit("/", 1)[0])
sys.path.append(f"/home/kali/.local/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")

from _version import __version__
from ptlibs import ptprinthelper, ptmisclib, ptjsonlib

from modules import xml_parser


class PtNmap:
    def __init__(self, args):
        self.ptjsonlib = ptjsonlib.PtJsonLib()
        self.use_json  = args.json

    def run(self, args: dict, nmap_path: str):
        """Run ptnmap scan with provided args"""
        try:
            with tempfile.NamedTemporaryFile(suffix=".xml", prefix="ptnmap_") as file:
                process = subprocess.run([nmap_path, *self.get_nmap_args(args), "-oX", file.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if process.returncode != 0:
                    raise Exception(process.stderr)
                result_xml = file.read().decode("utf-8")
                output_parser = xml_parser.XmlParser(result_xml, self.ptjsonlib, self.use_json)
                output_parser.parse_results(args)
        except Exception as e:
            self.ptjsonlib.end_error(str(e).replace("\n", " "), self.use_json)

        self.ptjsonlib.set_status("finished")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())

    def get_nmap_args(self, args):
        nmap_args = []
        if args.scan_live:
            nmap_args.append("-sn")
        if args.scan_os:
            nmap_args.append("-O")
        if args.scan_service:
            nmap_args.append("-sV")
        if args.scan_port_connect:
            nmap_args.append("-sT")
        if args.scan_port_syn:
            nmap_args.append("-sS")
        if args.port:
            nmap_args.append(f"-p {args.port}")
        nmap_args.append(args.target)
        return nmap_args


def get_help():
    return [
        {"description": ["Use the tool the same way as you would use nmap"]},
        {"usage": ["ptnmap <options>"]},
        {"usage_example": [
            ["ptnmap -sn -t 192.168.0.0/24"],
            ["ptnmap -sT -t 192.168.0.1 -p 1-1000"],
            ["ptnmap -sT -t 192.168.0.1 -sV"],
        ]},
        {"Scan options": [
            ["-sn", "--scan-live",           "",             "Do live device scan / portsweep / no service detection"],
            ["-sV", "--scan-service",        "",             "Do service scan / service banner grabber"],
            ["-O",  "--scan-os",             "",             "Do OS scan / detect target's OS,  root access required"],
            ["-sT", "--scan-port-connect",   "",             "Do port scan (TCP Connect)"],
            ["-sS", "--scan-port-syn",       "",             "Do port scan (TCP Syn / Stealth), root access required"],
        ]
         },
        {"options": [
            ["-t",  "--target",           "<target>",     "Set target"],
            ["-p",  "--port",             "<port>",       "Set port(s)"],
            ["-v",  "--version",          "",             "Show script version and exit"],
            ["-h",  "--help",             "",             "Show this help message and exit"],
            ["-j",  "--json",             "",             "Output in JSON format"],

        ]
        }]


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, usage=f"{SCRIPTNAME} <options>")
    exclusive = parser.add_mutually_exclusive_group(required=True)
    exclusive.add_argument("-sn", "--scan-live",         action="store_true")
    exclusive.add_argument("-sV", "--scan-service",      action="store_true")
    exclusive.add_argument("-O",  "--scan-os",           action="store_true")
    exclusive.add_argument("-sS", "--scan-port-syn",     action="store_true")
    exclusive.add_argument("-sT", "--scan-port-connect", action="store_true")
    parser.add_argument("-t",  "--target",       type=str)
    parser.add_argument("-p",  "--port",         type=str)
    parser.add_argument("-j",  "--json",         action="store_true", default=True)
    parser.add_argument("-v",  "--version",      action="version", version=f"{SCRIPTNAME} {__version__}")


    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptnmap"
    args = parse_args()
    script = PtNmap(args)
    script.run(args, nmap_path="/usr/bin/nmap")


if __name__ == "__main__":
    main()
