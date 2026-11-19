"""
Parser tests - run with:  python -m unittest discover -s tests -v

The sample outputs below are representative, hand-written examples, NOT captures from real
hardware.  When you have access to a switch/server, paste real output into new test cases so
the parsers are pinned to your NVOS / Cumulus / Ubuntu releases.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nvmon.checks import server as sc  # noqa: E402
from nvmon.checks import switch as sw  # noqa: E402
from nvmon.inventory import FabricAddress, device_from_row  # noqa: E402
from nvmon.models import FAIL, PASS, WARN  # noqa: E402
from nvmon.settings import Settings  # noqa: E402

S = Settings()


class InventoryTests(unittest.TestCase):
    def test_row(self):
        d = device_from_row(settings=S, row={"Name": "dgx-a01", "OS": "DGX OS", "Mgmt Address": "10.0.0.1",
                             "Fabric Addresses": "ens1f0np0=10.100.0.11/24; 10.100.1.11"})
        self.assertEqual((d.os, d.role, d.hostname), ("ubuntu", "server", "dgx-a01"))
        self.assertEqual(d.fabric_addresses[0], FabricAddress("10.100.0.11", 24, "ens1f0np0"))
        self.assertEqual(d.fabric_addresses[1], FabricAddress("10.100.1.11", None, None))

    def test_bad_os(self):
        with self.assertRaises(ValueError):
            device_from_row(settings=S, row={"Name": "x", "OS": "onyx", "Mgmt Address": "1.1.1.1"})


class ServerParserTests(unittest.TestCase):
    def test_resolv_conf(self):
        text = "# generated\nnameserver 127.0.0.53\noptions edns0\nsearch example.com\n"
        self.assertEqual(sc.parse_resolv_conf(text), ["127.0.0.53"])

    def test_resolvectl_dns(self):
        text = "Global:\nLink 2 (eno1): 10.10.10.10 10.10.10.20\nLink 3 (ens1f0np0):\n"
        self.assertEqual(sc.parse_resolvectl(text), ["10.10.10.10", "10.10.10.20"])

    def test_resolvectl_status_block(self):
        text = ("Link 2 (eno1)\n    Current Scopes: DNS\nCurrent DNS Server: 10.10.10.10\n"
                "       DNS Servers: 10.10.10.10\n                    10.10.10.20#dns2.example.com\n"
                "        DNS Domain: example.com\n")
        self.assertEqual(sc.parse_resolvectl(text), ["10.10.10.10", "10.10.10.20"])

    def test_compare_dns(self):
        exp = ["10.10.10.10", "10.10.10.20"]
        self.assertEqual(sc.compare_dns(exp, exp)[0], PASS)
        self.assertEqual(sc.compare_dns(["10.10.10.10"], exp)[0], WARN)
        self.assertEqual(sc.compare_dns(["8.8.8.8"], exp)[0], FAIL)
        self.assertEqual(sc.compare_dns([], exp)[0], FAIL)

    def test_ipmitool(self):
        text = ("Set in Progress         : Set Complete\nIP Address Source       : Static Address\n"
                "IP Address              : 10.20.1.11\nSubnet Mask             : 255.255.255.0\n"
                "MAC Address             : 3c:ec:ef:00:11:22\nDefault Gateway IP      : 10.20.1.1\n")
        lan = sc.parse_ipmitool_lan(text)
        self.assertEqual(lan["ip"], "10.20.1.11")
        self.assertEqual(lan["mac"], "3c:ec:ef:00:11:22")
        self.assertEqual(lan["source"], "Static Address")

    def test_ip_brief(self):
        text = ("lo               UNKNOWN        127.0.0.1/8 ::1/128\n"
                "ens1f0np0        UP             10.100.0.11/24 fe80::1/64\n"
                "ens2f0np0        DOWN           \n"
                "vlan10@bond0     UP             10.30.0.5/24\n")
        ifs = sc.parse_ip_brief(text)
        self.assertEqual(ifs["ens1f0np0"]["addrs"][0], "10.100.0.11/24")
        self.assertEqual(ifs["ens2f0np0"]["state"], "DOWN")
        self.assertIn("vlan10", ifs)

    def test_ibdev2netdev(self):
        rows = sc.parse_ibdev2netdev("mlx5_0 port 1 ==> ibp12s0 (Up)\nmlx5_4 port 1 ==> ens1f0np0 (Down)\n")
        self.assertEqual(rows[1], {"hca": "mlx5_4", "port": "1", "netdev": "ens1f0np0", "state": "Down"})


class SwitchParserTests(unittest.TestCase):
    def test_nvos_json(self):
        data = {
            "eth0": {"link": {"state": "up"}, "type": "eth"},
            "sw1p1": {"link": {"logical-state": "Active", "physical-state": "LinkUp", "speed": "400G"}, "type": "ib"},
            "sw2p1": {"link": {"logical-state": "Down", "physical-state": "Polling"}, "type": "ib"},
            "sw3p1": {"link": {"logical-state": "Initialize", "physical-state": "LinkUp"}, "type": "ib"},
        }
        ports = {p["name"]: p for p in sw.parse_interface_json(data)}
        self.assertEqual(ports["sw1p1"]["oper"], "up")
        self.assertEqual(ports["sw2p1"]["oper"], "down")
        self.assertEqual(ports["sw3p1"]["oper"], "init")
        self.assertTrue(sw.is_data_port("sw3p1", "nvos", S))
        self.assertFalse(sw.is_data_port("eth0", "nvos", S))

    def test_cumulus_json_admin_vs_oper(self):
        data = {
            "swp1": {"link": {"state": {"up": {}}, "oper-status": "up"}, "type": "swp"},
            "swp2": {"link": {"state": {"up": {}}, "oper-status": "down"}, "type": "swp"},
            "swp3": {"link": {"state": {"down": {}}, "oper-status": "down"}, "type": "swp"},
        }
        ports = {p["name"]: p for p in sw.parse_interface_json(data)}
        self.assertEqual((ports["swp1"]["oper"], ports["swp1"]["admin"]), ("up", "up"))
        self.assertEqual((ports["swp2"]["oper"], ports["swp2"]["admin"]), ("down", "up"))
        self.assertEqual((ports["swp3"]["oper"], ports["swp3"]["admin"]), ("down", "down"))

    def test_table_fallback(self):
        text = ("Interface  Admin Status  Oper Status  Speed  MTU   Type  Remote Host  Remote Port  Summary\n"
                "---------  ------------  -----------  -----  ----  ----  -----------  -----------  -------\n"
                "eth0       up            up           1G     1500  eth                             IP: 10.0.0.1/24\n"
                "swp1       up            up           100G   9216  swp   leaf02       swp1\n"
                "swp2       up            down                9216  swp\n"
                "swp3       down          down                9216  swp\n")
        ports = {p["name"]: p for p in sw.parse_interface_table(text)}
        self.assertEqual(ports["swp1"]["oper"], "up")
        self.assertEqual(ports["swp2"]["oper"], "down")
        self.assertEqual(ports["swp3"]["admin"], "down")

    def test_hints(self):
        port = {"name": "swp2", "oper": "down", "admin": "up"}
        hints = sw.analyze_port(port, {"nv show interface swp2 pluggable": "Module: not present"})
        self.assertTrue(any("No cable" in h for h in hints))
        init = sw.analyze_port({"name": "sw3p1", "oper": "init", "admin": "up"}, {})
        self.assertTrue(any("Subnet Manager" in h for h in init))

    def test_port_sort(self):
        names = ["sw10p1", "sw2p1", "sw1p2", "sw1p1"]
        self.assertEqual(sorted(names, key=sw.port_sort_key), ["sw1p1", "sw1p2", "sw2p1", "sw10p1"])


if __name__ == "__main__":
    unittest.main()
