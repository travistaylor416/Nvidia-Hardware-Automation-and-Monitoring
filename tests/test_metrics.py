"""
Metric parser tests.  Fixtures are representative hand-written samples modelled on the documented
output formats - NOT captures from real hardware.  Add real captures as you get them.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nvmon.metrics.parse import canonicalize, ib_state, parse_ib_sysfs  # noqa: E402
from nvmon.ssh import parse_batch, safe_token  # noqa: E402

ETHTOOL_M_OPTICAL = """
\tIdentifier                                : 0x11 (QSFP28)
\tTransmitter technology                    : 0x00 (850 nm VCSEL)
\tVendor name                               : NVIDIA
\tVendor PN                                 : MMA1B00-C100D
\tModule temperature                        : 41.00 degrees C / 105.80 degrees F
\tModule voltage                            : 3.2970 V
\tLaser tx bias current (Channel 1)         : 6.750 mA
\tTransmit avg optical power (Channel 1)    : 0.7600 mW / -1.19 dBm
\tTransmit avg optical power (Channel 2)    : 0.7500 mW / -1.25 dBm
\tRcvr signal avg optical power(Channel 1)  : 0.0500 mW / -13.01 dBm
\tRcvr signal avg optical power(Channel 2)  : 0.6000 mW / -2.22 dBm
\tLaser rx power low alarm (Channel 1)      : On
\tLaser rx power low alarm (Channel 2)      : Off
\tLaser rx power low alarm threshold        : 0.0490 mW / -13.10 dBm
\tLaser rx power low warning threshold      : 0.0980 mW / -10.09 dBm
\tLaser output power low alarm threshold    : 0.1550 mW / -8.10 dBm
\tModule temperature high alarm threshold   : 75.00 degrees C / 167.00 degrees F
"""

ETHTOOL_M_DAC = """
\tIdentifier                                : 0x11 (QSFP28)
\tConnector                                 : 0x23 (No separable connector)
\tTransmitter technology                    : 0xa0 (Copper cable unequalized)
\tVendor name                               : NVIDIA
"""

ETHTOOL_S_MLX5 = """NIC statistics:
     rx_packets: 1000
     rx_crc_errors_phy: 12
     rx_symbol_err_phy: 3
     rx_corrected_bits_phy: 5000
     link_down_events_phy: 2
     tx_errors_phy: 0
"""

NVOS_COUNTERS_JSON = """{"symbol-errors": 4, "link-downed": 1, "link-error-recovery": 0,
 "port-rcv-errors": 2, "port-xmit-discards": 0, "local-link-integrity-errors": 0,
 "effective-ber": "1e-15", "raw-ber": "3e-6"}"""

MLXLINK = """
Operational Info
----------------
State                           : Active
Physical state                  : LinkUp
Physical Counters and BER Info
------------------------------
Effective Physical BER          : 15E-255
Raw Physical BER                : 1E-8
Link Down Counter               : 1
Link Error Recovery Counter     : 0
Module Info
-----------
Temperature [C]                 : 45
Rx Power Current [dBm]          : -2.1,-2.3,-11.5,-2.2
Tx Power Current [dBm]          : 1.1,1.0,1.2,1.1
Vendor Name                     : NVIDIA
Cable Type                      : Optical Module
"""

SYSFS = """/sys/class/infiniband/mlx5_0/ports/1/state:4: ACTIVE
/sys/class/infiniband/mlx5_0/ports/1/phys_state:5: LinkUp
/sys/class/infiniband/mlx5_0/ports/1/rate:400 Gb/sec (4X NDR)
/sys/class/infiniband/mlx5_0/ports/1/link_layer:InfiniBand
/sys/class/infiniband/mlx5_0/ports/1/counters/symbol_error:7
/sys/class/infiniband/mlx5_0/ports/1/counters/link_downed:1
/sys/class/infiniband/mlx5_0/ports/1/counters/port_rcv_errors:3
/sys/class/infiniband/mlx5_0/ports/1/counters/port_rcv_data:123456
/sys/class/infiniband/mlx5_1/ports/1/state:1: DOWN
/sys/class/infiniband/mlx5_1/ports/1/phys_state:2: Polling
"""


class CanonicalizeTests(unittest.TestCase):
    def test_ethtool_module_optical(self):
        b = canonicalize(ETHTOOL_M_OPTICAL)
        self.assertEqual(b["media"], "optical")
        self.assertEqual(b["dom"]["rx_power_dbm"], [-13.01, -2.22])
        self.assertEqual(b["dom"]["tx_power_dbm"], [-1.19, -1.25])
        self.assertEqual(b["dom"]["temperature_c"], [41.0])
        self.assertAlmostEqual(b["dom"]["voltage_v"][0], 3.297)
        self.assertEqual(b["dom"]["tx_bias_ma"], [6.75])
        self.assertEqual(b["thresholds"]["rx_power_dbm_low_alarm"], -13.10)
        self.assertEqual(b["thresholds"]["rx_power_dbm_low_warn"], -10.09)
        self.assertEqual(b["thresholds"]["tx_power_dbm_low_alarm"], -8.10)
        self.assertEqual(b["thresholds"]["temperature_c_high_alarm"], 75.0)
        self.assertEqual(len(b["alarms"]), 1)
        self.assertEqual(b["module"], {"identifier": "0x11 (QSFP28)", "vendor": "NVIDIA", "part": "MMA1B00-C100D"})

    def test_ethtool_module_dac(self):
        self.assertEqual(canonicalize(ETHTOOL_M_DAC)["media"], "copper")

    def test_ethtool_stats_mlx5(self):
        c = canonicalize(ETHTOOL_S_MLX5)["counters"]
        self.assertEqual(c["crc_errors"], 12)
        self.assertEqual(c["symbol_errors"], 3)
        self.assertEqual(c["fec_corrected"], 5000)
        self.assertEqual(c["link_downed"], 2)
        self.assertNotIn("rx_errors", c)

    def test_nvos_json(self):
        b = canonicalize(NVOS_COUNTERS_JSON)
        self.assertEqual(b["counters"]["symbol_errors"], 4)
        self.assertEqual(b["counters"]["link_downed"], 1)
        self.assertEqual(b["counters"]["rx_errors"], 2)
        self.assertEqual(b["counters"]["tx_discards"], 0)
        self.assertEqual(b["ber"], {"effective_ber": 1e-15, "raw_ber": 3e-6})

    def test_nested_json_counters(self):
        b = canonicalize('{"counters": {"rx": {"errors": 5}, "in-fcs-errors": 9}}')
        self.assertEqual(b["counters"]["rx_errors"], 5)
        self.assertEqual(b["counters"]["crc_errors"], 9)

    def test_mlxlink(self):
        b = canonicalize(MLXLINK)
        self.assertEqual(b["dom"]["rx_power_dbm"], [-2.1, -2.3, -11.5, -2.2])
        self.assertEqual(b["dom"]["tx_power_dbm"], [1.1, 1.0, 1.2, 1.1])
        self.assertEqual(b["dom"]["temperature_c"], [45.0])
        self.assertEqual(b["ber"]["raw_ber"], 1e-8)
        self.assertEqual(b["counters"]["link_downed"], 1)
        self.assertEqual(b["counters"]["link_error_recovery"], 0)
        self.assertEqual(b["media"], "optical")

    def test_ib_sysfs(self):
        ports = parse_ib_sysfs(SYSFS)
        p = ports[("mlx5_0", "1")]
        self.assertEqual(ib_state(p["state"], p["phys_state"]), "up")
        self.assertEqual(p["link_layer"], "InfiniBand")
        c = canonicalize(p["counters_text"])["counters"]
        self.assertEqual((c["symbol_errors"], c["link_downed"], c["rx_errors"]), (7, 1, 3))
        down = ports[("mlx5_1", "1")]
        self.assertEqual(ib_state(down["state"], down["phys_state"]), "down")

    def test_absent_module(self):
        self.assertEqual(canonicalize("Module status : Not present\n")["media"], "absent")


class SSHHelpersTests(unittest.TestCase):
    def test_parse_batch(self):
        text = "@@NVMON@@ 0\nhello\n@@NVMON@@ rc 0\n@@NVMON@@ 1\nnope\n@@NVMON@@ rc 127\n"
        self.assertEqual(parse_batch(text, 3), [(0, "hello"), (127, "nope"), None])

    def test_safe_token(self):
        self.assertEqual(safe_token("mlx5_0"), "mlx5_0")
        for bad in ("swp1; rm -rf /", "$(id)", "a b", ""):
            with self.assertRaises(ValueError):
                safe_token(bad)


if __name__ == "__main__":
    unittest.main()
