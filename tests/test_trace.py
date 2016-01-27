# Copyright (C) 2012  Kevin P. Dyer (kpdyer.com)
# See LICENSE for more details.

import unittest

import pcapparser
from Trace import Trace
from Packet import Packet


class PcapParserTestCase(unittest.TestCase):
    def test_readfile(self):
        actualTrace = pcapparser.readfile(month=3, day=14, hour=22, webpageId=8)

        expected_trace = Trace(8)
        expected_trace.addPacket(Packet(Packet.UP, 0, 148))
        expected_trace.addPacket(Packet(Packet.DOWN, 0, 100))
        expected_trace.addPacket(Packet(Packet.UP, 0, 52))
        expected_trace.addPacket(Packet(Packet.UP, 3, 500))
        expected_trace.addPacket(Packet(Packet.DOWN, 18, 244))
        expected_trace.addPacket(Packet(Packet.UP, 35, 436))
        expected_trace.addPacket(Packet(Packet.DOWN, 75, 52))
        expected_trace.addPacket(Packet(Packet.DOWN, 118, 292))
        expected_trace.addPacket(Packet(Packet.UP, 158, 52))

        self.assertListEqual(actualTrace.packets, expected_trace.packets)


if __name__ == '__main__':
    unittest.main()
