# -*- coding: utf-8 -*-
import unittest

from smartmorphing import SmartMorphing
from Trace import Trace
from tests.traffic_test import TrafficTest


class SmartMorphingTest(TrafficTest):
    TRACE_2_SRC = [
        [0, 10, 60],
        [0, 20, 90],
        [0, 30, 90],
        [0, 40, 170],
        [0, 50, 300],
    ]
    TRACE_2_DST = [
        [0, 10, 30],
        [0, 20, 80],
        [0, 30, 90],
        [0, 40, 160],
        [0, 50, 330],
        [0, 60, 380],
        [0, 70, 150],
        [0, 80, 20],
        [0, 90, 100],
        [0, 100, 130],
    ]

    def run_trace_morph_test(self, src, dst, exp, **kwargs):
        t1_src = Trace.create_from_array(1, src)
        t1_dst = Trace.create_from_array(1, dst)
        cm = SmartMorphing()
        for k, v in kwargs.items():
            cm.set_param(k, v)
        cm.dst_trace = t1_dst
        t2 = cm.apply_to_trace(t1_src)
        self.assertTraceEqual(t2, exp)

    def test_simple_morphing_dst(self):
        # try to match DST times if possible (i.e. src is not delayed), trying to respect inter-packet timing
        #   of dst in case of multiple available packets
        src = [
            [0, 70, 300],
            [0, 72, 100],
            [0, 80, 600],
        ]
        dst = [
            [0, 68, 200],
            [0, 73, 250],
            [0, 76, 300],
            [0, 77, 400],
            [0, 79, 300],
        ]
        expected_trace = [
            (0, 70, 200),       # 1, src delay
            (0, 73, 250),       # 1, match dst
            (0, 76, 300),       # 2, match dst
            (0, 80, 400),       # 3, src delay
            (0, 82, 300),       # 3, match dst timing
        ]
        self.run_trace_morph_test(src, dst, expected_trace, D=4, TIMING_METHOD='DST')

    def test_simple_morphing_min(self):
        # Trying to minimize latency and sending ASAP, using min inter-packet latency for queuing
        src = [
            [0, 70, 300],
            [0, 72, 100],
            [0, 80, 600],
        ]
        dst = [
            [0, 68, 200],
            [0, 73, 250],
            [0, 76, 300],
            [0, 77, 400],
            [0, 80, 300],
        ]
        expected_trace = [
            (0, 70, 200),       # 1,
            (0, 72, 250),       # 1,
            (0, 74, 300),       # 2,
            (0, 80, 400),       # 3,
            (0, 83, 300),       # 3,
        ]
        self.run_trace_morph_test(src, dst, expected_trace, D=4, TIMING_METHOD='MIN', DEFAULT_PAUSE=2)

    def test_small_dst_trace(self):
        # If there are fewer packets in dst trace than src trace, the dst trace is copied
        src = [
            [0, 70, 300],
            [0, 71, 100],
            [0, 72, 10],
            [0, 73, 20],
            [0, 74, 30],
            [0, 75, 40],
        ]
        dst = [
            [0, 68, 200],
            [0, 71, 250],
            [0, 73, 300],
        ]
        exp = [
            (0, 70, 200),   # 1,
            (0, 71, 250),   # 1,
            (0, 73, 300),   # 2,
            (0, 75, 200),   # 3, adding DEFAULT_PAUSE after block copy
            (0, 78, 250),   # 4, respecting inter-packet latency for steps
            (0, 80, 300),   # 5,
            (0, 82, 200),   # 6,
        ]
        self.run_trace_morph_test(src, dst, exp, D=4, TIMING_METHOD='DST', DEFAULT_PAUSE=2)

    def test_long_dst_overhead_check(self):
        """ If the dst is much longer, src is morphed util a threshold of similarity with dst is reached
        """
        src = [
            [0, 70, 300],
            [0, 72, 100],
            [0, 80, 200],
        ]
        dst = [
            [0, 68, 200],
            [0, 73, 250],
            [0, 76, 300],
            [0, 77, 400],
            [0, 81, 300],
            [0, 82, 700],
            [0, 83, 40],
            [0, 84, 50],
            [0, 85, 60],
        ]
        expected_trace = [
            (0, 70, 200),       # 1, ok
            (0, 73, 250),       # 1, ok
            (0, 76, 300),       # 2, ok
            (0, 80, 400),       # 3, ok
            (0, 81, 300),       # -, ok
            (0, 82, 700),       # -, OV-reached
            (0, 83, 40),        # -, OV-ok   (JC=.62)
            (0, 84, 50),        # -, OV-ok   (JC=.75)
                                #    OV-drop (JC=.88)
        ]
        self.run_trace_morph_test(src, dst, expected_trace, D=6, TIMING_METHOD='DST', MIN_JACCARD_SIMILARITY=0.8)


if __name__ == '__main__':
    unittest.main()
