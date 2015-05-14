# -*- coding: utf-8 -*-
import copy

from Trace import Trace


class CounterMeasure(object):
    DEFAULT_PARAMS = {}

    def __init__(self, params=None):
        self.trace = None
        self.new_trace = None
        self.metadata = None
        self.model = None
        self.params = copy.deepcopy(self.DEFAULT_PARAMS)
        self.new_trace_size = 0
        if params:
            self.params.update(params)

    def set_param(self, parameter, value):
        self.params[parameter] = value
        self.update_params()

    def update_params(self):
        pass

    def train(self, src_page=None, target_page=None):
        pass

    def apply(self):
        """ Create a new trace by applying the countermeasure to the original trace

            The original trace is available in self.trace
            The modified trace should be saved in self.new_trace or returned
        """
        raise NotImplementedError

    def build_new_trace(self):
        self.new_trace = Trace(self.trace.getId())

    def add_packet(self, packet):
        # print packet.get_details()
        t = packet.getTime()
        self.new_trace_size += packet.size
        ind = len(self.new_trace.packets)
        while 0 < ind and t < self.new_trace.packets[ind - 1].getTime():
            ind -= 1
        self.new_trace.add_packet(packet, index=ind)

    def get_new_trace_time(self):
        return self.new_trace.packets[-1].time if self.new_trace.packets else 0

    def get_new_trace_size(self):
        return self.new_trace_size

    def apply_to_trace(self, trace):
        self.trace = trace
        self.build_new_trace()
        t2 = self.apply()
        if t2 is None:
            t2 = self.new_trace
        return t2

    @classmethod
    def initialize(cls):
        pass

    @classmethod
    def get_name(cls):
        return 'Generic Countermeasure'
