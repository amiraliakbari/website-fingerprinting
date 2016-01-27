"""
 This is a Python framework to compliment "Peek-a-Boo, I Still See You: Why
    Efficient Traffic Analysis Countermeasures Fail".

  Copyright (C) 2012  Kevin P. Dyer (http://kpdyer.com)
  See LICENSE for more details.
"""


class Packet(object):
    UP = 0
    DOWN = 1

    HEADER_ETHERNET = 0  # is actually 14 on the LAN
    HEADER_IP = 20
    HEADER_TCP_REQUIRED = 20
    HEADER_TCP_OPTIONAL = 12
    HEADER_TCP = HEADER_TCP_REQUIRED + HEADER_TCP_OPTIONAL

    # Packet format for SSHv1
    HEADER_SSH_PACKET_FIELD_LENGTH = 4
    HEADER_SSH_PACKET_TYPE = 1
    HEADER_SSH_PADDING = 7  # We already know that our payload is 0 mod 8
    HEADER_SSH_CRC = 4
    HEADER_SSH = HEADER_SSH_PACKET_FIELD_LENGTH + HEADER_SSH_PACKET_TYPE + HEADER_SSH_PADDING + HEADER_SSH_CRC

    HEADER_LENGTH = HEADER_ETHERNET + HEADER_IP + HEADER_TCP

    MTU = 1500 + HEADER_ETHERNET

    def __init__(self, direction, time, length):
        self.__direction = int(direction)
        self.__time = int(time)
        self.__length = int(length)

    def __eq__(self, other):
        return self.get_details() == other.get_details()

    def __unicode__(self):
        return '{}{} ({}ms)'.format('+' if self.__direction == self.UP else '-', self.__length, self.__time)

    def __repr__(self):
        return unicode(self)

    def get_details(self):
        return self.__direction, self.__time, self.__length

    def getDirection(self):
        return self.__direction

    def getLength(self):
        return self.__length

    def getTime(self):
        return self.__time

    @property
    def time(self):
        return self.__time

    @time.setter
    def time(self, value):
        self.__time = value

    @property
    def size(self):
        return self.__length

    def setLength(self, length):
        self.__length = int(length)

    def setTime(self, time):
        self.__time = int(time)

    def alter_size(self, new_size):
        packets = []
        d, t, l = self.get_details()
        if new_size >= self.__length:
            # pad
            np = Packet(d, t, new_size)
            packets.append(np)
            # TODO: if new_size>MTU
        else:
            # fragment
            for i in range(l // new_size):
                packets.append(Packet(d, t, new_size))
            if l % new_size:
                packets.append(Packet(d, t, l % new_size))
        return packets
