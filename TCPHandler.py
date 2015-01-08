__author__ = 'radicalcakes'

#raw socket server for sending the tcp packet to a configurable ip address
import socket
import binascii
import struct
from config import CONFIG


STAT1KEYS = ['tamper', 'cleanMe', 'alarm4', 'alarm3', 'alarm2', 'primaryAlarm']
STAT0KEYS = ['lowBattery', 'caseTamper', 'reset']
DATAKEYS = ['originator', 'firstHop', 'traceCount', 'traceIds', 'hopCount', '0x3e', 'pti', 'stat1', 'stat0', 'level', 'margin']


class Packet(object):
    def __init__(self, data):
        self.packet = ''
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data = self._format_list(data) if type(data) == list else self._format_data(data)

    def _checksum(self, msg):
        #creates checksum for the tcp header
        s = 0

        # loop taking 1 character at a time
        for i in range(0, len(msg)):
            w = ord(msg[i])
            s = s + w

        s = (s>>16) + (s & 0xff);
        s = s + (s >> 16);

        #complement and mask to 4 byte short
        s = ~s & 0xff

        return s

    def _bool_to_int(self, val):
        #converts a bool value to representations of 1/0
        if val:
            return 1
        else:
            return 0

    def _parse_stat(self, data, stat):
        #ensure that the correct stat key is passed
        if stat in ['stat1', 'stat0']:
            if stat == 'stat1':
                stat1 = []
                for key in STAT1KEYS:
                    stat1.append(data[key])
                return self._bool_to_int(stat1.count(True) > 1)
            else:
                stat0 = []
                for key in STAT0KEYS:
                    stat0.append(data[key])
                return self._bool_to_int(stat0.count(True) > 1)
        else:
            raise ValueError

    def _parse_data(self, data):
        initial_array = []
        #returns a parsed initial_array
        for key in DATAKEYS:
            #special case for the sec data
            if key == '0x3e':
                initial_array.append(62)
            elif key == 'traceIds':
                for trcid in data[key]:
                    initial_array.append(trcid)
            elif key == 'stat1':
                initial_array.append(self._parse_stat(data[key]))
            elif key == 'stat0':
                initial_array.append(self._parse_stat(data[key]))
            else:
                initial_array.append(data[key])
        return initial_array

    def _format_data(self, data):
        #formats the json data into a byte array for the packet use
        #throws n exception

        initial_arr = self._parse_data(data)
        packet_arr = []
        #first byte is 114
        header = 114
        #add 1 to include the header info
        length = len(initial_arr) + 1

        packet_arr.append(header)
        packet_arr.append(length)
        #add the other packet data ie; status, etc to the packet array
        packet_arr += initial_arr

        #compute chksum and append to the packet message
        packet_tup = tuple(packet_arr)
        packer = struct.Struct('I')
        prepacked = packer.pack(*packet_tup)
        #add in chksum
        chksum = self._checksum(prepacked)
        packet_arr.append(chksum)
        final_tup = tuple(packet_arr)
        packed = packer.pack(*final_tup)
        return packed

    def _format_list(self, data):
        new_data = map(self._format_data, data)
        return new_data

    def send(self):
        self.socket.connect(CONFIG['dest_ip'], CONFIG['dest_port'])
        print 'sending "%s"' % binascii.hexlify(self.data)
        if type(self.data) == list:
            for packet in self.data:
                self.socket.send(packet)
        else:
            self.socket.send(self.data)

        self.socket.close()



