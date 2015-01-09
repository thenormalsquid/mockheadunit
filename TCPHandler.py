__author__ = 'radicalcakes'

#raw socket server for sending the tcp packet to a configurable ip address
import socket
import math
import binascii
from config import CONFIG


STAT1KEYS = ['tamper', 'cleanMe', 'reserved1', 'reserved2', 'alarm4', 'alarm3', 'alarm2', 'primaryAlarm']
STAT0KEYS = ['reserved', 'lowBattery', 'caseTamper', 'set', 'reset', 'reserved1', 'reserved2', 'reserved3']
DATAKEYS = ['originator', 'firstHop', 'traceCount', 'traceIds', 'hopCount', '0x3e', 'pti', 'stat1', 'stat0', 'level', 'margin']


class Packet(object):
    def __init__(self, data):
        self.packet = ''
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data = self._format_list(data) if type(data) == list else self._format_data(data)

    def _hex_to_int(self, val):
        return int(val, 16)

    def _checksum(self, msg):
        #creates checksum for the tcp header
        s = hex(sum(map(self._hex_to_int, msg)))
        final = '0x' + s[len(s)-2:]

        return final

    def _get_int_from_data(self, i, val):
        #marks the current bit position in status if the bit position is true
        if val:
            return math.pow(2, i)
        return 0

    def _parse_stat(self, data, stat):
        #ensure that the correct stat key is passed
        if stat in ['stat1', 'stat0']:
            if stat == 'stat1':
                i = len(STAT1KEYS) - 1
                total = 0
                for key in STAT1KEYS:
                    for statobj in data:
                        if key in statobj:
                            #if the status is true, mark the bit position: 2^i where i is the bit position
                            total += self._get_int_from_data(i, statobj[key])

                    i -= 1
                return hex(int(total))
            else:
                i = len(STAT0KEYS) - 1
                total = 0
                for key in STAT0KEYS:
                    for statobj in data:
                        if key in statobj:
                            total += self._get_int_from_data(i, statobj[key])

                    i -= 1

                return hex(int(total))
        else:
            raise ValueError

    def _split_hex(self, val, initial_array):
        if len(val) > 4:
            s = val[2:]
            l = ['0x' + s[i:i+2] for i in range(0, len(s), 2)]
            initial_array += l
        else:
            initial_array.append(val)


    def _parse_data(self, data):
        initial_array = []
        #returns a parsed initial_array
        for key in DATAKEYS:
            #special case for the sec data
            if key == '0x3e':
                initial_array.append(hex(62))
            elif key not in data:
                continue
            elif key == 'traceIds':
                for trcid in data[key]:
                    self._split_hex(hex(trcid), initial_array)
            elif key == 'stat1':
                initial_array.append(self._parse_stat(data[key], key))
            elif key == 'stat0':
                initial_array.append(self._parse_stat(data[key], key))
            else:
                self._split_hex(hex(data[key]), initial_array)
        return initial_array

    def _format_data(self, data):
        #formats the json data into a byte array for the packet use
        #throws n exception

        initial_arr = self._parse_data(data)
        packet_arr = []
        #first byte is 114
        header = hex(114)
        #add 1 to include the header info
        length = hex(18)

        packet_arr.append(header)
        packet_arr.append(length)

        #add the other packet data ie; status, etc to the packet array
        packet_arr += initial_arr
        #compute chksum and append to the packet message
        chksum = self._checksum(packet_arr)

        packet_arr.append(chksum)
        packed = b''.join(packet_arr)

        msg = bytearray(packed)

        print msg
        return msg

    def _format_list(self, data):
        new_data = map(self._format_data, data)
        return new_data

    def send(self):
        self.socket.connect((CONFIG['dest_ip'], CONFIG['dest_port']))
        print 'sending "%s"' % binascii.hexlify(self.data)
        if type(self.data) == list:
            for packet in self.data:
                self.socket.send(packet)
        else:
            self.socket.send(self.data)

        self.socket.close()



