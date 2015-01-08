__author__ = 'radicalcakes'
import TCPHandler


#original data 72 12 B2 7B 87 32 00 7F 12 C0 00 00 3E 2A 01 20 4A 4A D8
test_json_obj = {
                #hidden server sould do the conversion of originators and firstHopid
                "originator": 2994439986,
                "firstHop": 8327872,
                "traceCount": 00,
                "hopCount": 00,
                "pti": 42,
                "stat1":[
                    {
                        "tamper": False
                    },
                    {
                        "cleanMe": False
                    },
                    {
                        "alarm4": False
                    },
                    {
                        "alarm3": False
                    },
                    {
                        "alarm2": False
                    },
                    {
                        "primaryAlarm": True
                    }

                ],
                "stat0": [
                    {
                        "reserved": False
                    },
                    {
                        "lowBattery": False
                    },
                    {
                        "caseTamper": True
                    },
                    {
                        "reset": False
                    }
                ],
                "level": 74,
                "margin": 74
            }


#firsthopid: 01 88 7A 94
#originator: B2 88 3A 6C

packet = TCPHandler.Packet(test_json_obj)
