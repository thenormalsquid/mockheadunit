__author__ = 'radicalcakes'
import TCPHandler

test_json_obj = {
                #hidden server sould do the conversion of originators and firstHopid
                "originator": 2995272300,
                "firstHop": 25721492,
                "traceCount": 00,
                "hopCount": 01,
                "pti": 00,
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
                        "primaryAlarm": False
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
                        "caseTamper": False
                    },
                    {
                        "reset": False
                    }
                ],
                "level": 00,
                "margin": 00
            }

#firsthopid: 01 88 7A 94
#originator: B2 88 3A 6C

packet = TCPHandler.Packet(test_json_obj)
