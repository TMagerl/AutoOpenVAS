#!/usr/bin/python3
#  Copyright (c) 2020 by T.Magerl, GPLv3
""" class Machine """

from datetime import datetime

import modules.syslog as log

default_stamp = datetime.strptime('1970-01-01 00:00:00', '%Y-%m-%d %H:%M:%S')


class Machine():
    """ machine container """
    
    def __init__(self, ip: str) -> None:
        
        self.keep = self.skip = self.running = False
        self.mac_new = None
        self.target = self.task = self.report = None
        
        self.data = {
          'ip':           ip,
          'mac':          None,
          'comment':      '',
          'severity':     -1,
          'link':         None,
          'created':      default_stamp,
          'last_attempt': default_stamp,
          'last_report':  default_stamp,
          'want_check':   False,
          'ip_changed':   False
          }
        
        log.debug('created container for {0}'.format(ip))
    
    def mac_update(self, mac: str) -> bool:  # TODO
        """ verify mac matches """
        
        if not isinstance(mac, str):
            return False
        
        mac = mac.upper()
        if self.data['mac'] == mac:
            return False
        
        return True
