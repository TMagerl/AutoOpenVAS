#!/usr/bin/python3
#  Copyright (c) 2020 by T.Magerl, GPLv3

""" network functions """

import re
from typing import Union, Iterator

import modules.syslog as log
from modules.exe import exe

mac_pattern = r"([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})"
ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"


def crawl_net(subnet: str = None) -> Iterator[Union[str, str]]:
    """ scan given subnet for IPs and MACs using nmap """
    
    log.notice("scanning {0} for machines".format(subnet))
    
    cmd = "nmap -sn"
    cmd = cmd.split()
    cmd.append(subnet)
    
    stdout, _ = exe(cmd, timeout=300)
    if not stdout:
        log.warn("failed to scan network.")
        return None, None, None
    
    s = stdout.replace('\n', '|')
    
    for chunk in re.findall(r"Nmap scan report for.*?MAC Address.*?\(.*?\)", s):
        
        try:
            ip = re.findall(ip_pattern, chunk)[0]
            mac = re.findall(mac_pattern, chunk)[0]
        
        except IndexError:
            continue
        
        comment = re.findall(r"{0}\s\(.*?\)".format(mac), chunk)
        comment = '' if len(comment) == 0 else comment[0][19:-1]
        
        log.debug("found {0}, {1} ({2})".format(ip, mac, comment))
        yield ip, mac, comment


def get_mac(ip: str) -> Union[str, None]:
    """ get current mac address from ip using arping """
    
    cmd = "/usr/sbin/arping -c1 {0}".format(ip)
    cmd = cmd.split()
    
    stdout, _ = exe(cmd, timeout=300)
    if not stdout:
        log.crit("failed to get mac address")
        return None
    
    try:
        mac = re.findall(mac_pattern, stdout.upper())[0]
        
        log.debug("current mac for {0}: {1}".format(ip, mac))
        return mac
    
    except IndexError:
        return None
