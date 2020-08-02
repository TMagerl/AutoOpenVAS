#!/usr/bin/python3
#  Copyright (c) 2020 by T.Magerl, GPLv3
""" class OpenVAS """

import re
from datetime import datetime
from time import sleep
from typing import Union, Iterator

import modules.syslog as log
from modules.exe import exe


class OpenVAS:
    """ parse and control openvas by omp """
    
    def __init__(self, login: str, passwd: str, ip: str, omp_port: str, web_port: str) -> None:
        self.ip = ip
        self.port = omp_port
        self.base_cmd = "omp --username={0} --password={1} --host={2} " \
                        "--port={3}".format(login, passwd, ip, omp_port)
        
        self.base_url = "https://{0}:{1}/omp?cmd=".format(ip, web_port)
    
    def _omp(self, arg: list, timeout: int = 30) -> str:
        """ communication with OpenVAS """
        
        cmd = self.base_cmd.split() + arg
        label = cmd[0] + " " + " ".join(cmd[len(cmd) - 2:])
        
        tried = 0
        while tried < 3:
            stdout, _ = exe(cmd, timeout=timeout, label=label)
            
            if not stdout:
                raise SystemExit(66)
            
            stdout = stdout.replace('\n', ' ')
            if "Failed to authenticate." in stdout:
                tried += 1
                log.err("wrong password or openvas busy [{0}/3]".format(tried))
                sleep(43)
            
            elif "Failed to acquire socket." in stdout:
                log.crit("Failed to acquire socket.".format(self.port))
                raise SystemExit(6)
            
            else:
                return stdout
        
        log.crit("giving up, wrong password or openvas busy." \
                 "try `systemctl restart greenbone-security-assistant` @ {0}.".format(self.ip))
        raise SystemExit(4)
    
    def reports(self) -> Iterator[Union[str, str, datetime]]:
        """ extract ip, reportID and time stamp from openvas report """
        
        raw_data = self._omp(['--xml', '<get_reports/>'], 300)
        
        for report_chunk in re.findall(r"<report id=\"[0-9a-f-]*?\">.*?</report>", raw_data):
            
            report = re.findall(r"<report id=\"[0-9a-f-]*?\">", report_chunk)[0]
            report = get_quote(report)
            
            for result_chunk in re.findall(r"<result id=\"[0-9a-f-]*?\">.*?</result>", report_chunk):
                
                ip = re.findall('<host>[0-9.]*?<.*?>', result_chunk)
                if not len(ip) == 1:
                    log.err('report: multiple hosts found')
                    continue
                ip = rm_tags(ip[0])
                
                stamp = re.findall('<modification_time>.*?</modification_time>', result_chunk)
                if not len(stamp) == 1:
                    log.err('report: multiple timestamps found')
                    continue
                
                stamp = rm_tags(stamp[0])
                stamp = datetime.strptime(stamp[:19], '%Y-%m-%dT%H:%M:%S')
                
                yield ip, report, stamp
    
    def tasks(self) -> Iterator[Union[str, str, str]]:
        """ extract ip, mac, task-IDs """
        
        raw_data = self._omp(['--xml', '<get_tasks/>'], 300)
        
        for result_line in re.findall(r"<task id=\"[0-9a-f-]*?\">.*?</task>", raw_data):
            try:
                name = re.findall('<target id=.*?>.*</name>', result_line)[0]
                name = re.findall('<name>.*?</name>', name)[0]
                ip = re.findall('\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\)', name)[0][1:-1]
                mac = re.findall('>[\dA-F]{2}:[\dA-F]{2}:[\dA-F]{2}:[\dA-F]{2}:[\dA-F]{2}:[\dA-F]{2}\s', name)[0][1:-1]
                if len(ip) < 8 or len(mac) < 17:
                    log.err('task strange mac/ip')
                    continue
                
                status = re.findall('<status>.*?</status>', result_line)[0]
                running = True if rm_tags(status) == "Running" else False
            
            except IndexError:
                log.err('task index error')
                continue
            
            task = re.findall('<task id=\"[0-9a-f-]*?\">', result_line)[0]
            task = get_quote(task)
            
            yield ip, mac, task, running
    
    def targets(self) -> Iterator[Union[str, str]]:
        """ extract ip, target-IDs """
        
        raw_data = self._omp(['--xml', '<get_targets/>'], 300)
        
        for result_line in re.findall(r"<target id=.*?</target>", raw_data):
            ip = rm_tags(re.findall('<hosts>.*?</hosts>', result_line)[0])
            
            target = re.findall('target id=\"[0-9a-f-]*?\"', result_line)[0]
            target = get_quote(target)
            
            yield ip, target
    
    def results(self) -> Iterator[Union[str, str, str]]:
        """ extract ip, severety """
        
        raw_data = self._omp(['--xml', '<get_results/>'], 300)
        # print(0, datetime.utcnow())
        for result_chunk in re.findall(r"<result id=\"[0-9a-f-]*?\">.*?</result>", raw_data):
            ip = re.findall('<host>[0-9.]*?<.*?>', result_chunk)
            if not len(ip) == 1:
                continue
            ip = rm_tags(ip[0])
            
            severity = re.findall('<cvss_base>[\d.]*?</cvss_base>', result_chunk)
            if len(severity) == 1:
                severity = rm_tags(severity[0])
                severity = round(float(severity), 1)
            else:
                severity = 0.0
            
            if not severity > 0:
                continue
            
            stamp = re.findall('<modification_time>.*?</modification_time>', result_chunk)
            if not len(stamp) == 1:
                continue
            
            stamp = rm_tags(stamp[0])
            stamp = datetime.strptime(stamp[:19], '%Y-%m-%dT%H:%M:%S')
            # print(1, datetime.utcnow())
            yield ip, severity, stamp
    
    def mk_target(self, ip: str, mac: str, ports: str, comment: str = '') -> Union[str, None]:
        """ create target """
        
        name = "<name>{0} ({1})</name>".format(mac, ip)
        hosts = "<hosts>{0}</hosts>".format(ip)
        comment = "<comment>{0}</comment>".format(comment)
        ports = "<port_list id=\"{0}\"/>".format(ports)
        cmd = "<create_target>{0}{3}{1}{2}</create_target>".format(name, hosts, ports, comment)
        
        raw_data = self._omp(['--xml', cmd])
        
        if is_ok(raw_data):
            target_id = re.findall('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', raw_data)[0]
            log.notice("[{0}]: created target {1}".format(mac, target_id))
            
            return target_id
        
        else:
            log.warn("[{0}]: failed creating target ({1})".format(mac, ip))
            return None
    
    def mk_task(self, ip: str, mac: str, target_id: str, scan_config: str, comment: str = '') -> Union[str, None]:
        """ create task """
        
        name = "<name>{0} ({1})</name>".format(mac, ip)
        target_id = "<target id=\"{0}\"/>".format(target_id)
        comment = "<comment>{0}</comment>".format(comment)
        scan_config = "<config id=\"{0}\"/>".format(scan_config)
        cmd = "<create_task>{0}{3}{2}{1}</create_task>".format(name, target_id, scan_config, comment)
        
        raw_data = self._omp(['--xml', cmd])
        
        if is_ok(raw_data):
            task_id = re.findall('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', raw_data)[0]
            
            log.notice("[{0}]: created task {1}".format(mac, task_id))
            
            return task_id
        
        else:
            log.warn("[{0}]: failed creating task ({1})".format(mac, ip))
            return None
    
    def run_task(self, task: str) -> Union[str, None]:
        """ telling omp to start a task """
        
        raw_data = self._omp(['-S', task], 90)
        
        if 'Failed to start task.' in raw_data:
            return None
        
        return raw_data
    
    def rm(self, what: str, what_id: str) -> bool:
        """ delete given task or target from OpenVAS """
        
        cmd = "<delete_{0} {0}_id=\"{1}\"/>".format(what, what_id)
        
        raw_data = self._omp(['--xml', cmd])
        
        return is_ok(raw_data)


def is_ok(raw_data: str) -> bool:
    """ check status code of omp command """
    
    status = re.findall('status=\"\d{3}\"', raw_data)
    
    if not len(status) == 1:
        return False
    status = get_quote(status[0])
    
    if status[:1] == "2":
        return True
    
    else:
        return False


def rm_tags(s: str) -> str:
    """ return string with all XML tags (<TAG>) removed """
    
    rm = re.findall('<.*?>', s)
    for r in rm:
        s = s.replace(r, '')
    
    return s


def get_quote(s: str) -> str:
    """ get substring between (first) quotes """
    
    try:
        s = re.findall('".*?"', s)[0]
        s = s[1:-1]
    except IndexError:
        s = None
    
    return s
