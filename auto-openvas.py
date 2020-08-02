#!/usr/bin/python3
#  Copyright (c) 2020 by T.Magerl, GPLv3

""" AutoVAS primary logic """

import argparse
import os
from datetime import datetime
from time import sleep
from typing import Tuple, Iterator

import modules.syslog as log
from modules.JSONfile import JSONfile
from modules.Machine import Machine
from modules.OpenVAS import OpenVAS
from modules.nettools import crawl_net, get_mac

log.init('AutoVAS')
log.log_level = 5


def registered(ip: str, keep: bool = None) -> bool:
    """ create machine object and return True if doesn't exist yet """
    
    new = False
    try:
        machine[ip]
    except KeyError:
        machine[ip] = Machine(ip)
        machine[ip].data['created'] = now()
        new = True
    
    if not keep is None:
        machine[ip].keep = keep
    
    return new


def import_targets(path: str) -> None:
    """ call method for file or folder """
    
    if os.path.isfile(path):
        import_target_file(path)
    
    elif os.path.isdir(path):
        import_target_folder(path)
    
    else:
        log.err('nothing to import from `{0}`?'.format(path))


def import_target_file(path: str) -> None:
    """ import single job file """
    
    configfile = JSONfile(path)
    data = configfile.read()
    
    if isinstance(data, dict):
        mk_machine(data, path)
    
    elif isinstance(data, list):
        for jsonset in data:
            mk_machine(jsonset, path)


def import_target_folder(path: str) -> None:
    """ crawl import folder and load jobs """
    
    for path, dirs, files in os.walk(path):
        for f in files:
            configfile = JSONfile(path + f)
            mk_machine(configfile.read(), path + '/' + f)


def mk_machine(json_data: dict, source: str) -> None:
    """ create new machine object """
    
    try:
        json_data['ip'], json_data['mac']
    except KeyError:
        log.err('failed importing `{0}`'.format(source))
        
        return
    
    ip = json_data['ip']
    new = registered(ip, True)
    
    if not machine[ip].data['mac']:
        machine[ip].data['mac'] = json_data['mac'].upper()
    
    if json_data.get('skip', False):
        machine[ip].skip = machine[ip].data['skip'] = True
    
    machine[ip].data['comment'] = json_data['comment']
    
    if new:
        log.debug('config for {0} [{1}] imported'.format(machine[ip].data['ip'], machine[ip].data['mac']))


def days_diff(date1: datetime, date2: datetime = None) -> int:
    """ return days between 2 dates """
    
    if date1 > date2:
        r = (date1 - date2).days
    else:
        r = (date2 - date1).days
    
    return abs(r)


def get_args() -> argparse.Namespace:
    """ argparser """
    
    p = argparse.ArgumentParser(description="AutoOpenVAS")
    
    p.add_argument('-scan', type=str, default=None, help="search (sub)net for IPs (e.g. 192.168.0.0/24)")
    p.add_argument('-run', action='store_true', help='start one task')
    p.add_argument('-verify', action='store_true', help='skip on unexpected mac')
    p.set_defaults(verify=False)
    p.add_argument('-v', action='store_true', help='verbose')
    p.add_argument('-vv', action='store_true', help='very verbose')
    p.set_defaults(runcheck=False)
    p.set_defaults(v=False)
    p.set_defaults(vv=False)
    
    return p.parse_args()


def load_previous_data() -> None:
    """ restore previously saved data (ip, mac and time stamps) """
    
    datafile = JSONfile(config['data_file'])
    data = datafile.read()
    if not data:
        return
    
    for dataset in data:
        ip = dataset['ip']
        
        for toddel in ('link', 'severity'):
            dataset.pop(toddel, None)
        
        registered(ip)
        machine[ip].data = {**machine[ip].data, **dataset}
        for timeset in ('created', 'last_attempt', 'last_report'):
            if not machine[ip].data[timeset]:
                continue
            
            machine[ip].data[timeset] = datetime.strptime(
              machine[ip].data[timeset][:19], '%Y-%m-%d %H:%M:%S')


def openvas_analysis() -> None:
    """ handle gathering from openvas """
    
    for ip, report, stamp in ov.reports():
        registered(ip)
        if not machine[ip].report \
          or (report == machine[ip].report and stamp < machine[ip].data['last_report']) \
          or (report != machine[ip].report and stamp > machine[ip].data['last_report']):
            machine[ip].data['last_report'] = stamp
            machine[ip].report = report
            machine[ip].data['link'] = "{0}get_report&report_id={1}".format(config['base_url'], report)
    
    for ip, mac, task, running in ov.tasks():
        registered(ip)
        machine[ip].data['mac'] = mac
        machine[ip].task = task
        machine[ip].running = running
        if running:
            machine[ip].keep = True
        
        if not machine[ip].data['link']:
            machine[ip].data['link'] = "{0}get_task&task_id={1}".format(config['base_url'], task)
    
    for ip, target in ov.targets():
        registered(ip)
        machine[ip].target = target
        if not machine[ip].data['link']:
            machine[ip].data['link'] = "{0}get_target&target_id={1}".format(config['base_url'], target)
    
    for ip, severity, stamp in ov.results():
        registered(ip)
        if stamp >= machine[ip].data['last_report']:
            if machine[ip].data['severity'] == -1:
                machine[ip].data['severity'] = 0
            machine[ip].data['severity'] += severity
    
    for ip in machine:
        if not machine[ip].running and \
          machine[ip].data['last_attempt'] > machine[ip].data['last_report']:
            machine[ip].attempt_sort = 0
        else:
            machine[ip].attempt_sort = 1


def openvas_populate() -> None:
    """ create missing openvas targets/tasks """
    
    for ip in machine:
        if not machine[ip].keep or machine[ip].skip:
            continue
        
        if not machine[ip].target:
            target = ov.mk_target(ip, machine[ip].data['mac'], config['default_portlist_id'],
                                  machine[ip].data['comment'])
            if target:
                machine[ip].target = target
                machine[ip].data['link'] = "{0}get_target&target_id={1}".format(config['base_url'], target)
        
        if machine[ip].target and not machine[ip].task:
            task = ov.mk_task(ip, machine[ip].data['mac'], machine[ip].target,
                              config['default_scan_config_id'], machine[ip].data['comment'])
            if task:
                machine[ip].task = task
                machine[ip].data['link'] = "{0}get_task&task_id={1}".format(config['base_url'], task)


def load_config() -> dict:
    """ get config + add app path"""
    
    r = {
      'self.path': os.path.dirname(os.path.realpath(__file__)),
      'keep_days': 31
      }
    
    configfile = JSONfile(r['self.path'] + '/auto-openvas.conf')
    
    r = {**r, **configfile.read()}
    r['base_url'] = "https://{0}:{1}/omp?cmd=".format(r['openvas_ip'], r['openvas_web_port'])
    r['run_limit'] = 3
    
    return r


def save_results() -> None:
    """ prepare and export gathered information """
    
    export = []
    
    for ip in machine:
        if not machine[ip].keep:
            continue
        export.append(machine[ip].data)
    
    datafile = JSONfile(config['data_file'])
    if not datafile.write(export, list_sort_key='last_report'):
        log.crit("failed writing to `{0}`".format(config['cron_job_file']))


def scan_net(subnet: str) -> None:
    """ crawl net and add found IPs """
    
    for ip, mac, comment in crawl_net(subnet):
        new = registered(ip, True)
        if new:
            log.debug('found {1} ({0}, {2})'.format(ip, mac, comment))
        
        if machine[ip].data['comment'] == '':
            machine[ip].data['comment'] = comment
        
        if not machine[ip].data['mac']:
            machine[ip].data['mac'] = mac
        
        #  TODO : mac conflict


def now() -> datetime:
    return datetime.utcnow().replace(microsecond=0)


def clean_up():
    """ remove machines with last successfull test older than threshold days """
    now = datetime.now()
    for ip in machine:
        if machine[ip].running or machine[ip].keep:
            continue
        
        last_success = now - machine[ip].data['last_report']
        last_success = last_success.days
        last_attempt = now - machine[ip].data['last_attempt']
        last_attempt = last_attempt.days
        
        if not last_success > config['clean_up_threshold_days'] \
          or not last_attempt < config['clean_up_threshold_days']:
            continue
        
        if machine[ip].task and not (ov.rm('task', machine[ip].task)):
            log.err("[{0}]: failed removing task ({1})".format(machine[ip].data['mac'], ip))
        
        if machine[ip].target and not ov.rm('target', machine[ip].target):
            log.err("[{0}]: failed removing target ({1})".format(machine[ip].data['mac'], ip))


def test_order(sort_key: str) -> Iterator[Tuple[str, str]]:
    """ return list (ip, sort_key) ordered by sort_key value """
    
    r = []
    for ip in machine:
        if not machine[ip].keep or machine[ip].skip:
            log.debug('excluded {0} from run-test-candidates.'.format(ip))
            continue
        
        # TODO optional min duration between tests of single machines
        
        r.append((ip, machine[ip].data[sort_key]))
    
    r.sort(key=lambda k: k[1])
    
    return r


def task_running(ip: str) -> bool:
    """ confirm that task is running """
    
    for check_ip, mac, task, running in ov.tasks():
        if not check_ip == ip:
            continue
        
        if running:
            machine[ip].running = True
            return True
    
    else:
        return False


def tasks_running() -> int:
    """ count running tasks """
    
    count = 0
    for ip in machine:
        if machine[ip].running:
            count += 1
    
    return count


def openvas_run_task() -> None:
    """ try to start OV task until success, ordered by last_report """
    
    if tasks_running() > config['run_limit']:
        log.info('limit of {0} running tasks reached, no new task.'.format(config['run_limit']))
        return
    
    for ip, _ in test_order('last_attempt'):
        if machine[ip].running:
            log.info('[{0}]: task already running'.format(machine[ip].data['mac']))
            continue
        
        machine[ip].data['last_attempt'] = now()
        
        if args.verify:
            real_mac = get_mac(ip)
            if real_mac and not machine[ip].data['mac'] == real_mac:
                log.warn('[{0}]: ERROR: address conflict {1} ({2})'.format(machine[ip].data['mac'], real_mac, ip))
                continue
        
        if ov.run_task(machine[ip].task):
            log.notice('[{0}]: started OpenVAS task'.format(machine[ip].data['mac']))
            
            sleep(60 * 2)
            
            if task_running(ip):
                log.debug('[{0}]: running task verified'.format(machine[ip].data['mac']))
                machine[ip].keep = True
                break
            
            else:
                log.warn('[{0}]: task was aborted'.format(machine[ip].data['mac']))
                continue
        
        else:
            log.warn('[{0}]: FAILED starting OpenVAS task'.format(machine[ip].data['mac']))
            
            continue
    
    else:
        log.err('FAILED to start any OpenVAS task.')


if __name__ == '__main__':
    args = get_args()
    if args.vv:
        log.log_level = 7
    elif args.v:
        log.log_level = 6
    
    log.debug('initiated...')
    
    config = load_config()
    ov = OpenVAS('admin', config['passwd'], config['openvas_ip'],
                 config['openvas_omp_port'], config['openvas_web_port'])
    
    machine = {}
    load_previous_data()
    import_targets(config['job_source'])
    
    if args.scan:
        scan_net(args.scan)
    
    openvas_analysis()
    openvas_populate()
    
    if args.run:
        openvas_run_task()
    
    clean_up()
    save_results()
    
    log.notice('{0} running tasks'.format(tasks_running()))
    log.debug('done.')
    
    raise SystemExit(0)
