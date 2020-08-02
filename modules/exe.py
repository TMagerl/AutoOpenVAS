#!/usr/bin/python3
#  Copyright (c) 2020 by T.Magerl, GPLv3

""" general module for subprocessing """

from subprocess import PIPE, STDOUT, Popen, TimeoutExpired
from typing import Tuple, Union

import modules.syslog as log


def exe(command: Union[list, str], **kwargs) -> Tuple[Union[str, bool], Union[str, Exception]]:
    """ execute external process, returns (stdout: str|false, stderr: str)
    
    kwargs:
        timeout: default = 300sec
        label: log-label
    """
    
    timeout = kwargs.pop('timeout', 300)
    if not isinstance(timeout, int):
        raise ValueError("timeout can be int only")
    
    if isinstance(command, str):
        command = command.split()
    
    elif not isinstance(command, list):
        raise ValueError("command can be list or string only")
    
    label = kwargs.pop('label', command[0])
    
    try:
        subp = Popen(command, stdout=PIPE, stderr=STDOUT)
    
    except OSError:
        log.crit("`{0}` not found".format(command[0]))
        return False, 'not found'
    
    except Exception as e:
        log.crit("`{0}` failed: {1}".format(command[0], e))
        return False, e
    
    try:
        stdout, stderr = subp.communicate(timeout=timeout)
    
    except TimeoutExpired:
        log.err('`{0}` exceeded timeout ({1} sesc}.'.format(command[0], timeout))
        subp.kill()
        return False, 'timeout'
    
    except Exception as e:
        log.crit("`{0}` communication failed: {1}".format(command[0], e))
        return False, e
    
    stdout = '' if not stdout else stdout.decode('utf8')
    stderr = '' if not stderr else stderr.decode('utf8')
    
    log.debug('`{0}` executed.'.format(label))
    return stdout, stderr
