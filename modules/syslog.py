#!/usr/bin/python3
#  Copyright (c) 2020 by T.Magerl, GPLv3

""" send message to syslog
    additionally to tty if called from console
    optional time measurement function
"""

import sys
from datetime import datetime as _dt
from timeit import default_timer
from typing import Tuple

from syslog import syslog, openlog

log_level = 5


def init(identifier: str) -> None:
    openlog(ident=identifier)


def start_timer(comment: str = 'unnamed') -> Tuple:
    """ return timestamp for use with log.timer() """
    
    return comment, default_timer()


def timer(start_timer: tuple, round_to: int = 2) -> None:
    """ log measured time from start_timer value on """
    
    comment, starttime = start_timer
    duration = default_timer() - starttime
    duration = round(duration, round_to)
    
    debug("'{0}' timer result: {1}ms".format(comment, duration))


def emerg(message: str) -> None:
    _sendlog(message, 0)


def alert(message: str) -> None:
    _sendlog(message, 1)


def crit(message: str) -> None:
    _sendlog(message, 2)


def err(message: str) -> None:
    _sendlog(message, 3)


def warn(message: str) -> None:
    _sendlog(message, 4)


def notice(message: str) -> None:
    _sendlog(message, 5)


def info(message: str) -> None:
    _sendlog(message, 6)


def debug(message: str) -> None:
    _sendlog(message, 7)


def _sendlog(message: str, level: int) -> None:
    """ primary log logic """
    
    if level > log_level:
        return
    
    syslog(level, message)
    
    if sys.stdout.isatty():
        print("[{0}] {1}: {2}".format(level, _dt.utcnow().replace(microsecond=0), message))
