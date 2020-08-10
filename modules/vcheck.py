#!/usr/bin/python3
#   Copyright (c) 2020 by T.Magerl, GPLv3

""" general version check module """

from typing import Union

from requests import get

import modules.syslog as log


def vcheck(recent_version_url: str) -> Union[str, bool, None]:
    """ compare given remote and local VERSION file
    
    return False if failed, None if no newer version found
    or recent version
    """
    
    try:
        with open('VERSION') as file:
            current_version = file.read().strip()
    
    except:
        log.warn('failed to read file `VERSION`.')
        return False
    
    recent_version = get(recent_version_url)
    if not recent_version.status_code == 200:
        log.warn('failed to get recent version.')
        return False
    recent_version = recent_version.text.strip()
    
    for current, recent in zip(current_version.split('.'), recent_version.split('.')):
        if recent > current:
            log.notice('v{0} is available (current: v{1}).'.format(
              recent_version, current_version))
            return recent_version
    
    else:
        log.debug('up to date: v{0}.'.format(current_version))
        return None
