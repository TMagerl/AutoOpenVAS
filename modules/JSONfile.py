#!/usr/bin/python3
#  Copyright (c) 2020 by T.Magerl, GPLv3

""" general module for handling json files, dicts and lists """

import json
from typing import Union

import modules.syslog as log


class JSONfile:
    """ convert JSON-formatted files to dict or list of dicts and back
    usage:

    myfile = JSONfile('filename')

    content = myfile.load([[list_sort_key='a'], reverse=True])
    if not myfile.error: print("yay")

    myfile.save(content[[, list_sort_key='a'], reverse=True])
    if not myfile.error: print("yay")
    """
    
    def __init__(self, filename: str) -> None:
        """ set filename and defaults """
        
        self.filename = filename
        self.error = False
        
        self.list_sort_key = None
        self.reverse = False
    
    def read(self, **kwargs) -> Union[list, dict, None]:
        """ load file content as dict or list of dicts (optionally sorted)
        kwargs:
            list_sort_key: str [default: None]
            reverse: bool [default: False]
         """
        try:
            with open(self.filename) as json_file:
                data = json.load(json_file)
            log.debug('`{0}` imported.'.format(self.filename))
        
        except FileNotFoundError:
            log.warn('`{0}` not found.'.format(self.filename))
            self.error = True
            return None
        
        except PermissionError:
            log.warn('Could not read `{0}`, permission denied.'.format(self.filename))
            self.error = True
            return None
        
        self.error = False
        return self._sort(data, kwargs)
    
    def write(self, data: Union[list, dict], **kwargs) -> bool:
        """ save dict or list of dicts to json file (optionally sorted)
        data:
            data: dict or list of dicts
        kwargs:
            list_sort_key: str [default: None]
            reverse: bool [default: False]
         """
        
        try:
            with open(self.filename, 'w+', encoding='utf-8') as f:
                f.write(json.dumps(self._sort(data, kwargs), indent=4, default=str))
            log.debug('data exported to `{0}`.'.format(self.filename))
        
        except FileNotFoundError:
            log.warn('`{0}` not found.'.format(self.filename))
            self.error = True
            return False
        
        except PermissionError:
            log.warn('Could not write `{0}`, permission denied.'.format(self.filename))
            self.error = True
            return False
        
        self.error = False
        return True
    
    def _sort(self, data: Union[list, dict], kwargs: dict) -> Union[list, dict]:
        """ sort data if list  """
        
        for key in ('list_sort_key', 'reverse'):
            if key in kwargs:
                setattr(self, key, kwargs.get(key))
        
        if not self.list_sort_key or not isinstance(data, list):
            return data
        
        try:
            data = sorted(data, key=lambda k: k[self.list_sort_key], reverse=self.reverse)
            sorted_by = " reversed" if self.reverse else ""
            log.debug('sorted by `{0}`{1}.'.format(self.list_sort_key, sorted_by))
        
        except:
            pass
        
        return data
