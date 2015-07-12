#
#          CapTipper is a malicious HTTP traffic explorer tool
#          By Omri Herscovici <omriher AT gmail.com>
#          http://omriher.com
#          @omriher
#
#
#          This file is part of CapTipper, and part of the Whatype library
#          Whatype is an independent file type identification python library
#          https://github.com/omriher/whatype
#
#          CapTipper is a free software under the GPLv3 License
#

from collections import namedtuple

import inspect
import imp
import os
import glob

import CTCore

class ConsolePlugin(object):

    description = ""
    author = ""

    def __init__(self):
        self.conversations = CTCore.conversations
        self.objects = CTCore.objects
        self.hosts = CTCore.hosts

    def run(self):
        raise NotImplementedError

    def get_name_by_id(self,id):
        name = CTCore.get_name(id)
        return name

    def get_body_by_id(self,id):
        response, size = CTCore.get_response_and_size(id, "all")
        return response

    def get_plaintext_body_by_id(self,id):
        if id < len(self.conversations) and self.conversations[id].magic_ext == "GZ":
            data, name = CTCore.ungzip(id)
        else:
            data = self.get_body_by_id(id)

        return data

    def is_valid_id(self,id):
        if int(id) >= len(self.objects) or int(id) < 0:
            return False
        return True


def init_plugins():
    p_files = glob.glob(CTCore.plugins_folder + "*.py")
    for p in p_files:
        p_full = os.path.join(os.path.dirname(os.path.realpath(__file__)),p)
        (path, name) = os.path.split(p_full)
        (name, ext) = os.path.splitext(name)

        (p_file, filename, data) = imp.find_module(name, [path])
        mod = imp.load_module(name, p_file, filename, data)

        for name, value in inspect.getmembers(mod):
            if inspect.isclass(value):
                if issubclass(value, ConsolePlugin) and value is not ConsolePlugin:
                    p_num = len(CTCore.plugins)
                    CTCore.plugins.append(namedtuple('Plugin', ['id', 'name','module', 'description']))
                    CTCore.plugins[p_num].id = p_num
                    CTCore.plugins[p_num].name = name
                    CTCore.plugins[p_num].module = value
                    CTCore.plugins[p_num].description = value.description
