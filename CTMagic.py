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

import os
import binascii

class WhatypeErr(Exception):
    def __init__(self, when, error):
        self.when = when
        self.error = error
    def __str__(self):
        return repr("Whatype Error on " + self.when + " : " + self.error)

class MagicNode(object):
    def __init__(self, byte):
        self.byte = byte
        self.filetype = ""
        self.ext = ""
        self.strings = ""
        self.children = []

    def add_child(self, obj):
        n = MagicNode(obj)
        self.children.append(n)
        return n

    def has_child(self, data):
        for child in self.children:
            if child.byte.lower() == data.lower():
                return child
        return None

    def get_childrens_by_byte(self, data):
        childrens = []
        for child in self.children:
            if child.byte.lower() == data.lower():
                #return child
                childrens.append(child)
        return childrens

class Whatype(object):
    WTver = "0.1"
    WTrev = "01"
    MAGICLIST_NAME = "magics.csv"

    def __init__(self,magic_file=""):
        if magic_file:
            if os.path.isfile(magic_file):
                self.magic_list_file = magic_file
            else:
                raise WhatypeErr("magics list load", "Couldn't find " + magic_file)
        else:
            default_mgc = os.path.join(os.path.dirname(os.path.realpath(__file__)),Whatype.MAGICLIST_NAME)
            if os.path.isfile(default_mgc):
                self.magic_list_file = default_mgc
            else:
                raise WhatypeErr("loading default magics list","Couldn't find default magics list. " \
                                "Please provide a magics CSV file")

        # Create main prefix tree graph (Trie)
        self.Tree = MagicNode("all_magics")
        with open(self.magic_list_file, "r") as ins:
            for line in ins:
                parts = line.split(",")
                # parts[0] = File Type
                # parts[1] = Magic bytes
                # parts[2] = File Ext
                # parts[3] = File Strings
                self.create_branch(0, self.Tree, parts[0], parts[1], parts[2],parts[3])

    def create_branch(self, node_level, father, filetype, magic, ext, strings):
        magic_bytes = magic.split(" ")
        byte = magic_bytes[node_level]
        son = father.has_child(byte)

        node_level += 1

        if (node_level < len(magic_bytes)):
            if son is None:
                son = father.add_child(byte)
            self.create_branch(node_level, son, filetype, magic, ext,strings)
        else:
            if (node_level == len(magic_bytes)):
                son = father.add_child(byte)
            son.filetype = filetype
            son.ext = ext
            son.strings = strings


    def print_tree(self,Node, index):
        for nd in Node.children:
            print(("--" * index + nd.byte))
            if (len(nd.children) > 0):
                self.print_tree(nd, index + 1)

    def strings_search(self,strings_list, content):
        bGood = True
        for str in strings_list.split(";"):
            if str.lower().rstrip().encode() not in content.lower():
            #if content.lower().find(str.lower().rstrip()) == -1:
                bGood = False
        return bGood

    def return_magic(self,cont,Name,Ext):
        if not Name:
            Name = "Inconclusive. "
            if self.istext(cont):
                Name += "Probably text"
                Ext = "TEXT"
            else:
                Name += "Probably binary"
                Ext = "BINARY"

        return Name,Ext

    def istext(self,cont):
        # Based on http://code.activestate.com/recipes/173220/
        import string
        text_characters = "".join(list(map(chr, list(range(32, 127)))) + list("\n\r\t\b"))
        _null_trans = str.maketrans("", "")

        if not cont:
            # Empty files are considered text
            return True
        if b"\0" in cont:
            # Files with null bytes are likely binary
            return False
        # Get the non-text characters (maps a character to itself then
        # use the 'remove' option to get rid of the text characters.)
            #t = cont.translate(_null_trans, text_characters)
        # If more than 30% non-text characters, then
        # this is considered a binary file
            #if float(len(t))/float(len(cont)) > 0.30:
                #return False
        return True

    def find(self, cont, Node, index=0, magic_history=[]):
        if cont == "" or cont is None:
            return "",""
        curr_byte = hex(cont[index])[2:].zfill(2)
        NextNode = Node.get_childrens_by_byte(curr_byte)

        if NextNode:
            magic_history.extend(NextNode)
            Name, Ext = self.find(cont, NextNode[0], index+1, magic_history)

            if Ext == "Rollback":
                for i in range(len(magic_history)):
                    Node = magic_history.pop()
                    if Node.filetype != "":
                        if self.strings_search(Node.strings, cont):
                            return Node.filetype, Node.ext
            else:
                return Name, Ext

            return self.return_magic(cont,"","")
            #return ""
        else:
            # last hex node found
            if Node.filetype != "":
                if self.strings_search(Node.strings, cont):
                    return Node.filetype, Node.ext

            if len(magic_history) == 0:
                #return "",""
                return self.return_magic(cont,"","")

            return "", "Rollback" # Magic search went too far, rollbacking

    def identify_file(self,filepath):
        try:
            file_content = open(filepath).read()
            return self.find(file_content, self.Tree)
        except Exception as e:
            raise WhatypeErr("file identification", str(e))


    def identify_buffer(self,file_content):
        try:
            return self.find(file_content, self.Tree,0,[])
        except Exception as e:
            raise WhatypeErr("buffer identification", str(e))