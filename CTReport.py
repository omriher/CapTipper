#
#          CapTipper is a malicious HTTP traffic explorer tool
#          By Omri Herscovici <omriher AT gmail.com>
#          http://omriher.com
#          @omriher
#
#          This file is part of CapTipper
#
#          CapTipper is a free software under the GPLv3 License
#
import StringIO
from collections import OrderedDict, namedtuple
import hashlib
import os
import time

import CTCore
import json
from pescanner import PEScanner
from jsontemplate import jsontemplate

class Report(object):

    def __init__(self,hosts,conversations, version):
        self.conversations = conversations
        self.hosts = hosts
        self.version = version
        self.JsonReport = OrderedDict()
        self.pcap_name = os.path.splitext(os.path.basename(CTCore.pcap_file))[0]

    def ClientJson(self):
        client_list = {}
        for key, value in CTCore.client.get_information().iteritems():
                client_list[key] = value

        self.JsonReport['client'] = client_list
        return True

    def ConversationsJson(self):
        hosts_list = []
        for host, ip in self.hosts.keys():
            host_obj = OrderedDict()
            host_obj["name"] = host
            host_obj["ip"] = ip
            host_obj["uris"] = []

            for conv in self.conversations:
                if conv.host == host and conv.server_ip == ip:
                    conv_obj = OrderedDict()
                    if (conv.magic_ext.lower() == "binary") or ((conv.res_type.lower().find("application") > -1) and (conv.res_type.lower().find("javascript") == -1)):
                        conv_obj["binary"] = 1

                    if (conv.magic_ext.lower() == "exe"):
                        conv_obj["exe"] = 1
                        try:
                            pescan = PEScanner(conv.res_body, '', '')
                            out = pescan.collect()
                            if out:
                                pedata = '\n'.join(out)
                                conv_obj["peinfo"] = pedata[1:]
                        except Exception, e:
                            conv_obj["peinfo"] = e.message

                    conv_obj["id"] = conv.id
                    conv_obj["server_ip"] = conv.server_ip
                    conv_obj["uri"] = conv.uri
                    conv_obj["short_uri"] = conv.short_uri
                    conv_obj["req_head"] = conv.req_head
                    conv_obj["res_body"] = conv.res_body
                    conv_obj["res_base64"] = ""
                    if conv.res_body is not None:
                        conv_obj["res_base64"] = conv.res_body.encode("base64").rstrip()
                        if conv_obj.has_key("binary"):
                            conv_obj["hexpeek"] = CTCore.hexdump(conv.res_body[:128])
                        else:
                            try:
                                conv_obj["respeek"] = conv.res_body[:128]
                                if len(conv.res_body) > 128:
                                    conv_obj["respeek"] += "..."
                            except:
                                conv_obj["hexpeek"] = CTCore.hexdump(conv.res_body[:128])

                    conv_obj["magic_name"] = conv.magic_name
                    conv_obj["magic_ext"] = conv.magic_ext
                    conv_obj["res_head"] = conv.res_head
                    conv_obj["res_num"] = conv.res_num
                    conv_obj["res_type"] = conv.res_type
                    conv_obj["host"] = conv.host
                    conv_obj["referer"] = conv.referer
                    conv_obj["filename"] = conv.filename
                    conv_obj["method"] = conv.method
                    conv_obj["epochtime"] = time.strftime('%x %X', time.gmtime(float(conv.req_microsec)))
                    conv_obj["res_len"] = CTCore.fmt_size(conv.res_len)
                    conv_obj["md5"] = hashlib.md5(StringIO.StringIO(conv.res_body).getvalue()).hexdigest()
                    conv_obj["sha256"] = hashlib.sha256(StringIO.StringIO(conv.res_body).getvalue()).hexdigest()

                    host_obj["uris"].append(conv_obj)

            hosts_list.append(host_obj)

        self.JsonReport['conversations'] = hosts_list
        return True

    def InfoJson(self):
        info_list = OrderedDict()

        info_list["pcap_file"] = CTCore.pcap_file
        info_list["analysis_time"] = time.strftime('%x %X', time.localtime())
        info_list["captipper_version"] = self.version
        info_list["traffic_time"] = time.strftime('%x %X', time.gmtime(float(self.conversations[0].req_microsec)))

        self.JsonReport['info'] = info_list

    def leafcounter(self,node):
        if isinstance(node, dict):
            if isinstance(node["children"], list):
                return sum([self.leafcounter(node["children"]) for n in node["children"]])
            else:
                return 1
        else:
            return 1

    def FlowJson(self):
        from urlparse import urlparse
        links = []
        for host, ip in self.hosts.keys():
            for conv in self.conversations:
                conv_ref = urlparse(conv.referer.lower()).netloc
                conv_host = conv.host.lower()
                conv_redirect_to = urlparse(conv.redirect_to.lower()).netloc

                if conv_host != host and conv_ref == host:
                    bFound = False

                    for link in links:
                        if link.host == conv_ref and link.directed_to == host:
                            bFound = True

                        if link.directed_to == conv_host:
                            bFound = True

                    if not bFound:
                        new_link = namedtuple("host", "directed_to")
                        new_link.host = conv_ref
                        new_link.directed_to = conv_host
                        links.append(new_link)

                if conv_redirect_to != b'':
                    bFound = False;
                    for link in links:
                        if link.host == conv_ref and link.directed_to == host:
                            bFound = True

                        if link.directed_to == conv_redirect_to or link.directed_to == conv_ref:
                            bFound = True

                    if not bFound:
                        new_link = namedtuple("host", "directed_to")
                        new_link.host = conv_host
                        new_link.directed_to = conv_redirect_to
                        links.append(new_link)

            bDomainExists = False
            for link in links:
                if link.host == host or link.directed_to == host:
                    bDomainExists = True

            if not bDomainExists:
                new_link = namedtuple("host", "directed_to")
                new_link.host = host
                new_link.directed_to = ""
                links.append(new_link)

        name_to_node = {}
        root = {'name': 'Client', 'children': []}

        for link in links:
            parent = link.host
            child = link.directed_to
            parent_node = name_to_node.get(parent)
            if not parent_node:
                name_to_node[parent] = parent_node = {'name': parent}
                root['children'].append(parent_node)
            name_to_node[child] = child_node = {'name': child}
            if child_node["name"]:
                parent_node.setdefault('children', []).append(child_node)

        leaves = self.leafcounter(root)

        flow_dict = {}
        flow_dict["hosts"] = root
        flow_dict["size"] = (leaves * 45)
        self.JsonReport['flow'] = flow_dict

    def ReportJSON(self, path):
        try:
            json_path = os.path.join(path, self.pcap_name + ".json")

            self.JsonReport = OrderedDict()
            self.FlowJson()
            self.InfoJson()
            self.ClientJson()
            self.ConversationsJson()

            with open(json_path , 'w') as outfile:
                json.dump(self.JsonReport, outfile, indent=4,ensure_ascii=False)

            CTCore.alert_message("Created JSON report to " + json_path, CTCore.msg_type.GOOD)
            return self.JsonReport
        except Exception, e:
            CTCore.alert_message("Error creating JSON report in " + json_path + " : " + str(e), CTCore.msg_type.ERROR)

    def convert(self,input):
        if isinstance(input, dict):
            return {self.convert(key): self.convert(value) for key, value in input.iteritems()}
        elif isinstance(input, list):
            return [self.convert(element) for element in input]
        elif isinstance(input, unicode):
            return input.encode('ISO-8859-1')
        else:
            return input

    def ReportHTML(self,json_content, path):
        try:
            html_path = os.path.join(path, self.pcap_name + ".html")
            with open(r'jsontemplate/CapTipperTemplate.html', 'r') as content_file:
                html_tmp = content_file.read()

            json_content = self.convert(json_content)

            html_code = jsontemplate.expand(html_tmp, json_content)

            with open(html_path, 'wb') as report_file:
               report_file.write(html_code)

            CTCore.alert_message("Created HTML report to " + html_path, CTCore.msg_type.GOOD)
            return True
        except Exception, e:
            CTCore.alert_message("Error creating HTML report in " + html_path + " : " + str(e), CTCore.msg_type.ERROR)

    def CreateReport(self, path):
        CTCore.alert_message("Generating Reports...", CTCore.msg_type.INFO)
        jsonResult = self.ReportJSON(path)
        if jsonResult:
            if self.ReportHTML(jsonResult, path):
                CTCore.alert_message("Finished creating reports!", CTCore.msg_type.GOOD)
            else:
                CTCore.alert_message("Failed creating HTML report", CTCore.msg_type.ERROR)
        else:
            CTCore.alert_message("Failed creating reports", CTCore.msg_type.ERROR)
