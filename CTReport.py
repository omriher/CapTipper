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
import base64
import traceback
import io
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
        for key, value in list(CTCore.client.get_information().items()):
            try:
                client_list[key] = value.decode()
            except:
                client_list[key] = value


        self.JsonReport['client'] = client_list
        return True

    def ConversationsJson(self):
        hosts_list = []
        for host, ip in list(self.hosts.keys()):
            host_obj = OrderedDict()
            host_obj["name"] = host.decode()
            host_obj["ip"] = ip
            host_obj["uris"] = []

            for conv in self.conversations:
                if conv.host == host and conv.server_ip_port == ip:
                    conv_obj = OrderedDict()
                    if (conv.magic_ext.lower() == "binary") or ((conv.res_type.lower().find(b"application") > -1) and (conv.res_type.lower().find(b"javascript") == -1)):
                        conv_obj["binary"] = 1

                    if (conv.magic_ext.lower() == "exe"):
                        conv_obj["exe"] = 1
                        try:
                            pescan = PEScanner(conv.res_body, '', '')
                            out = pescan.collect()
                            if out:
                                pedata = '\n'.join(out)
                                conv_obj["peinfo"] = pedata[1:]
                        except Exception as e:
                            conv_obj["peinfo"] = str(e) + " ! Perhaps PEINFO library failed to import !"

                    conv_obj["id"] = conv.id
                    conv_obj["server_ip_port"] = conv.server_ip_port
                    conv_obj["uri"] = conv.uri.decode()
                    conv_obj["short_uri"] = conv.short_uri.decode()
                    conv_obj["req"] = conv.req.decode()
                    conv_obj["res_base64"] = ""
                    conv_obj["res_body"] = ""
                    if conv.res_body is not None:
                        conv_obj["res_body"] = conv.res_body.decode('cp437', 'ignore')
                        #conv_obj["res_base64"] = conv.res_body.encode("base64").rstrip()
                        conv_obj["res_base64"] = base64.b64encode(conv.res_body).decode().rstrip()
                        if "binary" in conv_obj:
                            conv_obj["hexpeek"] = CTCore.hexdump(conv.res_body[:128])
                        else:
                            try:
                                conv_obj["respeek"] = conv.res_body.decode()[:128]
                                if len(conv.res_body) > 128:
                                    conv_obj["respeek"] += "..."
                            except:
                                conv_obj["hexpeek"] = CTCore.hexdump(conv.res_body[:128])

                    conv_obj["magic_name"] = conv.magic_name
                    conv_obj["magic_ext"] = conv.magic_ext
                    conv_obj["res_head"] = conv.res_head.decode()
                    conv_obj["res_num"] = conv.res_num.decode()
                    conv_obj["res_type"] = conv.res_type.decode()
                    conv_obj["host"] = conv.host.decode()
                    try:
                        conv.referer = conv.referer.decode()
                    except:
                        pass
                    conv_obj["referer"] = conv.referer
                    try:
                        conv.filename = conv.filename.decode()
                    except:
                        pass
                    conv_obj["filename"] = conv.filename
                    conv_obj["method"] = conv.method.decode()
                    conv_obj["epochtime"] = time.strftime('%x %X', time.gmtime(float(conv.req_microsec)))
                    conv_obj["res_len"] = CTCore.fmt_size(conv.res_len)
                    conv_obj["md5"] = ""
                    conv_obj["sha256"] = ""
                    if conv.res_body is not None:
                        conv_obj["md5"] = hashlib.md5(conv.res_body).hexdigest()
                        conv_obj["sha256"] = hashlib.sha256(conv.res_body).hexdigest()

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
        from urllib.parse import urlparse
        links = []
        for host, ip in list(self.hosts.keys()):
            for conv in self.conversations:
                conv_ref = urlparse(conv.referer.lower()).netloc
                conv_host = conv.host.decode().lower()
                conv_redirect_to = urlparse(conv.redirect_to.decode().lower()).netloc

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
                new_link.host = host.decode()
                new_link.directed_to = ""
                links.append(new_link)

        name_to_node = {}
        root = {'name': 'Client', 'children': []}

        for link in links:
            try:
                parent = link.host.decode()
            except:
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

            if not os.path.isdir(os.path.dirname(json_path)):
                os.makedirs(os.path.dirname(json_path))

            with open(json_path , 'w') as outfile:
                json.dump(self.JsonReport, outfile, indent=4,ensure_ascii=False)

            CTCore.alert_message("Created JSON report to " + json_path, CTCore.msg_type.GOOD)
            return self.JsonReport
        except Exception as e:
            CTCore.alert_message("Error creating JSON report in " + json_path + " : " + str(e), CTCore.msg_type.ERROR)
            traceback.print_exc()

    def convert(self,input):
        if isinstance(input, dict):
            return {self.convert(key): self.convert(value) for key, value in list(input.items())}
        elif isinstance(input, list):
            return [self.convert(element) for element in input]
        elif isinstance(input, str):
            try:
                return input.encode('ISO-8859-1')
            except Exception as e:
                return input.encode('utf-8')
        else:
            return input

    def ReportHTML(self,json_content, path):
        try:
            html_path = os.path.join(path, self.pcap_name + ".html")
            with open(r'jsontemplate/CapTipperTemplate.html', 'r') as content_file:
                html_tmp = content_file.read()

            #json_content = self.convert(json_content)

            html_code = jsontemplate.expand(html_tmp, json_content)
            if not os.path.isdir(os.path.dirname(html_path)):
                os.makedirs(os.path.dirname(html_path))

            with open(html_path, 'wb') as report_file:
               report_file.write(html_code.encode())

            CTCore.alert_message("Created HTML report to " + html_path, CTCore.msg_type.GOOD)
            return True
        except Exception as e:
            CTCore.alert_message("Error creating HTML report in " + html_path + " : " + str(e), CTCore.msg_type.ERROR)
            traceback.print_exc()

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
