"""Yara Pattern Detection plugin"""
import glob
import os
import sys
from CTCore import (
    colors,
    msg_type,
    alert_message
    )
from CTPlugin import ConsolePlugin
try:
    import yara
except ImportError as err:
    alert_message("{} : pip install yara-python==3.5.0".format(err), msg_type.ERROR)
    sys.exit(-1)

class check_yara(ConsolePlugin):

    rules = None
    help_string = "Usage>> plugin check_yara [all | conversation ID]"
    description = "Checks Yara Patterns : {}".format(help_string)
    author = "madwind@kisec.com"

    def run(self, args):
        if not self.yara_rule_load():
            alert_message("Yara rules load Error..", msg_type.ERROR)
            return ""

        if len(args) > 0:
            command = args[0]
            if command == "all":
                alert_message("Check Yara Patterns in objects", msg_type.INFO)
                for id in range(len(self.objects)):
                    # Check if id number is a valid conversation
                    if self.is_valid_id(id):
                        name = self.get_name_by_id(id)
                        # Get response body as text even in case it was Gzipped
                        response_body = self.get_plaintext_body_by_id(id)
                        matches = self.rules.match(data=response_body)
                        if matches:
                            alert_message("Detection: [{}] {} :[{}]".format(
                                id, name, (", ".join([str(rule) for rule in matches]))),
                                          msg_type.GOOD)
                    else:
                        alert_message("Invalid conversation ID {}".format(str(id)), msg_type.ERROR)
            elif command.isdigit():
                # Gets the conversation ID
                convid = int(command)
                # Check if id number is a valid conversation
                if self.is_valid_id(convid):
                    name = self.get_name_by_id(convid)
                    alert_message("Check Yara Patterns in object {} ({})...".format(
                        str(convid), name),
                                  msg_type.INFO)
                    # Get response body as text even in case it was Gzipped
                    response_body = self.get_plaintext_body_by_id(convid)
                    matches = self.rules.match(data=response_body)
                    if matches:
                        alert_message("Detection: [{}] {} :{}".format(
                            convid, name, (", ".join([str(rule) for rule in matches]))),
                                      msg_type.GOOD)
                else:
                    alert_message("Invalid conversation ID {}".format(str(convid)), msg_type.ERROR)
            else:
                alert_message("Invalid command {} : {}".format(
                    command, self.help_string), msg_type.ERROR)
        else:
            alert_message("No arguments given : {}".format(self.help_string), msg_type.ERROR)

    def yara_rule_load(self):
        """Yara rule load"""
        plugin_path = os.path.dirname(os.path.realpath(__file__))
        p_files = glob.glob(plugin_path + "/rules/*.yar")
        total_yara_rule = ""
        for p in p_files:
            yara_rule = ""
            with open(p, "r") as rule_file:
                yara_rule = rule_file.read()
            try:
                yara.compile(source=yara_rule)
            except yara.SyntaxError as error:
                alert_message("{} : SyntaxError : {}".format(p, error), msg_type.ERROR)
                return False
            total_yara_rule += yara_rule+"\n"
            try:
                self.rules = yara.compile(source=total_yara_rule)
            except yara.SyntaxError as error:
                alert_message("{} : SyntaxError : {}".format(p, error), msg_type.ERROR)
                return False
        if self.rules is None:
            alert_message("Empty Yara rules", msg_type.ERROR)
            return False
        return True
