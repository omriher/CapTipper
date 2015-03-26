import subprocess
import re
import os

from lib.cuckoo.common.abstracts import Processing

class captipper(Processing):
    """Runs CapTipper on pcap:
        1. Dump all files found in the pcap
        2. Checks the file types and returns if an EXE file was found
    """

    def run(self):
        """Run CapTipper
        @return: CapTipper dict.
        """
        self.key = "captipper"

        CAPTIPPER = "/home/cuckoo/tools/CapTipper/CapTipper.py" # CapTipper Path
        PCAPFILE = self.pcap_path # PCAP file created by cuckoo
        MAGIC_REG = "Magic: (.*)\)" # Reguler expression to find file types

        newpath = self.dropped_path + '/captipper/' # Path for files found in pcap
        if not os.path.exists(newpath): os.makedirs(newpath)

        CTout = subprocess.check_output([CAPTIPPER, PCAPFILE,'-d',newpath]) # runs CapTipper with arg to dump files
        
        # Parses file types found
        regex = re.compile(MAGIC_REG)
        types = regex.findall(CTout)
        exe_magic = False
        if "EXE" in types:
                exe_magic = True

        return dict(
            exe_exists=exe_magic
        )