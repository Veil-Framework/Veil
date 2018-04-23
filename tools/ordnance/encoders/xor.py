#!/usr/bin/env python

"""
This xor encoder was developed completely by Justin Warner (@sixdub)
Thanks a lot for letting us add this in!
    http://stackoverflow.com/questions/4020539/process-escape-sequences-in-a-string-in-python
"""

import codecs
import re
import sys
from lib.common import helpers


class EncoderModule:

    def __init__(self, cli_arguments):
        self.name = "Single byte Xor Encoder"
        self.cli_name = "xor"
        self.description = "Single byte xor shellcode encoder"
        self.author = "Justin Warner (@sixdub)"
        self.xor_key = 0x00
        self.shellcode = b""
        self.terminator = b'\x00'
        self.encoded_shellcode = ""
        self.encoded_payload_length = 0
        self.encoder_bad_chars = ["eb", "18", "5e", "8d", "3e", "31", "c0", "db", "8a", "1c", "06", "80", "f3", "88", "1f", "47", "40", "ef", "e8", "e3", "ff"]
        if cli_arguments is not None:
            if cli_arguments.bad_chars is not None:
                self.bad_chars = cli_arguments.bad_chars
            else:
                self.bad_chars = None
        self.misc_comments = """
            #This is the decoder stub
            #<_start>:
            #   eb 18                   jmp    40101a <call_shellcode>

            #<decoder>:
              #5e                       pop    %esi
              #8d 3e                    lea    (%esi),%edi
              #31 c0                    xor    %eax,%eax
              #31 db                    xor    %ebx,%ebx

            #<decode>:
              #8a 1c 06                 mov    (%esi,%eax,1),%bl
              #80 fb TERM               cmp    TERM,%bl
              #74 0e                    je     <encodedShellcode>
              #80 f3 KEY                xor    KEY,%bl
              #88 1f                    mov    %bl,(%edi)
              #47                       inc    %edi
              #40                       inc    %eax
              #eb ef                    jmp    <decode>

            #<call_shellcode>:
              #e8 e3 ff ff ff           call   <decoder>
      """

    def cli_encode(self, incoming_pld):
        self.encode_routine(incoming_pld)
        return

    def decode_escapes(self, s):
        ESCAPE_SEQUENCE_RE = re.compile(r'''
            ( \\U........      # 8-digit hex escapes
            | \\u....          # 4-digit hex escapes
            | \\x..            # 2-digit hex escapes
            | \\[0-7]{1,3}     # Octal escapes
            | \\N\{[^}]+\}     # Unicode characters by name
            | \\[\\'"abfnrtv]  # Single-character escapes
            )''', re.UNICODE | re.VERBOSE)

        def decode_match(match):
            return codecs.decode(match.group(0), 'unicode-escape')

        return ESCAPE_SEQUENCE_RE.sub(decode_match, s)

    def encode(self, incoming_pld):
        self.encode_routine(incoming_pld)
        return

    def encode_routine(self, incoming_payload):
        self.set_bad_characters(incoming_payload)
        self.set_shellcode(incoming_payload)
        encode = bytearray(b"")
        # This is where the encoding happens
        # Test all possible keys and see if it creates a bad char. If not, we have a winner!
        for test_key in range(1, 255):
            if not self.have_bad_chars(self.xor(self.shellcode, test_key), self.bad_chars):
                self.xor_key = test_key
                break
            else:
                pass

        # Ensure a key was found... if not, error out
        if self.xor_key == 0x00:
            print(" [!] ERROR: No key found... Stop being so picky and change your bad chars!")
            exit
        else:
            # XOR all the things
            # Justin, your code comments are awesome
            for x in self.shellcode:
                encode.append(ord(x) ^ self.xor_key)
            skipped_term = 0

            # Iterate over code to find a non-used terminating char
            # that is not a badchar
            for i in range(1, 255):
                if i in encode or i in self.bad_chars:
                    skipped_term += 1
                else:
                    self.terminator = i
                    break

            # Build final payload with stub
            encode.append(self.terminator)
            decodestub = b"\xeb\x18\x5e\x8d\x3e\x31\xc0\x31\xdb\x8a\x1c\x06\x80\xfb"
            decodestub += (self.terminator).to_bytes(1, byteorder='big')
            decodestub += b"\x74\x0e\x80\xf3"
            decodestub += (self.xor_key).to_bytes(1, byteorder='big')
            decodestub += b"\x88\x1f\x47\x40\xeb\xef\xe8\xe3\xff\xff\xff"
            complete = decodestub + encode
            complete2 = codecs.encode(complete, 'hex')
            complete2 = "\\x" + '\\x'.join(codecs.decode(complete2[i:i + 2], 'utf-8') for i in range(0, len(complete2), 2))
            self.encoded_payload_length = len(complete)

            # At this point, the shellcode is a byte array... now we convert to ASCII
            self.encoded_shellcode = self.shellcode_to_ascii(complete)
            incoming_payload.customized_shellcode = self.encoded_shellcode
            return

    def have_bad_chars(self, incoming, chars):
        for b in chars:
            if b in incoming:
                return True
        return False

    def set_shellcode(self, shellcode):
        self.shellcode = self.decode_escapes(shellcode.customized_shellcode)
        return

    def set_bad_characters(self, payload_obj):
        bad_characters = payload_obj.required_options["BadChars"][0]
        if bad_characters is not None:
            final_bad_chars = []
            bad_characters = bad_characters.split('\\x')
            if '' in bad_characters:
                bad_characters.remove('')

            # Do some validation on the received characters
            for item in bad_characters:
                if item in self.encoder_bad_chars:
                    print(helpers.color(" [!] ERROR: Encoder - Bad character specified is used for the decoder stub.", warning=True))
                    print(helpers.color(" [!] ERROR: Encoder - Please use different bad characters or another encoder!", warning=True))
                    sys.exit()
                else:
                    if len(item) == 2:
                        # Thanks rohan (@cptjesus) for providing this regex code, and making me too lazy
                        # to do it myself
                        rohan_re_code = re.compile('[a-f0-9]{2}',flags=re.IGNORECASE)
                        if rohan_re_code.match(item):
                            final_bad_chars.append(item)
                        else:
                            print()
                            print(helpers.color(" [!] ERROR: Bad Character - #1: Invalid bad character detected.", warning=True))
                            print(helpers.color(" [!] ERROR: Bad Character - Please provide bad characters in \\x00\\x02... format.", warning=True))
                            print()
                            return
                    else:
                        print()
                        print(helpers.color(" [!] ERROR: Bad Character - #2: Invalid bad character detected.", warning=True))
                        print(helpers.color(" [!] ERROR: Bad Character - Please provide bad characters in \\x00\\x01... format.", warning=True))
                        print()
                        return
            self.bad_chars = [int("0x" + x, 16) for x in final_bad_chars]
        return

    def shellcode_to_ascii(self, shell_code):
        output = ""
        for b in shell_code:
            output += "\\x%02x" % b
        return output

    # Takes a blob as input with a single byte key and returns blob output
    def xor(self, input_sc, key):
        output = bytearray(b"")
        for b in input_sc:
            output.append(ord(b) ^ key)
        return output

    def all_the_stats(self, parsed_cli_object):
        print("Payload Type: " + parsed_cli_object.payload)
        if parsed_cli_object.ip is None:
            print("IP Address: n/a")
        else:
            print("IP Address: " + parsed_cli_object.ip)
        print("Port: " + str(parsed_cli_object.port))
        print("Encoder Name: " + self.name)
        string_bad_chars = ""
        for bchar in self.bad_chars:
            string_bad_chars += str(hex(bchar)) + " "
        print("Bad Character(s): " + string_bad_chars)
        print("Shellcode length: " + str(self.encoded_payload_length))
        print("Xor Key: " + str(hex(self.xor_key)) + "\n")
        return
