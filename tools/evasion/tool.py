"""
This is the Veil-Evasion module
"""

import glob
import os
import readline
import subprocess
import sys
from os.path import join
from lib.common import completer
from lib.common import helpers
from tools.evasion.evasion_common import evasion_helpers
from tools.evasion.evasion_common import outfile
from tools.evasion.evasion_common import shellcode_help


# Try to find and import the settings.py config file
try:
    sys.path.append("/etc/veil/")
    import settings
except ImportError:
    print( "\n [!] ERROR #1-1: Can't import /etc/veil/settings.py.   Run: %s\n" % ( os.path.abspath( "./config/update-config.py" ) ) )
    sys.exit()


sys.path.insert(0, settings.VEIL_PATH + '/tools/ordnance')
import tool as ordnance_import


class Tools:

    def __init__(self, cli_options=None):
        self.cli_name = "Evasion"
        self.description = "Generates Anti-Virus avoiding executables #avlol"
        # Payloads currently within the payload directories
        self.active_payloads = {}
        # Load all payload modules
        self.load_payloads(cli_options)
        self.command_options = cli_options
        self.evasion_main_menu_commands = {
            "list": "List available payloads",
            "use": "Use a specific payload",
            "info": "Information on a specific payload",
            "exit": "Completely exit Veil",
            "back": "Go to Veil's main menu",
            "clean": "Remove generated artifacts",
            "checkvt": "Check VirusTotal.com against generated hashes"}
        self.final_shellcode = ""
        self.payload_option_commands = {
            "set": "Set shellcode option",
            "generate": "Generate the payload",
            "back": "Go back to Veil-Evasion",
            "exit": "Completely exit Veil",
            "options": "Show the shellcode's options"
        }

    def check_vt(self, interactive=True):
        """
        Checks payload hashes in veil-output/hashes.txt vs VirusTotal.com
        """

        # Command for in-menu vt-notify check against hashes within hash file
        # It's only triggered if selected in menu and file isn't empty
        try:
            if os.stat(settings.HASH_LIST)[6] != 0:
                checkVTcommand = settings.VEIL_PATH + 'tools/evasion/scripts/vt-notify/vt-notify.rb -f ' + settings.HASH_LIST + ' -i 0'
                print(helpers.color("\n [*] Checking Virus Total for payload hashes...\n"))
                checkVTout = subprocess.check_output(checkVTcommand, shell=True)
                checkVTout = checkVTout.decode('ascii')
                checkVTout = checkVTout.split('\n')

                found = False
                for line in checkVTout:
                    if "was found" in line:
                        filehash, filename = line.split()[0].split(":")
                        print(helpers.color(" [!] File %s with hash %s found!" % (filename, filehash), warning=True))
                        found = True
                if found is False:
                    print(" [*] No payloads found on VirusTotal.com!")

                input("\n [>] Press any key to continue...")

            else:
                print(helpers.color("\n [!] Hash file is empty, generate a payload first!", warning=True))
                input("\n [>] Press any key to continue...")

        except OSError:
            print(helpers.color("\n [!] ERROR: hash list %s not found" % (settings.HASH_LIST), warning=True))
            input("\n [>] Press any key to continue...")
        return

    def clean_artifacts(self, interactive=True):
        """
        Cleans out the payload source/compiled/handler folders.
        """

        # prompt for confirmation if we're in the interactive menu
        if interactive:
            choice = input("\n [>] Are you sure you want to clean payload folders? [y/N] ").strip().lower()

            if choice.startswith('y'):
                helpers.clean_payloads()

                choice = input("\n [>] Folders cleaned, press any enter to return to the main menu.")

            else:
                print(helpers.color("[*] You did not enter yes, not cleaning payloads!", warning=True))

        else:
            print("\n [*] Cleaning %s" % (settings.PAYLOAD_SOURCE_PATH))
            os.system('rm -f %s/*.*' % (settings.PAYLOAD_SOURCE_PATH))

            print(" [*] Cleaning %s" % (settings.PAYLOAD_COMPILED_PATH))
            os.system('rm -f %s/*.exe' % (settings.PAYLOAD_COMPILED_PATH))

            print(" [*] Cleaning %s" % (settings.HANDLER_PATH))
            os.system('rm -f %s/*.rc' % (settings.HANDLER_PATH))

            print(" [*] cleaning %s" % (settings.HASH_LIST))
            os.system('rm -f %s' % (settings.HASH_LIST))
            os.system('touch ' + settings.HASH_LIST)

            print("\n [*] Folders cleaned\n")
        return

    def cli_menu(self, invoked=False):
        # --list-payloads
        if self.command_options.list_payloads:
            self.list_loaded_payloads()
            sys.exit()

        # Check if a payload is provided, and if so, start the generation
        # process
        # Missing -p ?
        if not self.command_options.p:
            print(helpers.color(" [!] ERROR: Missing --payload selection (-p <payload>).    Try: -t Evasion --list-payloads", warning=True))
        else:
            user_cli_payload = self.return_payload_object(self.command_options.p)
            if not user_cli_payload:
                print(helpers.color(" [!] ERROR: You did not provide a valid payload selection!", warning=True))
                print(helpers.color(" [*] Ex: info 2 OR info lua/shellcode_inject/flat.py", warning=True))
                sys.exit()
            if self.command_options.ip is None and ("meterpreter" in user_cli_payload.path or "shellcode_inject" in user_cli_payload.path):
                print(helpers.color(" [!] ERROR: You did not provide an IP/domain to connect to/bind on", warning=True))
                sys.exit()

            # Make sure IP is valid
            # --ip
            if self.command_options.ip is not None:
                valid_ip = helpers.validate_ip(self.command_options.ip)
                valid_hostname = helpers.validate_hostname(self.command_options.ip)

                if not valid_ip and not valid_hostname:
                    print(helpers.color(" [!] ERROR: You did not provide a valid ip/domain!", warning=True))
                    print(helpers.color("[*] Please specify the correct value", warning=True))
                    sys.exit()

            # Determine if using Ordnance or MSFVenom for shellcode generation
            if self.command_options.ordnance_payload is None and self.command_options.msfvenom is None and "meterpreter" not in user_cli_payload.path:
                print(helpers.color(" [!] ERROR: You did not provide a shellcode option to use!", warning=True))
                sys.exit()

            # Check if using a pure payload (shellcodeless)
            if "meterpreter" in user_cli_payload.path or "shellcode_inject" in user_cli_payload.path:
                if "meterpreter" in user_cli_payload.path:
                    # Check for where the IP is being stored
                    if "LHOST" in user_cli_payload.required_options:
                        user_cli_payload.required_options["LHOST"][0] = self.command_options.ip
                    elif "RHOST" in user_cli_payload.required_options:
                        user_cli_payload.required_options["RHOST"][0] = self.command_options.ip
                    # Store the LPORT value in the payload
                    if "LPORT" in user_cli_payload.required_options:
                        user_cli_payload.required_options["LPORT"][0] = self.command_options.port
                else:
                    # If ordnance, generate shellcode through it
                    if self.command_options.ordnance_payload is not None:
                        Ordnance_object = ordnance_import.Tools(self.command_options)
                        Ordnance_object.cli_menu(invoked=True)
                        cli_shellcode = Ordnance_object.final_shellcode
                    # Or if msfvenom, get that code
                    elif self.command_options.msfvenom is not None:
                        cli_shellcode = shellcode_help.cli_msf_shellcode_gen(self.command_options)
                    # This could be the future area for adding custom shellcode. If there
                    # is a need I can add it in

                    # Set the shellcode in the Evasion payload
                    user_cli_payload.cli_shellcode = cli_shellcode

            # Loop over setting required options
            # -c
            if self.command_options.c is not None:
                for payload_option in self.command_options.c:
                    if payload_option != '':
                        if "=" not in payload_option:
                            print(helpers.color(" [!] Payload option not entered in correct syntax.\n", warning=True))
                            sys.exit()
                        else:
                            key = payload_option.split('=')[0].upper()
                            value = payload_option.split('=')[1]
                            if key in user_cli_payload.required_options:
                                user_cli_payload.required_options[key][0] = value
                            else:
                                print(helpers.color(" [!] The option " + key + " does not exist for the selected payload!.\n", warning=True))
                                sys.exit()

            # Generate the payload code
            # source code stored in user_cli_payload.source_code
            user_cli_payload.generate()

            # figure out how to compile the code
            outfile.compiler(user_cli_payload, invoked=True, cli_object=self.command_options)
        return

    def display_payload_options(self, selected_pload, showTitle=True):
        # show the title if specified
        if showTitle:
                evasion_helpers.title_screen()

        self.payload_info(selected_pload)
        return

    def invoked_tool_menu(self, callback_config=None):
        print("This is a menu when invoked by another tool")
        return

    def list_loaded_payloads(self):
        print(helpers.color("\n [*] Available Payloads:\n"))

        lastBase = None
        x = 1
        for name in sorted(self.active_payloads.keys()):
            parts = name.split("/")
            if lastBase and parts[0] != lastBase:
                print()
            lastBase = parts[0]

            print("\t%s)\t%s" % (x, '{0: <24}'.format(name)))

            x += 1
        print("\n")
        return

    def load_payloads(self, cli_args):
        for x in range(1, 5):
            for name in glob.glob(join("tools/evasion/payloads/" + "*/" * x,'[!_]*.py')):
                if name.endswith(".py") and ("__init__" not in name):
                    module = helpers.load_module(name)
                    self.active_payloads[name.replace('tools/evasion/payloads/', '')] = module.PayloadModule(cli_args)
        return

    def print_options_screen(self, pload_object):
        print()
        print("Payload: " + helpers.color(pload_object.path) + " selected\n")
        print(helpers.color(" Required Options:\n"))
        print('{0: <16}'.format('Name') + '\t' + '{0: <8}'.format('Value') + '\t' + '{0: <8}'.format('Description'))
        print('{0: <16}'.format('----') + '\t' + '{0: <8}'.format('-----') + '\t' + '{0: <8}'.format('-----------'))
        for opt_name in sorted(pload_object.required_options.keys()):
            print('{0: <16}'.format(opt_name) + '\t' + '{0: <8}'.format(pload_object.required_options[opt_name][0]) + '\t' + pload_object.required_options[opt_name][1])
        print()
        return

    def payload_info(self, payload_obj, showTitle=True, showInfo=True):
        """
        Print out information about a specified payload.
        payload_obj = the payload object to print information on
        showTitle = whether to show the Veil title
        showInfo = whether to show the payload information bit
        """

        print(helpers.color(" Payload Information:\n"))
        print("\tName:\t\t" + payload_obj.name)
        print("\tLanguage:\t" + payload_obj.language)
        print("\tRating:\t\t" + payload_obj.rating)

        # format this all nice-like
        print(evasion_helpers.format_long("Description:", payload_obj.description))
        # if required options were specified, output them
        if hasattr(payload_obj, 'required_options'):
            self.print_options_screen(payload_obj)
        return

    def return_payload_object(self, user_selection):
        # This function handles returning the selected payload module object
        # to the calling function

        payloads = sorted(self.active_payloads.items())
        payload_by_path = [payload for payload in payloads if payload[0] == user_selection.strip().lower()]

        if user_selection.isdigit() and (0 < int(user_selection) <= len(self.active_payloads)):
            #  minus 1 because menu starts counting at 1 not 0
            user_selection = int(user_selection) - 1
            return payloads[user_selection][1]
        elif payload_by_path:
            return payload_by_path[0][1]
        else:
            return False

    def tool_main_menu(self):
        # This is the main function where everything is called from
        # Iterate over payloads and find the user selected payload module
        evasion_main_command = ""
        show_evasion_menu = True
        while True:

            # set out tab completion for the appropriate modules on each run
            # as other modules sometimes reset this
            comp = completer.MainMenuCompleter(self.evasion_main_menu_commands, self.active_payloads)
            readline.set_completer_delims(' \t\n;')
            readline.parse_and_bind("tab: complete")
            readline.set_completer(comp.complete)

            if show_evasion_menu:
                evasion_helpers.title_screen()
                print("Veil-Evasion Menu")
                print("\n\t" + helpers.color(len(self.active_payloads)) + " payloads loaded\n")
                print("Available Commands:\n")
                for command in sorted(self.evasion_main_menu_commands.keys()):
                    print("\t" + helpers.color(command) + '\t\t\t' + self.evasion_main_menu_commands[command])
                print()
                show_evasion_menu = False

            evasion_main_command = input('Veil/Evasion>: ').strip().lower()

            if evasion_main_command.startswith("back") or evasion_main_command.startswith("main") or evasion_main_command.startswith("menu"):
                break

            elif evasion_main_command.startswith("checkvt"):
                self.check_vt()

            elif evasion_main_command.startswith("clean"):
                self.clean_artifacts()

            elif evasion_main_command.startswith("exit") or evasion_main_command.startswith("quit"):
                sys.exit(0)

            elif evasion_main_command.startswith('info'):
                if len(evasion_main_command.split()) == 2:
                    payload_selected = evasion_main_command.split()[1]
                    selected_payload_module = self.return_payload_object(payload_selected)
                    if not selected_payload_module:
                        print()
                        print(helpers.color(" [!] ERROR: You did not provide a valid payload selection!", warning=True))
                        print(helpers.color(" [*] Ex: info 2 OR info lua/shellcode_inject/flat.py", warning=True))
                        print()
                    else:
                        self.print_options_screen(selected_payload_module)
                else:
                    print()
                    print(helpers.color(" [!] ERROR: You did not provide a valid payload selection!", warning=True))
                    print(helpers.color(" [*] Ex: info 2 OR info lua/shellcode_inject/flat.py", warning=True))
                    print()

            elif evasion_main_command.startswith('list'):
                evasion_helpers.title_screen()
                self.list_loaded_payloads()

            elif evasion_main_command.startswith('use'):
                if len(evasion_main_command.split()) == 2:
                    payload_selected = evasion_main_command.split()[1].lower()
                    selected_payload_module = self.return_payload_object(payload_selected)
                    if not selected_payload_module:
                        print()
                        print(helpers.color(" [!] ERROR: You did not provide a valid payload selection!", warning=True))
                        print(helpers.color(" [*] Ex: use 2 OR use lua/shellcode_inject/flat.py", warning=True))
                        print()
                    else:
                        self.use_payload(selected_payload_module)
                        show_evasion_menu = True
                else:
                    print()
                    print(helpers.color(" [!] ERROR: You did not provide a valid payload selection!", warning=True))
                    print(helpers.color(" [*] Ex: use 2 OR use lua/shellcode_inject/flat.py", warning=True))
                    print()
        return

    def use_payload(self, selected_payload):
        # Tab completion, thanks Will :)
        comp = completer.PayloadCompleter(self.payload_option_commands, selected_payload)
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)

        self.display_payload_options(selected_payload)

        payload_options_command = ""
        evasion_helpers.print_dict_message(self.payload_option_commands, show_title=False)

        while True:
            payload_options_command = input("[" + selected_payload.path + ">>]: ").strip().lower()

            if payload_options_command.startswith("back") or payload_options_command.startswith("main") or payload_options_command.startswith("menu"):
                break

            elif payload_options_command.startswith("gen") or payload_options_command.startswith("run"):
                # Checking for Ruby specific payloads because of dumbass sleep check
                if selected_payload.language == 'ruby' and selected_payload.required_options["SLEEP"][0] != "X" and selected_payload.required_options["USERNAME"][0] == "X" and selected_payload.required_options["DOMAIN"][0] == "X" and selected_payload.required_options["HOSTNAME"][0] == "X":
                    print(helpers.color("[*] If using SLEEP check with Ruby, you must also provide an additional check (like HOSTNAME)!", warning=True))
                else:
                    selected_payload.generate()
                    if outfile.compiler(selected_payload):
                        break

            elif payload_options_command.startswith("exit") or payload_options_command.startswith("quit"):
                sys.exit(0)

            elif payload_options_command.startswith("help") or payload_options_command.startswith("option"):
                self.print_options_screen(selected_payload)
                evasion_helpers.print_dict_message(self.payload_option_commands, show_title=False)

            elif payload_options_command.startswith("set"):
                if len(payload_options_command.split()) == 3:
                    set_command, key, value = payload_options_command.split()
                    # Make sure it is uppercase
                    key = key.upper()
                    if key in selected_payload.required_options:
                        # Validate LHOST value
                        if key == "LHOST":
                            if helpers.validate_ip(value):
                                selected_payload.required_options[key][0] = value
                            else:
                                print()
                                print(helpers.color(" [!] ERROR: You did not provide a valid IP!", warning=True))
                                print()
                        # Validate LPORT
                        elif key == "LPORT":
                            if helpers.validate_port(value):
                                selected_payload.required_options[key][0] = value
                            else:
                                print()
                                print(helpers.color(" [!] ERROR: You did not provide a valid port number!", warning=True))
                                print()

                        else:
                            # Set other options
                            selected_payload.required_options[key][0] = value
                    else:
                        print()
                        print(helpers.color(" [!] ERROR: You did not provide a valid option!", warning=True))
                        print(helpers.color(" [*] Ex: set LHOST 8.8.8.8", warning=True))
                        print()

                else:
                    print()
                    print(helpers.color(" [!] ERROR: You did not provide a valid amount of arguments!", warning=True))
                    print(helpers.color(" [*] Ex: set DOMAIN christest.com", warning=True))
                    print()
        return
