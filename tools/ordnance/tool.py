"""
This is the Veil-Ordnance module
"""

import glob
import imp
import readline
import sys
from lib.common import helpers
from lib.common import completer
from tools.ordnance.ordnance_common import ordnance_helpers
from tools.ordnance.encoders import *
from tools.ordnance.payloads.x86 import *


class Tools:

    def __init__(self, cli_options=None):
        self.cli_name = "Ordnance"
        self.description = "Generates shellcode for supported payloads"
        # all encoders within the encoders directory
        self.active_encoders = {}
        # Payloads currently within the x86 payload directory
        self.active_shellcode = {}
        # Load all encoder modules
        self.load_encoders(cli_options)
        # Load all payload modules
        self.load_payloads(cli_options)
        self.command_options = cli_options
        self.ordnance_main_menu_commands = {
            "list": "List available [payloads] or [encoders]",
            "use": "Use a specific payload",
            "exit": "Completely exit Veil",
            "back": "Go to Veil's main menu"}
        self.final_shellcode = ""
        self.shellcode_option_commands = {
            "set": "Set payload option",
            "generate": "Generate the payload",
            "back": "Go back to Veil-Ordnance",
            "exit": "Completely exit Veil",
            "options": "Show the payload's options",
            "list": "List available encoders",
        }
        # Used to track if invoked by another tool
        self.invoked = False
        self.selected_payload = ""
        self.payload_options = {}

    def cli_menu(self, invoked=False):
        # Check to see if we're just listing payloads or encoders
        # If so, do that and then exit
        # --list-payloads
        if self.command_options.list_payloads:
            self.print_payloads()
            sys.exit()
        # --list-encoders
        elif self.command_options.list_encoders:
            self.print_encoders()
            sys.exit()

        # Now let's check for payloads we're doing
        # Missing --ordnance-payload ?
        if not self.command_options.ordnance_payload:
            print(helpers.color(" [!] ERROR: Missing ordnance-payload selection (--ordnance-payload <payload>).    Try: -t Ordnance --list-payloads", warning=True))
        else:
            payload_selected = self.command_options.ordnance_payload.lower()
            payload = self.return_payload_object(payload_selected)
            if not payload:
                print(helpers.color(" [!] ERROR: You specified a non-existent Ordnance payload!", warning=True))
                sys.exit()
            else:
                if "LHOST" in payload.required_options:
                    # Is --ip missing?
                    if self.command_options.ip is None:
                        print(helpers.color(" [!] ERROR: Missing --ip <value>", warning=True))
                        sys.exit()
                    else:
                        valid_ip = helpers.validate_ip(self.command_options.ip)
                        valid_hostname = helpers.validate_hostname(self.command_options.ip)
                        if valid_ip:
                            payload.required_options["LHOST"][0] = self.command_options.ip
                        elif valid_hostname:
                            if payload.cli_name == 'rev_tcp_dns':
                                payload.required_options["LHOST"][0] = self.command_options.ip
                            else:
                                print(helpers.color(" [!] ERROR: Invalid IP/Hostname specified!", warning=True))
                                sys.exit()
                        else:
                            print(helpers.color(" [!] ERROR: Invalid IP/Hostname specified!", warning=True))
                            sys.exit()
                if "LPORT" in payload.required_options:
                    if 0 < self.command_options.port < 65535:
                        payload.required_options["LPORT"][0] = self.command_options.port
                    else:
                        print(helpers.color(" [!] ERROR: Invalid port number provided!", warning=True))
                        print(helpers.color("[*] Try again?", warning=True))
                        sys.exit()
                # Generate the original shellcode
                payload.cli_gen_shellcode()
                self.final_shellcode = payload.customized_shellcode
                # Check if an encoder is being called by the user
                if self.command_options.encoder is not None:
                    encoder_found_here = False
                    if "BadChars" in payload.required_options:
                        payload.required_options["BadChars"][0] = self.command_options.bad_chars
                    for loaded_encoder in self.active_encoders.values():
                        if self.command_options.encoder.lower() == loaded_encoder.cli_name:
                            encoder_found_here = True
                            loaded_encoder.cli_encode(payload)
                    if not encoder_found_here:
                        print(helpers.color(" [!] ERROR: Encoder you specified was not found!", warning=True))
                        print(helpers.color("[*] Try again?", warning=True))
                        sys.exit()
                    self.final_shellcode = payload.customized_shellcode
                if invoked:
                    pass
                else:
                    payload.payload_stats()
        return

    def load_encoders(self, cli_args):
        for name in sorted( glob.glob('tools/ordnance/encoders/*.py') ):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_encoder = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.active_encoders[name] = loaded_encoder.EncoderModule(cli_args)
        return

    def load_payloads(self, cli_args):
        for name in sorted( glob.glob('tools/ordnance/payloads/x86/*.py') ):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_payloads = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.active_shellcode[name] = loaded_payloads.ShellcodeModule(cli_args)
        return

    def print_encoders(self):
        print("Available Encoder Modules")
        print("\tCommand Line Name => Description")
        print("-" * 79)
        print()
        for encoder_module in self.active_encoders.values():
            print( "\t%s => %s" % ( '{0: <24}'.format( helpers.color( encoder_module.cli_name ) ), encoder_module.name ) )
        return

    def print_shellcode_option_commands(self):
        print(helpers.color(" Available Commands:\n"))
        for name in sorted(self.shellcode_option_commands.keys()):
            print('\t' + '{0: <8}'.format(name) + "\t\t" + '{0: <8}'.format(self.shellcode_option_commands[name]))
        print()

    def print_options_screen(self, pload_object):
        ordnance_helpers.title_screen()
        print("Payload: " + helpers.color(pload_object.cli_name) + " selected\n")
        print(helpers.color(" Required Options:\n"))
        print('{0: <16}'.format('Name') + '\t' + '{0: <8}'.format('Value') + '\t' + '{0: <8}'.format('Description'))
        print('{0: <16}'.format('----') + '\t' + '{0: <8}'.format('-----') + '\t' + '{0: <8}'.format('-----------'))
        for opt_name in sorted(pload_object.required_options.keys()):
            print('{0: <16}'.format(opt_name) + '\t' + '{0: <8}'.format(pload_object.required_options[opt_name][0]) + '\t' + pload_object.required_options[opt_name][1])
        print()
        self.print_shellcode_option_commands()
        return

    def print_menu(self):
        ordnance_helpers.title_screen()
        print("Veil-Ordnance Menu")
        print("\n\t" + helpers.color(len(self.active_shellcode)) + " payloads loaded")
        print("\t" + helpers.color(len(self.active_encoders)) + " encoders loaded\n")
        print("Available Commands:\n")
        for command in sorted(self.ordnance_main_menu_commands.keys()):
            print("\t" + helpers.color(command) + '\t\t\t' + self.ordnance_main_menu_commands[command])
        print()
        return

    def print_payloads(self):
        print("Available Payload Modules")
        print("\tCommand Line Name => Description")
        print("-" * 79)
        print()

        lastBase = None
        x = 1
        for payload in self.active_shellcode.values():
            parts = payload.cli_name.split("_")
            if lastBase and parts[0] != lastBase:
                print()
            lastBase = parts[0]
            print( "\t%s)\t%s => %s" % ( x, '{0: <28}'.format( helpers.color( payload.cli_name ) ), payload.name ) )
            x += 1
        return

    def tool_main_menu(self, invoked=False):
        # This is the main function where everything is called from
        # Iterate over payloads and find the user selected payload module
        # invoked is used when another tool is calling this function
        ordnance_main_command = ""
        show_ordnance_menu = True

        # Called from another tool?
        if invoked:
            self.invoked = True

        while True:
            if show_ordnance_menu:
                self.print_menu()
                show_ordnance_menu = False

            ordnance_main_command = input('Veil/Ordnance>: ').strip().lower()

            # See if we're listing payloads or encoders
            if ordnance_main_command.startswith('list'):

                if len(ordnance_main_command.split()) == 1:
                    print()
                    print(helpers.color(" [!] ERROR: You did not provide what you want to list!", warning=True))
                    print(helpers.color(" [*] Ex: list payloads OR list encoders", warning=True))
                    print()

                elif len(ordnance_main_command.split()) == 2:
                    list_selection = ordnance_main_command.split()[1].lower()

                    # Check and see what we are listing
                    # Payloads
                    if list_selection.startswith('p'):
                        ordnance_helpers.title_screen()
                        self.print_payloads()

                    # Encoders
                    elif list_selection.startswith('e'):
                        ordnance_helpers.title_screen()
                        self.print_encoders()

                    else:
                        print()
                        print(helpers.color(" [!] ERROR: You did not provide a valid item to list!", warning=True))
                        print(helpers.color(" [*] Ex: list payloads OR list encoders", warning=True))
                        print()

            elif ordnance_main_command.startswith("back") or ordnance_main_command.startswith("main") or ordnance_main_command.startswith("menu"):
                break

            elif ordnance_main_command.startswith("exit") or ordnance_main_command.startswith("quit"):
                sys.exit(0)

            elif ordnance_main_command.startswith('use'):
                if len(ordnance_main_command.split()) == 2:
                    payload_selected = ordnance_main_command.split()[1].lower()
                    selected_payload_module = self.return_payload_object(payload_selected)
                    if not selected_payload_module:
                        print()
                        print(helpers.color(" [!] ERROR: You did not provide a valid payload selection!", warning=True))
                        print(helpers.color(" [*] Ex: use 2 OR use rev_http", warning=True))
                        print()
                    else:
                        self.use_payload(selected_payload_module)

                        # If invoked, return the shellcode
                        if self.invoked:
                            return
                        ## If not, show the menu
                        else:
                            show_evasion_menu = True
                else:
                    print()
                    print(helpers.color(" [!] ERROR: You did not provide a valid payload selection!", warning=True))
                    print(helpers.color(" [*] Ex: use 2 OR use rev_http", warning=True))
                    print()
        return

    def return_payload_object(self, user_selection):
        # This function handles returning the selected payload module object
        # to the calling function
        counter_value = 1
        for payload in self.active_shellcode.values():
            if user_selection.isdigit() and (0 < int(user_selection) <= len(self.active_shellcode)):
                if int(user_selection) == counter_value:
                    return payload
            else:
                if user_selection.lower() == payload.cli_name:
                    return payload

            # Iterate counter for number based selection
            counter_value += 1
        return False

    def use_encoder(self, incoming_pload):
        encoder_found = False
        for loaded_encoder in self.active_encoders.values():
            if incoming_pload.required_options["Encoder"][0].lower() == loaded_encoder.cli_name:
                encoder_found = True
                loaded_encoder.encode(incoming_pload)

        if not encoder_found:
            print()
            print(helpers.color(" [!] ERROR: Encoder not found! Printing non-encoded shellcode!", warning=True))
            print()
        return

    def use_payload(self, payload):
        while ordnance_helpers.loop_req_options(payload):
            # Soon as we load the payload, show options
            self.print_options_screen(payload)

            while True:
                comp = completer.OrdnanceCompleter(self.shellcode_option_commands, payload)
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)
                show_payload_menu = False
                shellcode_command = input("[" + payload.cli_name + ">>]: ").strip().lower()

                # Start logic for required option commands
                if shellcode_command.startswith("set"):
                    if len(shellcode_command.split()) < 3 or len(shellcode_command.split()) > 3:
                        print()
                        print(helpers.color(" [!] ERROR: You did not provide the correct input for setting an option!", warning=True))
                        print(helpers.color(" [*] Ex: set LHOST 192.168.18.14", warning=True))
                        print()
                    else:
                        found_req_option = False
                        for key, value in payload.required_options.items():
                            if shellcode_command.split()[1] == key.lower():
                                found_req_option = True
                                value[0] = shellcode_command.split()[2]
                        if not found_req_option:
                            print()
                            print(helpers.color(" [!] ERROR: You didn't provide a correct option to set, please retry!", warning=True))
                            print()
                elif shellcode_command.startswith("exit") or shellcode_command.startswith("quit"):
                    sys.exit(0)
                elif shellcode_command.startswith("back") or shellcode_command.startswith("main") or shellcode_command.startswith("menu"):
                    show_payload_menu = True
                    break
                elif shellcode_command.startswith("list"):
                    ordnance_helpers.title_screen()
                    self.print_encoders()
                elif shellcode_command.startswith("gen") or shellcode_command.startswith("run"):
                    lport_out = ""
                    lhost_out = ""
                    rhost_out = ""
                    if ordnance_helpers.loop_req_options(payload):
                        print()
                        print(helpers.color(" [!] ERROR: You didn't provide all the required options!", warning=True))
                        print()
                    else:
                        safe_to_generate = True
                        if "LHOST" in payload.required_options:
                            if not ordnance_helpers.check_lhost(payload.required_options["LHOST"][0]):
                                print()
                                print(helpers.color(" [!] ERROR: You didn't provide a valid IP address!", warning=True))
                                print(helpers.color(" [!] ERROR: Try again :)", warning=True))
                                print()
                                safe_to_generate = False
                        if "LPORT" in payload.required_options:
                            if not ordnance_helpers.check_lport(payload.required_options["LPORT"][0]):
                                print()
                                print(helpers.color(" [!] ERROR: You didn't provide a valid LPORT value!", warning=True))
                                print(helpers.color(" [!] ERROR: Try again :)", warning=True))
                                print()
                                safe_to_generate = False
                        if safe_to_generate:
                            # Generate the shellcode
                            payload.gen_shellcode()

                            # Gather information to generate handler if requested
                            self.final_shellcode = payload.customized_shellcode
                            if "LHOST" in payload.required_options:
                                lhost_out = payload.required_options["LHOST"][0]
                            if "LPORT" in payload.required_options:
                                lport_out = payload.required_options["LPORT"][0]
                            if "RHOST" in payload.required_options:
                                rhost_out = payload.required_options["RHOST"][0]

                            if lhost_out:
                                self.payload_options['LHOST'] = lhost_out
                            if lport_out:
                                self.payload_options['LPORT'] = lport_out
                            if rhost_out:
                                self.payload_options['RHOST'] = rhost_out

                            # Check if encoder is needed
                            if payload.required_options["Encoder"][0] is not "None":
                                self.use_encoder(payload)
                                self.final_shellcode = payload.customized_shellcode

                            # Print banner & payload stats
                            ordnance_helpers.title_screen()
                            payload.payload_stats()

                            # Did we come from Evasion? Or direct from Ordnance...
                            if self.invoked:
                                print('\nHalf way... ' + helpers.color('Shellcode generated with Veil-Ordnance!') + '   Returning to Veil-Evasion.')

                                # Re-set settings
                                if "LHOST" in payload.required_options:
                                    payload.required_options["LHOST"][0] = ""
                                if "LPORT" in payload.required_options:
                                    payload.required_options["LPORT"][0] = ""
                            else:
                                dummy = input("\n" + helpers.color('Done!') + "Hit enter to continue...")

                            show_payload_menu = True
                            break
                elif shellcode_command.startswith("option"):
                    # Reprint the shellcode options to console
                    self.print_options_screen(payload)

            if show_payload_menu:
                if not self.invoked:
                    self.print_menu()
                break
        return
