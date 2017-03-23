'''
This is the Veil-Ordnance module
'''

import glob
import imp
import readline
import sys
from lib.common import helpers
from lib.common import completer
from Tools.Ordnance.ordnance_common import ordnance_helpers
from Tools.Ordnance.encoders import *
from Tools.Ordnance.payloads.x86 import *


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
            "payload": "Use a specific payload",
            "info": "Information on a specific payload or encoder",
            "exit": "Exit Veil",
            "back": "Go to main Veil menu"}
        self.final_shellcode = ''
        self.shellcode_option_commands = {
            "set": "Set shellcode option",
            "generate": "Generate the shellcode",
            "back": "Go back",
            "exit": "Completely exit Veil",
            "options": "Show the shellcode's options"
        }
        # Used to track if invoked by another tool
        self.invoked = False
        self.selected_payload = ''
        self.payload_options = {}

    def cli_menu(self, invoked=False):
        # Check to see if we're just listing payloads or encoders
        # If so, do that and then exit
        if self.command_options.list_payloads:
            self.print_payloads()
            sys.exit()
        elif self.command_options.list_encoders:
            self.print_encoders()
            sys.exit()
        # Now let's check for payloads we're doing
        if self.command_options.ordnance_payload:
            payload_found = False
            for payload in self.active_shellcode.values():
                if self.command_options.ordnance_payload.lower() == payload.cli_name:
                    payload_found = True
                    if "LHOST" in payload.required_options:
                        valid_ip = helpers.validate_ip(self.command_options.ip)
                        valid_hostname = helpers.validate_hostname(self.command_options.ip)
                        if valid_ip:
                            payload.required_options["LHOST"][0] = self.command_options.ip
                        elif valid_hostname:
                            if payload.cli_name == 'rev_tcp_dns':
                                payload.required_options["LHOST"][0] = self.command_options.ip
                            else:
                                print(helpers.color("[*] Error: Invalid IP/Hostname specified!", warning=True))
                                print(helpers.color("[*] Try again?", warning=True))
                                sys.exit()
                        else:
                            print(helpers.color("[*] Error: Invalid IP/Hostname specified!", warning=True))
                            print(helpers.color("[*] Try again?", warning=True))
                            sys.exit()
                    if "LPORT" in payload.required_options:
                        if 0 < self.command_options.port < 65535:
                            payload.required_options["LPORT"][0] = self.command_options.port
                        else:
                            print(helpers.color("[*] Error: Invalid port number provided!", warning=True))
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
                            print(helpers.color("[*] Error: Encoder you specified was not found!", warning=True))
                            print(helpers.color("[*] Try again?", warning=True))
                            sys.exit()
                        self.final_shellcode = payload.customized_shellcode
                    if invoked:
                        pass
                    else:
                        payload.payload_stats()

            # If the payload supplied isn't found
            if not payload_found:
                print(helpers.color("[*] Error: You specified a non-existent Ordnance payload!", warning=True))
                print(helpers.color("[*] Go to start... do not collect $200!", warning=True))
                sys.exit()

    def load_encoders(self, cli_args):
        for name in glob.glob('Tools/Ordnance/encoders/*.py'):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_encoder = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.active_encoders[name] = loaded_encoder.EncoderModule(cli_args)
        return

    def load_payloads(self, cli_args):
        for name in glob.glob('Tools/Ordnance/payloads/x86/*.py'):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_payloads = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.active_shellcode[name] = loaded_payloads.ShellcodeModule(cli_args)
        return

    def print_encoders(self):
        print("Available Encoder Modules")
        print("Command Line Name => Description")
        print("-" * 79)
        print()
        for encoder_module in self.active_encoders.values():
            print(helpers.color(encoder_module.cli_name) + " => " + encoder_module.name)
        return

    def print_shellcode_option_commands(self):
        print("Available Commands: \n")
        for name in sorted(self.shellcode_option_commands.keys()):
            print('\t' + '{0: <8}'.format(name) + "\t\t" + '{0: <8}'.format(self.shellcode_option_commands[name]))

    def print_options_screen(self, pload_object):
        ordnance_helpers.title_screen()
        print("Payload: " + helpers.color(pload_object.cli_name) + " selected\n")
        print(helpers.color("Required Options:\n"))
        print('{0: <16}'.format('Name') + '\t' + '{0: <8}'.format('Value') + '\t' + '{0: <8}'.format('Description'))
        print('{0: <16}'.format('----') + '\t' + '{0: <8}'.format('-----') + '\t' + '{0: <8}'.format('-----------'))
        for opt_name in sorted(pload_object.required_options.keys()):
            print('{0: <16}'.format(opt_name) + '\t' + '{0: <8}'.format(pload_object.required_options[opt_name][0]) + '\t' + pload_object.required_options[opt_name][1])
        print()
        self.print_shellcode_option_commands()
        print()
        return

    def print_payloads(self):
        print("Available Payload Modules")
        print("Command Line Name => Description")
        print("-" * 79)
        print()
        for payload in self.active_shellcode.values():
            print(helpers.color(payload.cli_name) + " => " + payload.name)
        return

    def tool_main_menu(self, invoked=False):
        # This is the main function where everything is called from
        # Iterate over payloads and find the user selected payload module
        # invoked is used when another tool is calling this function
        ordnance_main_command = ''
        show_ordnance_menu = True
        if invoked:
            self.invoked = True

        while ordnance_main_command == '':

            if show_ordnance_menu:
                ordnance_helpers.title_screen()
                print("Veil-Ordnance Menu")
                print("\n\t" + helpers.color(len(self.active_shellcode)) + " payloads loaded")
                print("\t" + helpers.color(len(self.active_encoders)) + " encoders loaded\n")
                print("Available Commands:\n")
                for command in sorted(self.ordnance_main_menu_commands.keys()):
                    print("\t" + helpers.color(command) + '\t\t\t' + self.ordnance_main_menu_commands[command])
                print()
            show_ordnance_menu = True

            ordnance_main_command = input('Veil-Ordnance command: ').strip()

            # See if we're listing payloads or encoders
            if ordnance_main_command.lower().startswith('list'):

                if len(ordnance_main_command.split()) == 1:
                    print()
                    print(helpers.color("[*] Error: You did not provide what you want to list!", warning=True))
                    print(helpers.color("[*] Ex: list payloads or list encoders", warning=True))
                    print()
                    ordnance_main_command = ''
                    show_ordnance_menu = False

                elif len(ordnance_main_command.split()) == 2:

                    list_selection = ordnance_main_command.split()[1]

                    # Check and see what we are listing
                    if list_selection.lower() == 'payloads':
                        ordnance_helpers.title_screen()
                        self.print_payloads()
                        show_ordnance_menu = False
                        print()
                        ordnance_main_command = ''

                    elif list_selection.lower() == 'encoders':
                        ordnance_helpers.title_screen()
                        self.print_encoders()
                        show_ordnance_menu = False
                        print()
                        ordnance_main_command = ''

                    else:
                        show_ordnance_menu = False
                        print()
                        print(helpers.color("[*] Error: You did not provide a valid item to list!", warning=True))
                        print(helpers.color("[*] Ex: list payloads or list encoders", warning=True))
                        print()
                        ordnance_main_command = ''

                else:
                    ordnance_main_command = ''

            elif ordnance_main_command.lower() == "help":
                ordnance_main_command = ''

            elif ordnance_main_command.lower() == "back":
                ordnance_main_command = ''
                break

            elif ordnance_main_command.lower() == "exit":
                if invoked:
                    break
                else:
                    sys.exit(0)

            elif ordnance_main_command.lower().startswith('payload'):
                if len(ordnance_main_command.split()) < 2:
                    print(helpers.color("[*] Error: You did not provide the payload to use!", warning=True))
                    print(helpers.color("[*] Ex: use rev_http", warning=True))
                    ordnance_main_command = ''
                elif len(ordnance_main_command.split()) > 2:
                    print(helpers.color("[*] Error: You provided too many options!", warning=True))
                    print(helpers.color("[*] Ex: use rev_http", warning=True))
                else:
                    self.selected_payload = ordnance_main_command.split()[1].lower()
                    self.use_payload(self.selected_payload)

                    # If invoked, return the shellcode
                    if self.invoked:
                        return

                    if self.final_shellcode == '':
                        show_ordnance_menu = False
                self.selected_payload = ''
                ordnance_main_command = ''

            else:
                ordnance_main_command = ''
        return

    def use_encoder(self, incoming_pload):
        encoder_found = False
        for loaded_encoder in self.active_encoders.values():
            if incoming_pload.required_options["Encoder"][0].lower() == loaded_encoder.cli_name:
                encoder_found = True
                loaded_encoder.encode(incoming_pload)

        if not encoder_found:
            print(helpers.color("[*] Error: Encoder not found! Printing non-encoded shellcode!", warning=True))
        return

    def use_payload(self, incoming_payload):
        shellcode_found = False
        for payload in self.active_shellcode.values():
            if incoming_payload.lower() == payload.cli_name:
                shellcode_found = True
                while ordnance_helpers.loop_req_options(payload):
                    self.print_options_screen(payload)

                    while True:
                        comp = completer.OrdnanceCompleter(self.shellcode_option_commands, payload)
                        readline.set_completer_delims(' \t\n;')
                        readline.parse_and_bind("tab: complete")
                        readline.set_completer(comp.complete)
                        breakout = False
                        shellcode_command = input(
                            "[" + payload.cli_name + ">>]: ").lower().strip()

                        # Start logic for required option commands
                        if shellcode_command.startswith("set"):
                            if len(shellcode_command.split()) < 3 or len(shellcode_command.split()) > 3:
                                print(helpers.color("[*] Error: You did not provide the correct input for setting an option!", warning=True))
                                print(helpers.color("[*] Error: Ex: set LHOST 192.168.18.14"))
                            else:
                                found_req_option = False
                                for key, value in payload.required_options.items():
                                    if shellcode_command.split()[1] == key.lower():
                                        found_req_option = True
                                        value[0] = shellcode_command.split()[2]
                                if not found_req_option:
                                    print(helpers.color("[*] Error: You didn't provide a correct option to set, please retry!", warning=True))
                        elif shellcode_command == "exit":
                            # Completely exit out of Veil
                            print(helpers.color("[*] You're rage quitting all of Veil!", warning=True))
                            sys.exit(0)
                        elif shellcode_command == "back":
                            # Go back to shellcode selection
                            shellcode_command = ''
                            breakout = True
                            break
                        elif shellcode_command == "generate":
                            lport_out = ''
                            lhost_out = ''
                            rhost_out = ''
                            if ordnance_helpers.loop_req_options(payload):
                                print(helpers.color("[*] Error: You didn't provide all the required options!", warning=True))
                            else:
                                safe_to_generate = True
                                if "LHOST" in payload.required_options:
                                    if not ordnance_helpers.check_lhost(payload.required_options["LHOST"][0]):
                                        print(helpers.color("[*] Error: You didn't provide a valid IP address!", warning=True))
                                        print(helpers.color("[*] Error: Try again :)", warning=True))
                                        safe_to_generate = False
                                if "LPORT" in payload.required_options:
                                    if not ordnance_helpers.check_lport(payload.required_options["LPORT"][0]):
                                        print(helpers.color("[*] Error: You didn't provide a valid LPORT value!", warning=True))
                                        print(helpers.color("[*] Error: Try again :)", warning=True))
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

                                    # Print payload stats
                                    payload.payload_stats()
                                    if self.invoked:
                                        dummy = input('\nHit enter to return to Veil-Evasion... ')
                                    else:
                                        dummy2 = input('\nHit enter to continue... ')
                                    shellcode_command = ''

                                    if "LHOST" in payload.required_options:
                                        payload.required_options["LHOST"][0] = ''
                                    if "LPORT" in payload.required_options:
                                        payload.required_options["LPORT"][0] = ''
                                    breakout = True
                                    break
                        elif shellcode_command == "options":
                            # Reprint the shellcode options to console
                            self.print_options_screen(payload)

                    if breakout:
                        ordnance_helpers.title_screen()
                        print("Veil-Ordnance Menu")
                        print("\n\t" + helpers.color(len(self.active_shellcode)) + " payloads loaded")
                        print("\t" + helpers.color(len(self.active_encoders)) + " encoders loaded\n")
                        print("Available Commands:\n")
                        for command in sorted(self.ordnance_main_menu_commands.keys()):
                            print("\t" + helpers.color(command) + '\t\t\t' + self.ordnance_main_menu_commands[command])
                        print()
                        break

        if not shellcode_found:
            print(helpers.color("[*] Error: You did not provide a valid payload name, please try again!", warning=True))
        return
