'''

This is the conductor which controls everything

'''

import glob
import imp
import os
import readline
import sys
from lib.common import completer
from lib.common import helpers
from lib.common import messages


class Conductor:

    def __init__(self, cli_stuff):
        # Create dictionaries of supported modules
        # empty until stuff loaded into them
        self.imported_tools = {}
        self.load_tools(cli_stuff)
        self.mainmenu_commands = {
            "list": "List available tools",
            "use": "Use a specific tool",
            "info": "Information on a specific tool",
            "update": "Update Veil",
            "exit": "Exit Veil"}
        self.number_of_tools = len(self.imported_tools)
        self.command_line_options = cli_stuff

    def command_line_use(self):
        tool_found = False
        for key, tool_object in sorted(self.imported_tools.items()):
            # if the entered number matches the payload, use that payload
            if self.command_line_options.tool.lower() == tool_object.cli_name.lower():
                tool_object.cli_menu()
                tool_found = True
        if not tool_found:
            print(helpers.color('Error: You did not provide a valid tool name!', warning=True))
            print(helpers.color('Quitting Veil...', warning=True))
            sys.exit()

    def list_tools(self):
        # show title bar
        messages.title_screen()

        # Loop over all tools loaded into Veil, print name and description
        # Function for listing all payloads
        tool_counter = 1
        print(helpers.color(' [*] Available Tools:\n'))
        for key, tool in sorted(self.imported_tools.items()):
            print('\t' + str(tool_counter) + ")\t" + tool.cli_name)
            tool_counter += 1
        print()
        return

    def load_tools(self, command_line_object):
        # Load all tools within the Tools folder
        # (Evasion, Ordnance, Pillage, etc.)
        for name in glob.glob('Tools/*/Tool.py'):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_tool = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.imported_tools[name] = loaded_tool.Tools(
                    command_line_object)
        return

    def main_menu(self):
        # default blank command for the main meny loop
        main_menu_command = ''
        show_header = True

        # Try except to catch keyboard interrupts
        try:

            # Loop for the main menu, will always loop as long as command is ''
            while main_menu_command == '':
                comp = completer.VeilMainMenuCompleter(self.mainmenu_commands, self.imported_tools)
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)

                if show_header:
                    messages.title_screen()
                    print("Main Menu")
                    print("\n\t" + helpers.color(len(self.imported_tools)) + " tools loaded\n")
                    print("Available Commands:\n")
                    for command in sorted(self.mainmenu_commands.keys()):
                        print("\t" + helpers.color(command) + '\t\t\t' + self.mainmenu_commands[command])
                    print()

                main_menu_command = input('Main menu choice: ').strip()

                if main_menu_command.startswith('use'):

                    # Check to make sure a tool is provided with use command
                    if len(main_menu_command.split()) == 1:

                        # List tools, don't show header, loop back in main menu
                        self.list_tools()
                        show_header = False
                        main_menu_command = ''

                    elif len(main_menu_command.split()) == 2:

                        # Grab the command, either the number or word
                        tool_choice = main_menu_command.split()[1]

                        # if we're choosing the payload by numbers
                        if tool_choice.isdigit() and\
                                0 < int(tool_choice) <= len(self.imported_tools):
                            tool_number = 1
                            for key, tool_object in sorted(self.imported_tools.items()):
                                # if the entered number matches the payload, use that payload
                                if int(tool_choice) == tool_number:
                                    tool_object.tool_main_menu()
                                    tool_number += 1
                                    show_header = True
                                else:
                                    tool_number += 1
                            show_header = True

                        # Else if selecting payload by name
                        else:
                            for key, tool_object in sorted(self.imported_tools.items()):
                                # if the entered number matches the payload, use that payload
                                if tool_choice.lower() == tool_object.cli_name.lower():
                                    tool_object.tool_main_menu()
                                    show_header = True

                        # Once done with tool, clear main menu command
                        main_menu_command = ''
                        show_header = True

                    # Catch anything else, like an error
                    else:
                        main_menu_command = ''

                elif main_menu_command.startswith('list'):

                    # List tools, don't show header, loop back in main menu
                    self.list_tools()
                    show_header = False
                    main_menu_command = ''

                elif main_menu_command.startswith('info'):

                    if len(main_menu_command.split()) == 1:
                        show_header = True
                        main_menu_command = ''

                    elif len(main_menu_command.split()) == 2:

                        # Grab the command, either the number or word
                        info_choice = main_menu_command.split()[1]

                        # if we're choosing the payload by numbers
                        if info_choice.isdigit() and\
                                0 < int(info_choice) <= len(self.imported_tools):
                            tool_number = 1
                            for key, tool_object in sorted(self.imported_tools.items()):
                                # if the entered number matches the tool, use that tool
                                if int(info_choice) == tool_number:
                                    print()
                                    print(helpers.color(tool_object.cli_name) + " => " + tool_object.description)
                                    print()
                                    show_header = False
                                tool_number += 1

                        # if the entered name matches the tool, use that tool
                        else:
                            for key, tool_object in sorted(self.imported_tools.items()):
                                if main_menu_command.split()[1].lower() == tool_object.cli_name.lower():
                                    print()
                                    print(helpers.color(tool_object.cli_name) + " => " + tool_object.description)
                                    print()
                                    show_header = False

                        main_menu_command = ''

                    else:
                        main_menu_command = ''
                        show_header = True

                elif main_menu_command.startswith('update'):

                    self.update_veil()
                    main_menu_command = ''

                elif main_menu_command.startswith('exit'):
                    print('\n' + helpers.color('You rage quit Veil!', warning=True) + '\n')
                    sys.exit()

                else:
                    show_header = True
                    main_menu_command = ''

        except KeyboardInterrupt:
            print("\n\n" + helpers.color("You rage quit Veil!", warning=True))
            sys.exit()

    def update_veil(self):
        os.system('git pull')
        input('Veil has checked for updates, press enter to continue')
        return
