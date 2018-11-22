"""
This is the conductor which controls everything
"""

import glob
import imp
import os
import readline
import sys
from lib.common import completer
from lib.common import helpers
from lib.common import messages


# Try to find and import the settings.py config file
try:
    sys.path.append("/etc/veil/")
    import settings
except ImportError:
    print( "\n [!] ERROR #1-2: Can't import /etc/veil/settings.py.   Run: %s\n" % ( os.path.abspath( "./config/update-config.py" ) ) )
    sys.exit()


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
            "options": "Show Veil configuration",
            "update": "Update Veil",
            "exit": "Completely exit Veil"}
        self.number_of_tools = len(self.imported_tools)
        self.command_line_options = cli_stuff

    def command_line_use(self):
        tool_found = False
        for key, tool_object in sorted(self.imported_tools.items()):
            # If the entered number matches the payload, use that payload
            if self.command_line_options.tool.lower() == tool_object.cli_name.lower():
                tool_object.cli_menu()
                tool_found = True
        if not tool_found:
            print(helpers.color(' [!] ERROR: You did not provide a valid tool name!', warning=True))
            sys.exit()

    def list_tools(self, show_header = True):
        # Did we run a command?
        if show_header:
            # show title bar
            messages.title_screen()
            print(helpers.color(' [*] Available Tools:\n'))
        else:
            print("Available Tools:\n")

        # Loop over all tools loaded into Veil, print name and description
        # Function for listing all payloads
        tool_counter = 1
        for key, tool in sorted(self.imported_tools.items()):
            print('\t' + str(tool_counter) + ")\t" + tool.cli_name)
            tool_counter += 1
        print()
        return

    def load_tools(self, command_line_object):
        # Load all tools within the Tools folder
        # (Evasion, Ordnance, Pillage, etc.)
        for name in glob.glob('tools/*/tool.py'):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_tool = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.imported_tools[name] = loaded_tool.Tools(
                    command_line_object)
        return

    def main_menu(self):
        # default blank command for the main menu loop
        main_menu_command = ""
        show_header = True

        # Try except to catch keyboard interrupts
        try:

            # Loop for the main menu, will always loop as long as command is ''
            while True:
                comp = completer.VeilMainMenuCompleter(self.mainmenu_commands, self.imported_tools)
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)

                if show_header:
                    messages.title_screen()
                    print("Main Menu")
                    print("\n\t" + helpers.color(len(self.imported_tools)) + " tools loaded\n")
                    # List tools, but don't show the header
                    self.list_tools(False)
                    print("Available Commands:\n")
                    for command in sorted(self.mainmenu_commands.keys()):
                        print("\t" + helpers.color(command) + '\t\t\t' + self.mainmenu_commands[command])
                    print()
                    show_header = False

                main_menu_command = input('Veil>: ').strip()

                if main_menu_command.startswith('use'):
                    # Check to make sure a tool is provided with use command
                    if len(main_menu_command.split()) == 1:

                        # List tools, don't show header, loop back in main menu
                        self.list_tools()
                        show_header = False

                    elif len(main_menu_command.split()) == 2:
                        # Grab the command, either the number or word
                        tool_choice = main_menu_command.split()[1]

                        # If we're choosing the payload by numbers
                        if tool_choice.isdigit() and\
                                0 < int(tool_choice) <= len(self.imported_tools):
                            tool_number = 1
                            for key, tool_object in sorted(self.imported_tools.items()):
                                # if the entered number matches the payload, use that payload
                                if int(tool_choice) == tool_number:
                                    tool_object.tool_main_menu()
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
                        show_header = True

                elif main_menu_command.startswith('list'):
                    # List tools, don't show header, loop back in main menu
                    self.list_tools()

                elif main_menu_command.startswith('info'):
                    if len(main_menu_command.split()) == 1:
                        show_header = True

                    elif len(main_menu_command.split()) == 2:
                        # Grab the command, either the number or word
                        info_choice = main_menu_command.split()[1]

                        # If we're choosing the payload by numbers
                        if info_choice.isdigit() and\
                                0 < int(info_choice) <= len(self.imported_tools):
                            tool_number = 1
                            for key, tool_object in sorted(self.imported_tools.items()):
                                # If the entered number matches the tool, use that tool
                                if int(info_choice) == tool_number:
                                    print()
                                    print(helpers.color(tool_object.cli_name) + " => " + tool_object.description)
                                    print()
                                tool_number += 1

                        # If the entered name matches the tool, use that tool
                        else:
                            for key, tool_object in sorted(self.imported_tools.items()):
                                if main_menu_command.split()[1].lower() == tool_object.cli_name.lower():
                                    print()
                                    print(helpers.color(tool_object.cli_name) + " => " + tool_object.description)
                                    print()
                    else:
                        show_header = True

                elif main_menu_command.startswith('option'):
                    self.options_veil()

                # Hidden menu option
                elif main_menu_command.startswith('config'):
                    self.config_veil()

                # Hidden menu option
                elif main_menu_command.startswith('setup'):
                    self.setup_veil()

                elif main_menu_command.startswith('update'):
                    self.update_veil()

                elif main_menu_command.startswith('exit') or main_menu_command.startswith('quit'):
                    sys.exit()

        except KeyboardInterrupt:
            print("\n\n" + helpers.color("^C.   Quitting...", warning=True))
            sys.exit()

    # Show options
    def options_veil(self):
        print( " [i] Veil configuration file: /etc/veil/settings.py" )
        for i in dir(settings):
            if i.startswith('_'): continue
            print( " [i] {0}: {1}".format( i , eval( 'settings.' + str(i) )))
        input( '\n\nOptions shown. Press enter to continue' )
        return

    # Self update framework
    def update_veil(self):
        if settings.OPERATING_SYSTEM == "Kali":
            os.system('apt-get update; apt-get -y install veil')
        else:
            os.system('git pull')
        input('\n\nVeil has checked for updates, press enter to continue')
        return

    # Re-run setup
    def setup_veil(self):
        if settings.OPERATING_SYSTEM == "Kali":
            if os.path.exists("/usr/share/veil/config/setup.sh"):
                os.system('/usr/share/veil/config/setup.sh -f -s')
            else:
                print("\n [!] ERROR: Kali is missing %s\n" % ("/usr/share/veil/config/setup.sh"))
                os.system('./config/setup.sh -f -s')
        else:
            os.system('./config/setup.sh -f -s')
        input('\n\nVeil has ran setup.sh, press enter to continue')
        return

    # Re-run config.py
    def config_veil(self):
        if settings.OPERATING_SYSTEM == "Kali":
            if os.path.exists("/usr/share/veil/config/update-config.py"):
                os.system('cd /usr/share/veil/config/; ./update-config.py')
            else:
                print("\n [!] ERROR: Kali is missing %s\n" % ("/usr/share/veil/config/update-config.py"))
                os.system('cd ./config/; ./update-config.py')
        else:
            os.system('cd ./config/; ./update-config.py')
        input('\n\nVeil has reconfigured, press enter to continue')
        return
